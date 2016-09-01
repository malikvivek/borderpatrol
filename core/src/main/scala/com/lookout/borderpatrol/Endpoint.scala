package com.lookout.borderpatrol

import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

import com.twitter.conversions.storage._
import com.twitter.finagle.Http.Client
import com.twitter.finagle.client.StackClient
import com.twitter.finagle.http.path.Path
import com.twitter.finagle.param.ProtocolLibrary
import com.twitter.finagle.service.StatsFilter
import com.twitter.finagle.{Http, Service}
import com.twitter.finagle.http.{Request, Response}
import com.twitter.finagle.tracing.NullTracer
import com.twitter.logging.Logger
import com.twitter.util.Future

import scala.collection.JavaConverters._
import scala.language.postfixOps


/**
  * Endpoint defines the remote endpoint that BP uses to perform specific operations
  */
trait Endpoint {
  val name: String
  val path: Path
  val hosts: Set[URL]
  def send(request: Request): Future[Response]
}

/**
  * Add "send" interface to Endpoint class
  */
object Endpoint {
  private[this] val log = Logger.get(getClass.getPackage.getName)
  private[this] val cache: collection.concurrent.Map[String, Service[Request, Response]] =
    new ConcurrentHashMap[String, Service[Request, Response]] asScala

  /**
   * Enable TLS
   */
  def tls(endpoint: Endpoint): Http.Client => Http.Client = { cl =>
    val isHttps = endpoint.hosts.exists(u => u.getProtocol == "https")
    val hostname = endpoint.hosts.map(u => u.getHost).mkString
    if (isHttps) cl.withTls(hostname) else cl
  }

  /**
   * If endpoint pointing to an ELB (i.e. single host), then it is important to disable fail fast as the
   * remote load balancer has the visibility into which endpoints are up
   */
  def failFast(endpoint: Endpoint): Http.Client => Http.Client = { cl =>
    if (endpoint.hosts.size == 1) cl.withSessionQualifier.noFailFast else cl
  }

  /** Spawn a client */
  def client(name: String, endpoint: Endpoint): Service[Request, Response] = {
    // Find CSV of host & ports
    val hostAndPorts = endpoint.hosts.map { u =>
      val port = if (u.getPort < 0) u.getDefaultPort else u.getPort
      s"${u.getHost}:${port}"
    }.mkString(",")
    val chain = tls(endpoint) //compose failFast(endpoint)

    chain(Http.Client(Client.stack, StackClient.defaultParams +
      ProtocolLibrary("http") + StatsFilter.Param(TimeUnit.MICROSECONDS)))
      .withMaxHeaderSize(32.kilobytes) /* Sum of all headers should be less than 32k */
      .withMaxRequestSize(50.megabytes) /* Size of request body should be less than 50M */
      .withMaxResponseSize(50.megabytes) /* Size of response body should be less than 50M */
      .withTracer(NullTracer)
      .newService(hostAndPorts, name)
  }

  /** Get or store client in cache */
  private[this] def getOrCreate(endpoint: Endpoint): Future[Service[Request, Response]] =
    cache.getOrElse(endpoint.name, {
      //  Allocate a new client
      val cl = client(endpoint.name, endpoint)
      // putIfAbsent atomically inserts the client into the map,
      val maybeC = cache.putIfAbsent(endpoint.name, cl)
      // if maybeC has a value, we got pre-empted => abandon our new allocated cl
      // and return the present one. Otherwise, return newly allocate cl.
      maybeC.getOrElse(cl)
    }).toFuture

  /** Connect and send the request */
  def connect(endpoint: Endpoint, request: Request): Future[Response] = {
    (for {
      cl <- getOrCreate(endpoint)
      res <- cl.apply(request)
    } yield res) handle {
      case e =>
        throw BpCommunicationError(s"Failed to connect for: '${endpoint.name}' " +
          s"to: ${endpoint.hosts.map(u => u.getAuthority).mkString(",")} with: ${e.getMessage}")
    }
  }

  /** Get client service from cache */
  def get(name: String): Option[Service[Request, Response]] = cache.get(name)

  /** Clear cache */
  def clearCache(): Unit = cache.clear()
}

/**
  * Simple Endpoint representation
  *
  * @param name name of the endpoint
  * @param path path at the endpoint
  * @param hosts endpoint hosts
  */
case class SimpleEndpoint(name: String, path: Path, hosts: Set[URL]) extends Endpoint {
  def send(request: Request): Future[Response] = Endpoint.connect(this, request)
}
