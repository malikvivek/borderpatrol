package com.lookout.borderpatrol

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

import com.twitter.finagle.Http.Client
import com.twitter.finagle.client.StackClient
import com.twitter.finagle.param.ProtocolLibrary
import com.twitter.finagle.service.StatsFilter
import com.twitter.finagle.{Http, Service}
import com.twitter.finagle.http.{Response, Request}
import com.twitter.logging.Logger
import com.twitter.util.Future
import scala.collection.JavaConverters._
import scala.language.postfixOps


object Binder {
  private[this] val log = Logger.get(getClass.getPackage.getName)
  private[this] val cache: collection.concurrent.Map[String, Service[Request, Response]] =
    new ConcurrentHashMap[String, Service[Request, Response]] asScala

  private[this] def client(name: String, endpoint: Endpoint): Service[Request, Response] = {
    // If its https, use TLS
    val https = endpoint.hosts.filter(u => u.getProtocol == "https").nonEmpty
    val hostname = endpoint.hosts.map(u => u.getHost).mkString

    // Find CSV of host & ports
    val hostAndPorts = endpoint.hosts.map(u => u.getAuthority).mkString(",")

    // Create a client and configure metrics in microseconds
    if (https) Http
      .Client(Client.stack, StackClient.defaultParams + ProtocolLibrary("http") +
              StatsFilter.Param(TimeUnit.MICROSECONDS))
      .withTls(hostname).newService(hostAndPorts, name)
    else Http
      .Client(Client.stack, StackClient.defaultParams + ProtocolLibrary("http") +
              StatsFilter.Param(TimeUnit.MICROSECONDS))
      .newService(hostAndPorts, name)
  }

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

  def get(name: String): Option[Service[Request, Response]] = cache.get(name)

  def clear(): Unit = cache.clear()
}
