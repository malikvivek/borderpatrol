package com.lookout.borderpatrol.server

import java.util.{logging => javalog}

import com.lookout.borderpatrol.auth.{BorderRequest, BpIdentityProviderError,
BpInvalidRequest, CustomerIdRequest, SessionIdRequest}
import com.lookout.borderpatrol.sessionx.{BpSignedIdError, SecretStoreApi, Session, SessionStore, SignedId}
import com.lookout.borderpatrol.{BpNotFoundRequest, CustomerIdentifier, Endpoint,
LoginManager, ServiceIdentifier, ServiceMatcher}
import com.twitter.util._
import com.twitter.finagle.{Filter, Service, SimpleFilter}
import com.twitter.finagle.http.{Cookie, Method, Request, Response}
import com.twitter.logging.{Logger, _}
import com.twitter.util.Future

import scala.util.{Failure, Try}

/**
  * Filter to generate access logs
  *
  * @param name
  * @param path
  * @param fileSize
  */

case class AccessLogFilter(name: String, path: String, fileSize: Long)
  extends SimpleFilter[Request, Response] {

  val logger: Logger = {
    val logger = Logger.get(name)
    logger.clearHandlers()
    logger.setLevel(Logger.INFO)
    logger.setUseParentHandlers(false)
    logger
  }

  lazy val local = new Local[String]
  lazy val formatter = new Formatter {
    override def format(record: javalog.LogRecord) =
      local().getOrElse("MISSING!:") + formatText(record) + lineTerminator
  }

  lazy val accessLogHandler = FileHandler(
    filename = path,
    rollPolicy = Policy.MaxSize(new StorageUnit(fileSize)),
    level = Some(Level.INFO),
    append = true,
    formatter = BareFormatter
  ).apply()
  lazy val stringHandler = new StringHandler(formatter, Some(Logger.INFO))
  lazy val consoleHandler = new ConsoleHandler(BareFormatter, Some(Logger.INFO))
  logger.addHandler(new QueueingHandler(accessLogHandler))

  local() = "I"

  def apply(req: Request, service: Service[Request, Response]): Future[Response] = {

    val startTime = Time.now
    for {
      resp <- service(req)
      _<- Future(logger.info(s"${req.xForwardedFor.getOrElse("-")}\t${startTime.format("[yyyy/mm/dd:hh:mm:ss.sss]")}\t"+
        s"${req.method}\t${req.host.getOrElse("-")}\t${req.path.getOrDefault("-")}\t" +
        s"${req.cookies.getValue("border_session").getOrElse("-").takeRight(8)}\t"+
        s"${resp.statusCode}\t${req.contentLength.getOrElse("-")}\t" +
        s"${resp.cookies.getValue("border_session").getOrElse("-").takeRight(8)}\t"+
        s"${resp.contentLength.getOrElse("-")}\t${Time.now.since(startTime).inMilliseconds}\t ${req}AccessLogV1"))
    } yield resp

  }
}
