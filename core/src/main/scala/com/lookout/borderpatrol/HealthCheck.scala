package com.lookout.borderpatrol

import java.net.URL

import com.twitter.finagle.http.{Request, Status}
import com.twitter.util._
import io.circe.Encoder
import io.circe._
import io.circe.generic.auto._
import io.circe.syntax._
import scala.collection.concurrent.TrieMap


/**
 * Derive a custom healthCheck from this trait and register with the registry
 */
trait HealthCheck {
  val name: String
  def check(): Future[HealthCheckStatus]

  /** Intercept the future exceptions and convert it into HealthCheckStatus */
  def execute(): Future[HealthCheckStatus] =
    (for {
      hcs <- check()
    } yield hcs) handle {
      case e => HealthCheckStatus.unhealthy(Status.InternalServerError, e.getMessage)
    }
}

object HealthCheck {

  /** BorderPatrol health check on a URL */
  case class UrlHealthCheck(name: String, url: URL) extends HealthCheck {
    def check(): Future[HealthCheckStatus] =
      BinderBase.connect(s"${getClass.getSimpleName}.$name", Set(url), Request()).map(rep => rep.status match {
        case Status.Ok => HealthCheckStatus.healthy
        case _ => HealthCheckStatus.unhealthy(rep.status, rep.status.reason.asJson)
      })
  }
}

/**
 * Health Check status
 *
 * @param status
 * @param messageStr Message in string format
 * @param messageJson Message in JSON format
 */
case class HealthCheckStatus(status: Status,
                             messageStr: Option[String] = None,
                             messageJson: Option[Json] = None)

object HealthCheckStatus {
  val healthy = HealthCheckStatus(status=Status.Ok)

  def healthy(message: String): HealthCheckStatus =
    HealthCheckStatus(status=Status.Ok, messageStr=Some(message))

  def healthy(message: Json): HealthCheckStatus =
    HealthCheckStatus(status=Status.Ok, messageJson=Some(message))

  def unhealthy(status: Status, message: String): HealthCheckStatus =
    HealthCheckStatus(status, messageStr=Some(message))

  def unhealthy(status: Status, message: Json): HealthCheckStatus =
    HealthCheckStatus(status, messageJson=Some(message))

  // Encoder/Decoder for HealthCheckStatus
  implicit val encodeHealthCheckStatus: Encoder[HealthCheckStatus] = Encoder.instance { result =>
    if (result.messageStr.nonEmpty)
      Json.fromFields(Seq(
        ("status", result.status.code.asJson),
        ("message", result.messageStr.asJson)))
    else if (result.messageJson.nonEmpty)
      Json.fromFields(Seq(
        ("status", result.status.code.asJson),
        ("message", result.messageJson.asJson)))
    else
      Json.fromFields(Seq(
        ("status", result.status.code.asJson)))
  }
}

class HealthCheckRegistry {
  private[this] val healthChecks = TrieMap[String, HealthCheck]()

  def register(healthCheck: HealthCheck): Unit =
    healthChecks.putIfAbsent(healthCheck.name, healthCheck)

  def collectHealthCheckResults(): Future[Map[String, HealthCheckStatus]] =
    Future.collect((healthChecks.map(hc => (hc._1, hc._2.execute()))).toMap)
}
