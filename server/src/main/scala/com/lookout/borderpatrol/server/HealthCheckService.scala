package com.lookout.borderpatrol.server

import com.lookout.borderpatrol.{HealthCheckStatus, HealthCheckRegistry}
import com.lookout.borderpatrol.util.Combinators._
import com.twitter.finagle.Service
import com.twitter.finagle.http.{Status, Request, Response}
import com.twitter.util.Future
import io.circe.Json
import io.circe.generic.auto._
import io.circe.syntax._


case class HealthCheckService(registry: HealthCheckRegistry)
  extends Service[Request, Response] {

  private[this] def allHealthy(results: Map[String, HealthCheckStatus]) =
    results.filterNot(entry => entry._2.status == Status.Ok).isEmpty

  def apply(req: Request): Future[Response] = {
    registry.collectHealthCheckResults() map { results =>
      tap(Response()) { resp => {
        if (results.isEmpty)
          resp.status = Status.NotImplemented
        else if (allHealthy(results))
          resp.status = Status.Ok
        else
          resp.status = Status.InternalServerError

        resp.contentType = "application/Json"
        resp.contentString = Json.fromFields(Seq(
          ("status", resp.status.code.asJson),
          ("dependencies", results.asJson),
          ("version", BpBuild.BuildInfo.version.asJson)
        )).toString()
      }}
    }
  }
}
