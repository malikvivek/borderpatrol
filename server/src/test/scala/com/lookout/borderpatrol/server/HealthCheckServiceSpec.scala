package com.lookout.borderpatrol.server

import com.lookout.borderpatrol.{HealthCheckStatus, HealthCheckRegistry}
import com.lookout.borderpatrol.test.BorderPatrolSuite
import com.twitter.finagle.http.{Status, Request}
import com.twitter.util.{Await, Future}
import org.mockito.Mockito._
import org.scalatest.mock.MockitoSugar
import io.circe.generic.auto._
import io.circe.syntax._


class HealthCheckServiceSpec extends BorderPatrolSuite with MockitoSugar {

  behavior of "HealthCheckService"

  it should "returns Status.NotImplemented, when no registry collects no HealthStatus(s)" in {
    // Registry
    val mockRegistry = mock[HealthCheckRegistry]
    when(mockRegistry.collectHealthCheckResults()).thenReturn(
      Future.value(Map.empty[String, HealthCheckStatus]))

    // Execute
    val output = HealthCheckService(mockRegistry, "0.0.0")(Request())

    // Validate
    Await.result(output).status should be (Status.NotImplemented)
    Await.result(output).contentType.get should include("application/json")
    Await.result(output).contentString.replaceAll("\\s", "") should be("""{"status":501,"dependencies":{},"version":"0.0.0"}""")
  }

  it should "return Status.Ok, when registry collects all healthy Status(s)" in {
    // Registry
    val mockRegistry = mock[HealthCheckRegistry]
    when(mockRegistry.collectHealthCheckResults()).thenReturn(
      Future.value(Map("node1" -> HealthCheckStatus.healthy("string message"),
        "node2" -> HealthCheckStatus.healthy("json message".asJson))))

    // Execute
    val output = HealthCheckService(mockRegistry, "0.0.0")(Request())

    // Validate
    Await.result(output).status should be (Status.Ok)
    Await.result(output).contentType.get should include("application/json")
    Await.result(output).contentString.replaceAll("\\s", "") should be("""{"status":200,"dependencies":{"node2":{"status":200,"message":"jsonmessage"},"node1":{"status":200,"message":"stringmessage"}},"version":"0.0.0"}""")
  }

  it should "return Status.InternalError, when registry collects at least one unhealthy Status(s)" in {
    // Registry
    val mockRegistry = mock[HealthCheckRegistry]
    when(mockRegistry.collectHealthCheckResults()).thenReturn(
      Future.value(Map("node1" -> HealthCheckStatus.healthy("string message"),
        "node2" -> HealthCheckStatus.healthy("json message".asJson),
        "node3" -> HealthCheckStatus.unhealthy(Status.BadGateway, "string message"),
        "node3" -> HealthCheckStatus.unhealthy(Status.MovedPermanently, "json message".asJson)
      )))

    // Execute
    val output = HealthCheckService(mockRegistry, "0.0.0")(Request())

    // Validate
    Await.result(output).status should be (Status.InternalServerError)
    Await.result(output).contentType.get should include("application/json")
    Await.result(output).contentString.replaceAll("\\s", "") should be("""{"status":500,"dependencies":{"node2":{"status":200,"message":"jsonmessage"},"node1":{"status":200,"message":"stringmessage"},"node3":{"status":301,"message":"jsonmessage"}},"version":"0.0.0"}""")
  }
}
