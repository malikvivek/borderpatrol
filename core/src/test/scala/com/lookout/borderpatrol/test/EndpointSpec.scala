package com.lookout.borderpatrol.test

import java.net.URL

import com.lookout.borderpatrol._
import com.twitter.finagle.Service
import com.twitter.finagle.http.path.Path
import com.twitter.finagle.http.{Request, Response, Status}
import com.twitter.util.Await


class EndpointSpec extends BorderPatrolSuite {
  import coreTestHelpers._

  override def afterEach(): Unit = {
    try {
      super.afterEach() // To be stackable, must call super.afterEach
    }
    finally {
      Endpoint.clearCache()
    }
  }

  behavior of "Endpoint"

  it should "store clients in the cache" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678", Service.mk[Request, Response] { req =>
        Response(Status.Ok).toFuture
      }
    )
    try {
      // Good endpoints (are stored)
      val resp1 = tokenmasterIdEndpoint.send(Request())
      val resp2 = tokenmasterAccessEndpoint.send(Request())
      Endpoint.get(tokenmasterIdEndpoint.name) should not be(None)
      Endpoint.get(tokenmasterAccessEndpoint.name) should not be(None)
      Await.result(resp1).status should be(Status.Ok)
      Await.result(resp2).status should be(Status.Ok)

      // Bad endpoints (are also stored)
      val badEndpoint = SimpleEndpoint("blah", Path("/some"), Set(new URL("http://some.example.com:1234")))
      val resp3 = badEndpoint.send(Request())
      val caught = the[BpCommunicationError] thrownBy {
        Await.result(resp3)
      }
      caught.getMessage should include("Failed to connect for: 'blah' to")
      Endpoint.get(badEndpoint.name) should not be(None)

    } finally {
      server.close()
    }
  }
}
