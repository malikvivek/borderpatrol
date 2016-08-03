package com.lookout.borderpatrol.auth.tokenmaster

import com.lookout.borderpatrol.BpCommunicationError
import com.lookout.borderpatrol.auth.{BorderRequest, BpForbiddenRequest}
import com.lookout.borderpatrol.sessionx._
import com.lookout.borderpatrol.test._
import com.twitter.finagle.Service
import com.twitter.finagle.http.{Request, Response, Status}
import com.twitter.finagle.http.service.RoutingService
import com.twitter.util.Await


class LoginManagersSpec extends BorderPatrolSuite {
  import coreTestHelpers._
  import tokenmasterTestHelpers._

  behavior of "BasicLoginManager"

  it should "return a valid redirect location" in {
    val request = req("enterprise", "ent")
    checkpointLoginManager.redirectLocation(request) should be(checkpointLoginManager.authorizePath.toString)
    checkpointLoginManager.redirectLocation(request, "foo" -> "bar", "bar" -> "baz") should
      be(checkpointLoginManager.authorizePath.toString + "?foo=bar&bar=baz")
  }

  behavior of "OAuth2LoginManager"

  it should "return a valid redirect location" in {
    val request1 = req("sky", "ulm1")
    request1.headerMap.set("X-Forwarded-Proto", "https")
    val request2 = req("sky", "ulm2")
    val request3 = req("sky", "ulm3", "action" -> "consent")
    val request4 = req("sky", "ulm4", "action" -> "foo")
    val location1 = umbrellaLoginManager.redirectLocation(request1)
    val location2 = umbrellaLoginManager.redirectLocation(request2, "foo" -> "bar", "bar" -> "baz")
    location1 should startWith(umbrellaLoginManager.authorizeEndpoint.hosts.head.toString +
      umbrellaLoginManager.authorizeEndpoint.path.toString)
    location1 should include("response_type=code")
    location1 should include("state=foo")
    location1 should not include("prompt=")
    location1 should include("client_id=clientId")
    location1 should include("redirect_uri=https%3A%2F%2Fsky.example.com%2Fsignin")
    location2 should include("redirect_uri=http%3A%2F%2Fsky.example.com%2Fsignin")
    location2 should include("foo=bar")
    location2 should include("bar=baz")
    umbrellaLoginManager.redirectLocation(request3) should include("prompt=admin_consent")
    umbrellaLoginManager.redirectLocation(request4) should not include("prompt=")
  }

  it should "succeed to fetch oAuth2 token for code from server" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains "token" => Service.mk[Request, Response] { req =>
          req.getParam("code") should be("XYZ123")
          req.contentString should include("redirect_uri=https%3A%2F%2Fsky.example.com%2Fsignin")
          Response(Status.Ok).toFuture
        }
        case _ => fail("must not get here")
      })

    try {
      // Login POST request
      val request = req("sky", "/signin", ("code" -> "XYZ123"))
      val borderRequest = BorderRequest(request, cust2, two, sessionid.untagged)
      request.headerMap.set("X-Forwarded-Proto", "https")

      // Execute
      val output = umbrellaLoginManager.codeToToken(borderRequest)

      // Validate
      Await.result(output).status should be(Status.Ok)
    } finally {
      server.close()
    }
  }

  it should "throw an Exception if host value is not present in the request when calling redirectLocation" in {
    // Create request
    val request = Request("/umb")

    // Validate
    val caught = the[Exception] thrownBy {
      // Execute
      val output = umbrellaLoginManager.redirectLocation(request)
    }
    caught.getMessage should include("Host not found in Request")
  }

  it should "throw a BpCommunicationError if it fails to reach OAuth2 IDP to convert code to token" in {

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = req("rainy", "/signblew", ("code" -> "XYZ123"))
    val borderRequest = BorderRequest(request, cust2, two, sessionid.untagged)

    // Execute
    val output = rainyLoginManager.codeToToken(borderRequest)

    // Validate
    val caught = the[BpCommunicationError] thrownBy {
      Await.result(output)
    }
    caught.getMessage should include (
      "An error occurred while talking to: Failed to connect for: 'rlmTokenEndpoint'")
  }

  it should "throw an Exception if host value is not present in the request when calling codeToToken" in {
    // Create request
    val request = Request("/umb")
    val borderRequest = BorderRequest(request, cust2, two, sessionid.untagged)

    // Validate
    val caught = the[Exception] thrownBy {
      // Execute
      val output = umbrellaLoginManager.codeToToken(borderRequest)
    }
    caught.getMessage should include("Host not found in Request")
  }

  it should "throw a BpForbiddenRequest if it fails to receive OAuth2 code from oAuth2 server" in {

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = req("enterprise", "/ent")
    val borderRequest = BorderRequest(request, cust2, two, sessionid.untagged)

    // Validate
    val caught = the[BpForbiddenRequest] thrownBy {
      // Execute
      val output = umbrellaLoginManager.codeToToken(borderRequest)
    }
    caught.getMessage should include("Forbidden: OAuth2 code not found in HTTP Request")
  }

  it should "throw a BpForbiddenRequest and log error if it fails to receive OAuth2 code from oAuth2 server" in {

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = req("enterprise", "/ent", ("error" -> "Access_denied"), ("error_description" -> "Something bad"))
    val borderRequest = BorderRequest(request, cust2, two, sessionid.untagged)

    // Validate
    val caught = the[BpForbiddenRequest] thrownBy {
      // Execute
      val output = umbrellaLoginManager.codeToToken(borderRequest)
    }
    caught.getMessage should include("OAuth2 authentication failed with error: 'Access_denied: Something bad'")
  }
}