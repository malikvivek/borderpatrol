package com.lookout.borderpatrol.auth

import com.lookout.borderpatrol.sessionx.SessionStores.MemcachedStore
import com.lookout.borderpatrol.sessionx._
import com.lookout.borderpatrol.test.BorderPatrolSuite
import com.lookout.borderpatrol.test.sessionx
import com.twitter.finagle.http._
import com.twitter.finagle.memcached
import com.twitter.finagle.memcached.GetResult
import com.twitter.io.Buf
import com.twitter.util.{Await, Future, Time}


class BorderAuthSpec extends BorderPatrolSuite  {
  import sessionx.helpers.{secretStore => store, _}

  // Method to decode SessionData from the sessionId in Response
  def sessionDataFromResponse(resp: Response): Future[Request] =
    (for {
      sessionId <- SignedId.fromResponse(resp).toFuture
      sessionMaybe <- sessionStore.get[Request](sessionId)
    } yield sessionMaybe.fold[Identity[Request]](EmptyIdentity)(s => Id(s.data))).map {
      case Id(req) => req
      case EmptyIdentity => null
    }

  //  Test Services
  val serviceFilterTestService = mkTestService[CustomerIdRequest, Response] { req => Future.value(Response(Status.Ok)) }
  val sessionIdFilterTestService = mkTestService[SessionIdRequest, Response] { req => Future.value(Response(Status.Ok)) }
  val identityFilterTestService = mkTestService[AccessIdRequest[Request], Response] { req => Future.value(Response(Status.Ok)) }
  val workingService = mkTestService[BorderRequest, Response] { req => Response(Status.Ok).toFuture }
  val workingMap = Map("keymaster" -> workingService)

  //  Mock SessionStore client
  case object FailingMockClient extends memcached.MockClient {
    override def set(key: String, flags: Int, expiry: Time, value: Buf) : Future[Unit] = {
      Future.exception[Unit](new Exception("oopsie"))
    }
    override def getResult(keys: Iterable[String]): Future[GetResult] = {
      Future.exception(new Exception("oopsie"))
    }
  }

  behavior of "CustomerIdFilter"

  it should "succeed and return output of upstream Service if Request is destined to a known Service" in {
    // Execute
    val output = (CustomerIdFilter(serviceMatcher) andThen serviceFilterTestService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "return NotFound Status if Request is destined to an unknown Service" in {
    // Execute
    val output = (CustomerIdFilter(serviceMatcher) andThen serviceFilterTestService)(req("foo", "/bar"))

    // Validate
    Await.result(output).status should be (Status.NotFound)
  }

  behavior of "SessionIdFilter"

  it should "succeed and return output of upstream Service if CustomerIdRequest contains SignedId" in {
    val testService = mkTestService[SessionIdRequest, Response] {
      req => {
        assert(req.req.path == "/ent")
        Future.value(Response(Status.Ok))
      }
    }

    //  Allocate and Session
    val sessionId = sessionid.untagged
    val cooki = sessionId.asCookie()

    //  Create request
    val request = req("enterprise", "/ent")
    request.addCookie(cooki)

    //  Execute
    val output = (SessionIdFilter(sessionStore) andThen testService)(CustomerIdRequest(request, cust1))

    //  Verify
    Await.result(output).status should be (Status.Ok)
  }

  it should "return redirect to login URI, if no SignedId present in the BorderRequest" in {

    // Create request
    val request = req("enterprise", "/ent")

    // Execute
    val output = (SessionIdFilter(sessionStore) andThen sessionIdFilterTestService)(CustomerIdRequest(request, cust1))

    // Validate
    Await.result(output).status should be (Status.Found)
    Await.result(output).location.get should be (request.path)
    val sessionData = sessionDataFromResponse(Await.result(output))
    Await.result(sessionData).path should be (request.path)
  }

  it should "return redirect to login URI, if no SignedId present in the BorderRequest for OAuth2Code" in {

    // Create request
    val request = req("sky", "/umb")

    // Execute
    val output = (SessionIdFilter(sessionStore) andThen sessionIdFilterTestService)(CustomerIdRequest(request, cust2))

    // Validate
    Await.result(output).status should be (Status.Found)
    Await.result(output).location.get should be (request.uri)
    val sessionData = sessionDataFromResponse(Await.result(output))
    Await.result(sessionData).path should be (request.path)
  }

  it should "propagate the error Status code returned by the upstream Service" in {
    val testService = mkTestService[SessionIdRequest, Response] { request => Future.value(Response(Status.NotFound))}

    // Allocate and Session
    val sessionId = sessionid.untagged
    val cooki = sessionId.asCookie()

    // Create request
    val request = req("enterprise", "/ent")
    request.addCookie(cooki)

    // Execute
    val output = (SessionIdFilter(sessionStore) andThen testService)(CustomerIdRequest(request, cust1))

    // Verify
    Await.result(output).status should be (Status.NotFound)
  }

  it should "propagate the Exception thrown by the upstream Service" in {
    val testService = mkTestService[SessionIdRequest, Response] {
      request => Future.exception(new Exception("SessionIdFilter test failure"))
    }

    // Allocate and Session
    val sessionId = sessionid.untagged
    val cooki = sessionId.asCookie()

    // Create request
    val request = req("enterprise", "/ent")
    request.addCookie(cooki)

    // Execute
    val output = (SessionIdFilter(sessionStore) andThen testService)(CustomerIdRequest(request, cust1))

    // Verify
    val caught = the [Exception] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal ("SessionIdFilter test failure")
  }

  it should "propagate the Exception thrown while storing the Session using SessionStore.update" in {
    // Mock sessionStore
    val mockSessionStore = MemcachedStore(FailingMockClient)

    // Create request
    val request = req("enterprise", "/ent")

    // Execute
    val output = (SessionIdFilter(mockSessionStore) andThen sessionIdFilterTestService)(CustomerIdRequest(request, cust1))

    // Verify
    val caught = the [Exception] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal ("oopsie")
  }

  behavior of "IdentityFilter"

  it should "succeed and return output of upstream Service, if Session is found for SignedId" in {
    val testService = mkTestService[AccessIdRequest[Int], Response] {
      request => {
        assert(request.id == Identity(999))
        Future.value(Response(Status.Ok)) }
    }

    //  Allocate and Session
    val sessionId = sessionid.untagged
    val cooki = sessionId.asCookie()

    //  Create request
    val request = req("enterprise", "/ent")
    request.addCookie(cooki)
    val sessionData = 999
    sessionStore.update[Int](Session(sessionId, sessionData))

    //  Execute
    val output = (IdentityFilter[Int](sessionStore) andThen testService)(
      BorderRequest(request, cust1, one, sessionId))

    //  Verify
    Await.result(output).status should be (Status.Ok)
  }

  it should "return a redirect to login URL, if it fails Session lookup using SignedId" in {

    // Allocate and Session
    val sessionId = sessionid.untagged
    val cooki = sessionId.asCookie()

    // Create request
    val request = req("enterprise", "/ent")
    request.addCookie(cooki)

    // Execute
    val output = (IdentityFilter[Request](sessionStore) andThen identityFilterTestService)(
      BorderRequest(request, cust1, one, sessionId))

    // Verify
    Await.result(output).status should be (Status.Found)
    Await.result(output).location.get should be (request.uri)
    val returnedSessionId = SignedId.fromResponse(Await.result(output)).toFuture
    Await.result(returnedSessionId) should not be (sessionId)
    val sessionData = sessionDataFromResponse(Await.result(output))
    Await.result(sessionData).path should be (request.path)
  }

  it should "propagate the exception thrown by SessionStore.get operation" in {
    // Allocate and Session
    val sessionId = sessionid.untagged
    val cooki = sessionId.asCookie()

    // Create request
    val request = req("enterprise", "/ent")
    request.addCookie(cooki)

    // Mock sessionStore
    val mockSessionStore = MemcachedStore(FailingMockClient)

    // Execute
    val output = (IdentityFilter[Request](mockSessionStore) andThen identityFilterTestService)(
      BorderRequest(request, cust1, one, sessionId))

    // Verify
    val caught = the [Exception] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal ("oopsie")
  }

  it should "propagate the Exception thrown by SessionStore.update operation" in {
    //  Mock SessionStore client
    case object FailingUpdateMockClient extends memcached.MockClient {
      override def set(key: String, flags: Int, expiry: Time, value: Buf) : Future[Unit] = {
        Future.exception[Unit](new Exception("whoopsie"))
      }
    }

    // Allocate and Session
    val sessionId = sessionid.untagged
    val cooki = sessionId.asCookie()

    // Mock sessionStore
    val mockSessionStore = MemcachedStore(FailingUpdateMockClient)

    // Create request
    val request = req("enterprise", "/ent")
    request.addCookie(cooki)

    // Execute
    val output = (IdentityFilter[Request](mockSessionStore) andThen identityFilterTestService)(
      BorderRequest(request, cust1, one, sessionId))

    // Verify
    val caught = the [Exception] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal ("whoopsie")
  }

  behavior of "ExceptionFilter"

  it should "succeed and act as a passthru for the valid Response returned by Service" in {
    val testService = mkTestService[Request, Response] { req => Future.value(Response(Status.Ok)) }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "succeed and convert the AccessDenied exception into error Response" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(AccessDenied(Status.NotAcceptable, "No access allowed to service"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.NotAcceptable)
    Await.result(output).contentString should be ("AccessDenied: No access allowed to service")
  }

  it should "succeed and convert the SessionStoreError exception into error Response" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(new SessionStoreError("update failed"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.InternalServerError)
    Await.result(output).contentString should be ("An error occurred interacting with the session store: update failed")
  }

  it should "succeed and convert the AccessIssuerError exception into error Response" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(AccessIssuerError(Status.NotAcceptable, "Some access issuer error"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.NotAcceptable)
    Await.result(output).contentString should be ("Some access issuer error")
  }

  it should "succeed and convert the IdentityProviderError exception into error Response" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(IdentityProviderError(Status.NotAcceptable, "Some identity provider error"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.NotAcceptable)
    Await.result(output).contentString should be ("Some identity provider error")
  }

  it should "succeed and convert the Runtime exception into error Response" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(new RuntimeException("some weird exception"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.InternalServerError)
    Await.result(output).contentString should be ("some weird exception")
  }

  behavior of "BorderService"

  it should "successfully reach the upstream service path via access service chain, if authenticated" in {
    val identityService = mkTestService[BorderRequest, Response] { _ => fail("Must not invoke identity service") }
    val identityProviderMap = Map("keymaster" -> identityService)
    val testSidBinder = mkTestSidBinder { _ => fail("TestSidBinder should not be invoked for this test") }

    // Allocate and Session
    val sessionId = sessionid.authenticated

    // Login POST request
    val request = req("enterprise", "/ent")

    // Original request
    val output = BorderService(identityProviderMap, workingMap, serviceMatcher, testSidBinder).apply(
      SessionIdRequest(request, cust1, sessionId))

    //  Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "successfully reach the unprotected upstream service path, if unauthenticated" in {
    val accessService = mkTestService[BorderRequest, Response] { _ => fail("Must not invoke identity service") }
    val accessServiceMap = Map("keymaster" -> accessService)
    val testSidBinder = mkTestSidBinder { req => {
      assert(req.context == checkpointSid)
      Response(Status.Ok).toFuture
    }}

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = req("enterprise", "/check")

    // Original request
    val output = BorderService(workingMap, accessServiceMap, serviceMatcher, testSidBinder).apply(
      SessionIdRequest(request, cust1, sessionId))

    //  Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "successfully reach the unprotected upstream service path, if authenticated" in {
    val accessService = mkTestService[BorderRequest, Response] { _ => fail("Must not invoke identity service") }
    val accessServiceMap = Map("keymaster" -> accessService)
    val testSidBinder = mkTestSidBinder { req => {
      assert(req.context == checkpointSid)
      Response(Status.Ok).toFuture
    }}

    // Allocate and Session
    val sessionId = sessionid.authenticated

    // Login POST request
    val request = req("enterprise", "/check")

    // Original request
    val output = BorderService(workingMap, accessServiceMap, serviceMatcher, testSidBinder).apply(
      SessionIdRequest(request, cust1, sessionId))

    //  Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "successfully reach the loginManager confirm path via identity provider chain, if unauthenticated" in {
    val accessService = mkTestService[BorderRequest, Response] { _ => fail("Must not invoke identity service") }
    val accessServiceMap = Map("keymaster" -> accessService)
    val testSidBinder = mkTestSidBinder { _ => { fail("TestSidBinder should not be invoked for this test") } }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = req("enterprise", "/loginConfirm")

    // Original request
    val output = BorderService(workingMap, accessServiceMap, serviceMatcher, testSidBinder).apply(
      SessionIdRequest(request, cust1, sessionId))

    //  Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "send a redirect to default service if session is unauthenticated and trying to reach Root path" in {
    val testSidBinder = mkTestSidBinder { _ => { fail("TestSidBinder should not be invoked for this test") } }

    //  Allocate and Session
    val sessionId = sessionid.untagged

    //  Create request
    val request = req("enterprise", "")

    //  Execute
    val output = BorderService(workingMap, workingMap, serviceMatcher, testSidBinder).apply(
      SessionIdRequest(request, cust1, sessionId))

    //  Verify
    Await.result(output).status should be (Status.Found)
    Await.result(output).location.value should be ("/ent")
  }

  it should "send a redirect to default service if session is authenticated and trying to reach Root path" in {
    val testSidBinder = mkTestSidBinder { _ => { fail("TestSidBinder should not be invoked for this test") } }

    //  Allocate and Session
    val sessionId = sessionid.authenticated

    //  Create request
    val request = req("enterprise", "/")

    //  Execute
    val output = BorderService(workingMap, workingMap, serviceMatcher, testSidBinder).apply(
      SessionIdRequest(request, cust1, sessionId))

    //  Verify
    Await.result(output).status should be (Status.Found)
    Await.result(output).location.value should be ("/ent")
  }

  it should "send a redirect to login if session is unauthenticated and trying to reach upstream service" in {
    val testSidBinder = mkTestSidBinder { _ => { fail("TestSidBinder should not be invoked for this test") } }

    //  Allocate and Session
    val sessionId = sessionid.untagged

    //  Create request
    val request = req("enterprise", "/ent/dothis")

    //  Execute
    val output = BorderService(workingMap, workingMap, serviceMatcher, testSidBinder).apply(
      SessionIdRequest(request, cust1, sessionId))

    //  Verify
    Await.result(output).status should be (Status.Found)
    Await.result(output).location.value should be ("/check")
  }

  it should "send a redirect to login if session is unauthenticated and trying to reach unknown service" in {
    val testSidBinder = mkTestSidBinder { _ => { fail("TestSidBinder should not be invoked for this test") } }

    //  Allocate and Session
    val sessionId = sessionid.untagged

    //  Create request
    val request = req("enterprise", "/unknown")

    //  Execute
    val output = BorderService(workingMap, workingMap, serviceMatcher, testSidBinder).apply(
      SessionIdRequest(request, cust1, sessionId))

    //  Verify
    Await.result(output).status should be (Status.Found)
    Await.result(output).location.value should be ("/check")
  }

  it should "return a Status.NotFound if session is authenticated and trying to reach LoginManager confirm" in {
    val testSidBinder = mkTestSidBinder { _ => { fail("TestSidBinder should not be invoked for this test") } }

    //  Allocate and Session
    val sessionId = sessionid.authenticated

    //  Create request
    val request = req("enterprise", "/loginConfirm")

    //  Execute
    val output = BorderService(workingMap, workingMap, serviceMatcher, testSidBinder).apply(
      SessionIdRequest(request, cust1, sessionId))

    //  Verify
    Await.result(output).status should be (Status.NotFound)
  }

  it should "return a Status.NotFound if session is authenticated and trying to reach unknown path" in {
    val testSidBinder = mkTestSidBinder { _ => { fail("TestSidBinder should not be invoked for this test") } }

    //  Allocate and Session
    val sessionId = sessionid.authenticated

    //  Create request
    val request = req("enterprise", "/unknown")

    //  Execute
    val output = BorderService(workingMap, workingMap, serviceMatcher, testSidBinder).apply(
      SessionIdRequest(request, cust1, sessionId))

    //  Verify
    Await.result(output).status should be (Status.NotFound)
  }

  it should "throw an AccessIssuerError if it fails to find AccessIssuer service chain" in {
    val accessIssuerMap = Map("foo" -> workingService)
    val testSidBinder = mkTestSidBinder { _ => { fail("TestSidBinder should not be invoked for this test") } }

    // Allocate and Session
    val sessionId = sessionid.authenticated

    // Login POST request
    val request = req("enterprise", "/ent")

    // Validate
    val caught = the [AccessIssuerError] thrownBy {
      // Execute
      val output = BorderService(workingMap, accessIssuerMap, serviceMatcher, testSidBinder).apply(
        SessionIdRequest(request, cust1, sessionId))
    }
    caught.getMessage should equal ("Failed to find AccessIssuer Service Chain for keymaster")
  }

  it should "throw an IdentityProviderError if it fails to find IdentityProvider service chain" in {
    val identityProviderMap = Map("foo" -> workingService)
    val testSidBinder = mkTestSidBinder { _ => { fail("TestSidBinder should not be invoked for this test") } }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = req("enterprise", "/loginConfirm")

    // Validate
    val caught = the [IdentityProviderError] thrownBy {
      // Execute
      val output = BorderService(identityProviderMap, workingMap, serviceMatcher, testSidBinder).apply(
        SessionIdRequest(request, cust1, sessionId))
    }
    caught.getMessage should equal ("Failed to find IdentityProvider Service Chain for keymaster")
  }

  behavior of "AccessFilter"

  case class TestAccessResponse(access: Access[String]) extends AccessResponse[String]

  it should "succeed and include service token in the request and invoke the REST API of upstream service" in {
    val accessService = mkTestService[AccessRequest[Int], AccessResponse[String]] {
      request => TestAccessResponse (Access("blah")).toFuture
    }
    val testSidBinder = mkTestSidBinder {
      request => {
        // Verify service token in the request
        assert(request.req.uri == one.path.toString)
        assert(request.req.headerMap.get("Auth-Token") == Some("blah"))
        Response(Status.Ok).toFuture
      }
    }

    // Allocate and Session
    val sessionId = sessionid.authenticated

    // Create request
    val request = req("enterprise", "/ent")

    // Execute
    val output = (AccessFilter[Int, String](testSidBinder) andThen accessService)(
      AccessIdRequest(request, cust1, one, sessionId, Id(10)))

    // Validate
    Await.result(output).status should be (Status.Ok)
  }

  behavior of "RewriteFilter"

  it should "succeed and include service token in the request and invoke the REST API of upstream service" in {
    val testService = mkTestService[BorderRequest, Response] {
      req => {
        // Verify path is unchanged in the request
        assert(req.req.uri.startsWith(one.path.toString))
        Response(Status.Ok).toFuture
      }
    }

    // Allocate and Session
    val sessionId = sessionid.authenticated

    // Create request
    val request = req("enterprise", "/ent/whatever")

    // Execute
    val output = (RewriteFilter() andThen testService)(
      BorderRequest(request, cust1, one, sessionId))

    // Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "succeed and include service token in the request and invoke rewritten URL on upstream service" in {
    val testService = mkTestService[BorderRequest, Response] {
      req => {
        // Verify path is rewritten in the request
        assert(req.req.uri.startsWith(two.rewritePath.get.toString))
        Response(Status.Ok).toFuture
      }
    }

    // Allocate and Session
    val sessionId = sessionid.authenticated

    // Create request
    val request = req("umbrella", "/umb/some/weird/path")

    // Execute
    val output = (RewriteFilter() andThen testService)(
      BorderRequest(request, cust2, two, sessionId))

    // Validate
    Await.result(output).status should be (Status.Ok)
  }

  behavior of "LogoutService"

  it should "succeed to logout by deleting session from store and redirecting to default service" in {
    // Allocate and Session
    val sessionId = sessionid.authenticated
    val sessionCookie = sessionId.asCookie()

    // Session data
    val sessionData = 999
    sessionStore.update[Int](Session(sessionId, sessionData))

    // Create request
    val request = req("enterprise", "/logout")
    request.addCookie(sessionCookie)

    // Add more cookies
    val signedId1 = sessionid.untagged
    val cooki1 = signedId1.asCookie("border_some")
    request.addCookie(cooki1)
    val signedId2 = sessionid.untagged
    val cooki2 = signedId2.asCookie("some")
    request.addCookie(cooki2)

    // Execute
    val output = LogoutService(sessionStore).apply(CustomerIdRequest(request, cust1))

    // Validate
    Await.result(output).status should be (Status.Found)
    Await.result(output).location.get should be (cust1.defaultServiceId.path.toString)
    Await.result(output).cookies.get(sessionCookie.name).get.value should be ("")
    Await.result(output).cookies.get(sessionCookie.name).get.isDiscard should be (true)
    Await.result(output).cookies.get(cooki1.name).get.value should be ("")
    Await.result(output).cookies.get(cooki2.name) should be (None)
    Await.result(sessionStore.get[Int](sessionId)) should be (None)
  }

  it should "succeed to logout the requests w/o sessionId by simply redirecting to default service" in {
    // Create request
    val request = req("enterprise", "/logout")

    // Execute
    val output = LogoutService(sessionStore).apply(CustomerIdRequest(request, cust1))

    // Validate
    Await.result(output).status should be (Status.Found)
    Await.result(output).location.get should be (cust1.defaultServiceId.path.toString)
    Await.result(output).cookies.get(SignedId.sessionIdCookieName) should be (None)
  }

  it should "succeed to logout the requests w/o sessionId by simply redirecting to logged out page" in {
    // Create request
    val request = req("sky", "/logout")

    // Execute
    val output = LogoutService(sessionStore).apply(CustomerIdRequest(request, cust2))

    // Validate
    Await.result(output).status should be (Status.Found)
    Await.result(output).location.get should be (cust2.loginManager.protoManager.loggedOutUrl.get.toString)
    Await.result(output).cookies.get(SignedId.sessionIdCookieName) should be (None)
  }
}
