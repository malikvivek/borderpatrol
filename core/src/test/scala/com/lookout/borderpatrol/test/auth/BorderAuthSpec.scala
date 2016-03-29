package com.lookout.borderpatrol.auth

import com.lookout.borderpatrol.BpCommunicationError
import com.lookout.borderpatrol.errors.BpNotFoundRequest
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

  // Method to decode SessionData from the sessionId
  def getRequestFromSessionId(sid: SignedId): Future[Request] =
    (for {
      sessionMaybe <- sessionStore.get[Request](sid)
    } yield sessionMaybe.fold[Identity[Request]](EmptyIdentity)(s => Id(s.data))).map(i => i match {
      case Id(req) => req
      case EmptyIdentity => null
    })

  // Method to decode SessionData from the sessionId in Response
  def sessionDataFromResponse(resp: Response): Future[Request] =
    for {
      sessionId <- SignedId.fromResponse(resp).toFuture
      req <- getRequestFromSessionId(sessionId)
    } yield req

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

  it should "send to upstream Service if Request is destined to a known Service" in {
    // Execute
    val output = (CustomerIdFilter(serviceMatcher) andThen serviceFilterTestService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "return NotFound Status if Request is destined to an unknown Service" in {
    // Execute
    val output = (CustomerIdFilter(serviceMatcher) andThen serviceFilterTestService)(req("foo", "/bar"))

    // Validate
    val caught = the [BpNotFoundRequest] thrownBy {
      Await.result(output)
    }
    caught.status should be(Status.NotFound)
    caught.getMessage should startWith ("Not Found: Failed to find CustomerIdentifier for")
  }

  it should "return NotFound Status if Request lacks the hostname " in {
    // Execute
    val output = (CustomerIdFilter(serviceMatcher) andThen serviceFilterTestService)(Request("/bar"))

    // Validate
    val caught = the [BpNotFoundRequest] thrownBy {
      Await.result(output)
    }
    caught.status should be(Status.NotFound)
    caught.getMessage should startWith ("Not Found: Failed to find CustomerIdentifier for")
    caught.getMessage should include ("null-hostname")
  }

  behavior of "SessionIdFilter"

  it should "succeed to find SessionId & ServiceId and forward it to upstream Service" in {

    //  Allocate and Session
    val sessionId = sessionid.untagged
    val cooki = sessionId.asCookie()

    //  Create request
    val request = req("enterprise", "/ent")
    request.addCookie(cooki)

    //  test service
    val testService = mkTestService[SessionIdRequest, Response] {
      req => {
        assert(req.serviceIdOpt == Some(one))
        assert(req.sessionIdOpt == Some(sessionId))
        Future.value(Response(Status.Ok))
      }
    }

    //  Execute
    val output = (SessionIdFilter(serviceMatcher, sessionStore) andThen testService)(CustomerIdRequest(request, cust1))

    //  Verify
    Await.result(output).status should be (Status.Ok)
  }

  it should "fail to find ServiceId and succeed to find SessionId, but forward it to upstream Service" in {

    //  Allocate and Session
    val sessionId = sessionid.untagged
    val cooki = sessionId.asCookie()

    //  Create request
    val request = req("enterprise", "/blah")
    request.addCookie(cooki)

    //  test service
    val testService = mkTestService[SessionIdRequest, Response] {
      req => {
        assert(req.serviceIdOpt == None)
        assert(req.sessionIdOpt == Some(sessionId))
        Future.value(Response(Status.Ok))
      }
    }

    //  Execute
    val output = (SessionIdFilter(serviceMatcher, sessionStore) andThen testService)(CustomerIdRequest(request, cust1))

    //  Verify
    Await.result(output).status should be (Status.Ok)
  }

  it should "fail to find SessionId and succeed to find ServiceId, but forward it to upstream Service" in {

    //  Create request
    val request = req("enterprise", "/ent")

    //  test service
    val testService = mkTestService[SessionIdRequest, Response] {
      req => {
        assert(req.serviceIdOpt == Some(one))
        assert(req.sessionIdOpt == None)
        Future.value(Response(Status.Ok))
      }
    }

    //  Execute
    val output = (SessionIdFilter(serviceMatcher, sessionStore) andThen testService)(CustomerIdRequest(request, cust1))

    //  Verify
    Await.result(output).status should be (Status.Ok)
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

    // Validate
    val caught = the [BpRedirectError] thrownBy {
      Await.result(output)
    }

    // Validate
    caught.status should be(Status.Unauthorized)
    caught.location should be equals ("/dang")
    caught.sessionIdOpt should not be (Some(sessionId))
    val reqZ = getRequestFromSessionId(caught.sessionIdOpt.get)
    Await.result(reqZ).uri should be(request.uri)
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

  it should "succeed and convert the BpAccessIssuerError exception into error Response" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(BpAccessIssuerError(Status.NotAcceptable, "No access allowed to service"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.NotAcceptable)
    Await.result(output).contentType should be (Some("text/plain"))
    Await.result(output).contentString should include ("No access allowed to service")
  }

  it should "succeed and convert the BpSessionStoreError exception into error Response" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(new BpSessionStoreError("update failed"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.InternalServerError)
    Await.result(output).contentString should include ("An error occurred interacting with the session store: update failed")
  }

  it should "succeed and convert the BpAccessIssuerError exception into JSON error Response" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(BpAccessIssuerError(Status.NotAcceptable, "Some access issuer error"))
    }

    // Login POST request
    val request = req("enterprise", cust1.loginManager.protoManager.loginConfirm.toString)
    request.accept = Seq("application/json")

    // Execute
    val output = (ExceptionFilter() andThen testService)(request)

    // Validate
    Await.result(output).status should be (Status.NotAcceptable)
    Await.result(output).contentType should be (Some("application/json"))
    Await.result(output).contentString should include (""""description" : "BPAUTH: Some access issuer error"""")
  }

  it should "succeed and convert the BpIdentityProviderError exception into error Response" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(BpIdentityProviderError(Status.NotAcceptable, "Some identity provider error"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.NotAcceptable)
    Await.result(output).contentString should be ("BPAUTH: Some identity provider error")
  }

  it should "succeed and convert the BpCoreError exception into error Response" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(BpCommunicationError("Some identity provider error"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.InternalServerError)
    Await.result(output).contentString should include ("Some identity provider error")
  }

  it should "succeed and convert the BpBorderError exception into error Response" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(new BpNotFoundRequest("Some identity provider error"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.NotFound)
    Await.result(output).contentString should be ("Not Found: Some identity provider error")
  }

  it should "succeed and convert the BpRedirectError exception into error Response" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(BpRedirectError(Status.Unauthorized, "/location", Some(sessionid.untagged),
        "Some identity provider error"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be (Status.Found)
    Await.result(output).location should be (Some("/location"))
    Await.result(output).contentString should be ("Some identity provider error")
  }

  it should "succeed and convert the BpRedirectError exception into error Response with json body" in {
    val testService = mkTestService[Request, Response] { req =>
      Future.exception(BpRedirectError(Status.Unauthorized, "/location", Some(sessionid.untagged),
        "Some identity provider error"))
    }

    // Request
    val request = req("enterprise", "/ent")
    request.accept = Seq("application/json")

    // Execute
    val output = (ExceptionFilter() andThen testService)(request)

    // Validate
    Await.result(output).status should be (Status.Unauthorized)
    Await.result(output).contentType should be (Some("application/json"))
    Await.result(output).contentString should include (""""redirect_url" : "/location"""")
    Await.result(output).contentString should include (""""description" : "Some identity provider error"""")
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

  behavior of "SendToIdentityProvider"

  it should "send a request for unauth SessionId to loginConfirm path to IdentityService chain" in {
    val testService = mkTestService[SessionIdRequest, Response] { _ => fail("Must not invoke this service") }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = reqPost("enterprise", cust1.loginManager.protoManager.loginConfirm.toString, Buf.Empty)

    // Original request
    val output = (SendToIdentityProvider(workingMap, sessionStore) andThen testService) (
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    //  Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "send a request w/o SessionId to loginConfirm path to IdentityService chain" in {
    val identityProvider = mkTestService[BorderRequest, Response] { req =>
      val storedReq = Await.result(sessionStore.get[Request](req.sessionId)).get.data
      storedReq.path should be (cust1.defaultServiceId.path.toString)
      SignedId.fromRequest(storedReq).toOption should be (Some(req.sessionId))
      Response(Status.Ok).toFuture
    }
    val identityProviderMap = Map("keymaster" -> identityProvider)
    val testService = mkTestService[SessionIdRequest, Response] { _ => fail("Must not invoke this service") }

    // Login POST request
    val request = reqPost("enterprise", cust1.loginManager.protoManager.loginConfirm.toString, Buf.Empty)

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService) (
      SessionIdRequest(request, cust1, Some(one), None))

    //  Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "send a request w/o SessionId w/ target_url to loginConfirm path to IdentityService chain" in {
    val identityProvider = mkTestService[BorderRequest, Response] { req =>
      val storedReq = Await.result(sessionStore.get[Request](req.sessionId)).get.data
      storedReq.path should be ("blah")
      SignedId.fromRequest(storedReq).toOption should be (Some(req.sessionId))
      Response(Status.Ok).toFuture
    }
    val identityProviderMap = Map("keymaster" -> identityProvider)
    val testService = mkTestService[SessionIdRequest, Response] { _ => fail("Must not invoke this service") }

    // Login POST request
    val request = reqPost("enterprise", cust1.loginManager.protoManager.loginConfirm.toString, Buf.Empty,
      ("target_url" -> "blah"))

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService) (
      SessionIdRequest(request, cust1, Some(one), None))

    //  Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "send the request w/ authenticated SessionId to follow-on service" in {
    val identityProvider = mkTestService[BorderRequest, Response] { _ => fail("Must not invoke identity service") }
    val identityProviderMap = Map("keymaster" -> identityProvider)
    val testService = mkTestService[SessionIdRequest, Response] { _ =>
      Response(Status.NotAcceptable).toFuture }

    // Allocate and Session
    val sessionId = sessionid.authenticated
    val cooki = sessionId.asCookie()

    // Login POST request
    val request = reqPost("enterprise", cust1.loginManager.protoManager.loginConfirm.toString, Buf.Empty)
    request.addCookie(cooki)

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService) (
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    //  Validate
    Await.result(output).status should be (Status.NotAcceptable)
  }

  it should "redirect the request w/ unauth SessionId for protected service to login page" in {
    val identityProvider = mkTestService[BorderRequest, Response] { _ => fail("Must not invoke identity service") }
    val identityProviderMap = Map("keymaster" -> identityProvider)
    val testService = mkTestService[SessionIdRequest, Response] { _ => fail("Must not invoke this service") }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login request
    val request = req("enterprise", "ent")

    // Original request
     val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService) (
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    // Validate
    val caught = the [BpRedirectError] thrownBy {
      Await.result(output)
    }

    // Validate
    caught.status should be(Status.Unauthorized)
    caught.location should be (internalProtoManager.authorizePath.toString)
    caught.sessionIdOpt should be (Some(sessionId))
  }

  it should "redirect the request w/ unauth SessionId for protected service to login page for OAuth2" in {
    val identityProvider = mkTestService[BorderRequest, Response] { _ => fail("Must not invoke identity service") }
    val identityProviderMap = Map("keymaster" -> identityProvider)
    val testService = mkTestService[SessionIdRequest, Response] { _ => fail("Must not invoke this service") }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login request
    val request = req("sky", "umb")

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService) (
      SessionIdRequest(request, cust2, Some(two), Some(sessionId)))

    // Validate
    val caught = the [BpRedirectError] thrownBy {
      Await.result(output)
    }

    // Validate
    caught.status should be(Status.Unauthorized)
    caught.location should startWith (oauth2CodeProtoManager.authorizeUrl.toString)
    caught.sessionIdOpt should be (Some(sessionId))
  }

  it should "redirect the request w/ unauth SessionId to unknown path to login page" in {
    val identityProvider = mkTestService[BorderRequest, Response] { _ => fail("Must not invoke identity service") }
    val identityProviderMap = Map("keymaster" -> identityProvider)
    val testService = mkTestService[SessionIdRequest, Response] { _ => fail("Must not invoke this service") }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login request
    val request = req("enterprise", "unknown")

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService) (
      SessionIdRequest(request, cust1, None, Some(sessionId)))

    // Validate
    val caught = the [BpRedirectError] thrownBy {
      Await.result(output)
    }

    // Validate
    caught.status should be(Status.Unauthorized)
    caught.location should be (internalProtoManager.authorizePath.toString)
    caught.sessionIdOpt should be (Some(sessionId))
  }

  it should "throw an BpIdentityProviderError if it fails to find IdentityProvider service chain" in {
    val identityProviderMap = Map("foo" -> workingService)

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = reqPost("enterprise", cust1.loginManager.protoManager.loginConfirm.toString, Buf.Empty)

    // Execute
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen sessionIdFilterTestService)(
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    // Validate
    val caught = the [BpIdentityProviderError] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal ("BPAUTH: Failed to find IdentityProvider Service Chain for keymaster")
  }

  it should "propagate the Exception thrown while storing the Session using SessionStore.update" in {
    val identityProvider = mkTestService[BorderRequest, Response] { _ => fail("Must not invoke identity service") }
    val identityProviderMap = Map("keymaster" -> identityProvider)
    val testService = mkTestService[SessionIdRequest, Response] { _ => fail("Must not invoke this service") }

    // Mock sessionStore
    val mockSessionStore = MemcachedStore(FailingMockClient)

    // Create request
    val request = reqPost("enterprise", cust1.loginManager.protoManager.loginConfirm.toString, Buf.Empty)

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, mockSessionStore) andThen testService) (
      SessionIdRequest(request, cust1, Some(one), None))

    // Verify
    val caught = the [Exception] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal ("oopsie")
  }

  it should "throw an exception while attempting a redirect to login and Host is not missing from HTTP Request" in {
    val testService = mkTestService[SessionIdRequest, Response] { _ => fail("Must not invoke this service") }

    //  Allocate and Session
    val sessionId = sessionid.untagged

    // Create request
    val request = Request("/umb")

    // Validate
    val caught = the[Exception] thrownBy {
      // Execute
      val output = (SendToIdentityProvider(workingMap, sessionStore) andThen testService)(
        SessionIdRequest(request, cust2, Some(two), Some(sessionId)))
    }
    caught.getMessage should equal("Host not found in HTTP Request")
  }

  behavior of "SendToAccessIssuer"

  it should "send the request to AccessIssuer chain if session is authenticated and trying to reach a valid service" in {
    val testService = mkTestService[SessionIdRequest, Response] { _ => fail("Must not invoke this service") }

    //  Allocate and Session
    val sessionId = sessionid.authenticated

    //  Create request
    val request = req("enterprise", "ent")

    //  Execute
    val output = (SendToAccessIssuer(workingMap) andThen testService)(
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    //  Verify
    Await.result(output).status should be (Status.Ok)
  }

  it should "redirect to default serviceId if session is authenticated and trying to reach Root path" in {
    val testService = mkTestService[SessionIdRequest, Response] { _ => fail("Must not invoke this service") }

    //  Allocate and Session
    val sessionId = sessionid.authenticated

    //  Create request
    val request = req("enterprise", "")

    //  Execute
    val output = (SendToAccessIssuer(workingMap) andThen testService)(
      SessionIdRequest(request, cust1, None, Some(sessionId)))

    // Validate
    val caught = the [BpRedirectError] thrownBy {
      Await.result(output)
    }

    // Validate
    caught.status should be(Status.NotFound)
    caught.location should be (one.path.toString)
  }

  it should "forward to next service if session is authenticated but trying to reach unknown path" in {
    val testService = mkTestService[SessionIdRequest, Response] { _ =>
      Response(Status.NotFound).toFuture }

    //  Allocate and Session
    val sessionId = sessionid.authenticated

    //  Create request
    val request = req("enterprise", "/unknown")

    //  Execute
    val output = (SendToAccessIssuer(workingMap) andThen testService)(
      SessionIdRequest(request, cust1, None, Some(sessionId)))

    //  Verify
    Await.result(output).status should be (Status.NotFound)
  }

  it should "throw an BpAccessIssuerError if it fails to find AccessIssuer service chain" in {
    val accessIssuerMap = Map("foo" -> workingService)

    // Allocate and Session
    val sessionId = sessionid.authenticated
    val cooki = sessionId.asCookie()

    // Login POST request
    val request = req("enterprise", "/ent")
    request.addCookie(cooki)

    // Execute
    val output = (SendToAccessIssuer(accessIssuerMap) andThen sessionIdFilterTestService)(
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    // Validate
    val caught = the [BpAccessIssuerError] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal ("BPAUTH: Failed to find AccessIssuer Service Chain for keymaster")
  }

  behavior of "SendToUnprotectedService"

  it should "send request w/ auth SessionId to unprotected upstream service path" in {
    val testService = mkTestService[SessionIdRequest, Response] { _ => fail("Must not invoke this service") }
    val testSidBinder = mkTestSidBinder { req => {
      assert(req.context == checkpointSid)
      Response(Status.Ok).toFuture
    }}

    // Allocate and Session
    val sessionId = sessionid.authenticated

    // Login POST request
    val request = req("enterprise", "/check")

    // Original request
    val output = (SendToUnprotectedService(testSidBinder) andThen testService)(
      SessionIdRequest(request, cust1, Some(checkpointSid), Some(sessionId)))

    //  Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "send request w/ unauth SessionId to unprotected upstream service path" in {
    val testService = mkTestService[SessionIdRequest, Response] { _ => fail("Must not invoke this service") }
    val testSidBinder = mkTestSidBinder { req => {
      assert(req.context == checkpointSid)
      Response(Status.Ok).toFuture
    }}

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = req("enterprise", "/check")

    // Original request
    val output = (SendToUnprotectedService(testSidBinder) andThen testService)(
      SessionIdRequest(request, cust1, Some(checkpointSid), Some(sessionId)))

    //  Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "send request w/ unauth SessionId to unknown path to next service in the chain" in {
    val testSidBinder = mkTestSidBinder { _ => fail("Must not invoke this service binder")}

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = req("enterprise", "unknown")

    // Original request
    val output = (SendToUnprotectedService(testSidBinder) andThen sessionIdFilterTestService)(
      SessionIdRequest(request, cust1, None, Some(sessionId)))

    //  Validate
    Await.result(output).status should be (Status.Ok)
  }

  it should "send request w/ unauth SessionId to protected service to next service in the chain" in {
    val testSidBinder = mkTestSidBinder { _ => fail("Must not invoke this service binder")}

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = req("enterprise", "ent")

    // Original request
    val output = (SendToUnprotectedService(testSidBinder) andThen sessionIdFilterTestService)(
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    //  Validate
    Await.result(output).status should be (Status.Ok)
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
    val output = (ExceptionFilter() andThen CustomerIdFilter(serviceMatcher) andThen LogoutService(sessionStore))(
      request)

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
    val output = (ExceptionFilter() andThen CustomerIdFilter(serviceMatcher) andThen LogoutService(sessionStore))(
      request)

    // Validate
    Await.result(output).status should be (Status.Found)
    Await.result(output).location.get should be (cust1.defaultServiceId.path.toString)
    Await.result(output).cookies.get(SignedId.sessionIdCookieName) should be (None)
  }

  it should "succeed to logout the requests w/o sessionId w/ JSON response to logged out page" in {
    // Create request
    val request = req("sky", "/logout", ("destination", "/abc%0d%0atest:abc%0d%0a"))
    request.accept = Seq("application/json")

    // Execute
    val output = (ExceptionFilter() andThen CustomerIdFilter(serviceMatcher) andThen LogoutService(sessionStore))(
      request)

    // Validate
    Await.result(output).status should be (Status.Ok)
    Await.result(output).contentType should be (Some("application/json"))
    Await.result(output).contentString should include
      (s""""redirect_url" : "/abc"""")
    Await.result(output).cookies.get(SignedId.sessionIdCookieName) should be (None)
  }
}
