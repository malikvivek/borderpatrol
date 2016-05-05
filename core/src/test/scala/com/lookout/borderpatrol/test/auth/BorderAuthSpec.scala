package com.lookout.borderpatrol.test.auth

import com.lookout.borderpatrol.{BpCommunicationError, BpNotFoundRequest}
import com.lookout.borderpatrol.auth._
import com.lookout.borderpatrol.sessionx.SessionStores.MemcachedStore
import com.lookout.borderpatrol.sessionx._
import com.lookout.borderpatrol.test._
import com.twitter.finagle.http._
import com.twitter.finagle.http.service.RoutingService
import com.twitter.finagle.{Service, memcached}
import com.twitter.finagle.memcached.GetResult
import com.twitter.io.Buf
import com.twitter.util.{Await, Future, Time}


class BorderAuthSpec extends BorderPatrolSuite {

  import coreTestHelpers.{secretStore => store, _}

  // Method to decode SessionData from the sessionId
  def getRequestFromSessionId(sid: SignedId): Future[Request] =
    (for {
      sessionMaybe <- sessionStore.get[Request](sid)
    } yield sessionMaybe.fold[Identity[Request]](EmptyIdentity)(s => Id(s.data))).map {
      case Id(req) => req
      case EmptyIdentity => null
    }

  // Method to decode SessionData from the sessionId in Response
  def sessionDataFromResponse(resp: Response): Future[Request] =
    for {
      sessionId <- SignedId.fromResponse(resp).toFuture
      req <- getRequestFromSessionId(sessionId)
    } yield req

  //  Test Services
  val serviceFilterTestService = Service.mk[CustomerIdRequest, Response] { req => Future.value(Response(Status.Ok))}
  val sessionIdFilterTestService = Service.mk[SessionIdRequest, Response] { req => Future.value(Response(Status.Ok))}
  val identityFilterTestService =
    Service.mk[AccessIdRequest[Request], Response] { req => Future.value(Response(Status.Ok))}
  val workingService = Service.mk[BorderRequest, Response] { req => Response(Status.Ok).toFuture}
  val workingMap = Map("test1.type" -> workingService, "test2.type" -> workingService)

  //  Mock SessionStore client
  case object FailingMockClient extends memcached.MockClient {
    override def set(key: String, flags: Int, expiry: Time, value: Buf): Future[Unit] = {
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
    Await.result(output).status should be(Status.Ok)
  }

  it should "return NotFound Status if Request is destined to an unknown Service" in {
    // Execute
    val output = (CustomerIdFilter(serviceMatcher) andThen serviceFilterTestService)(req("foo", "/bar"))

    // Validate
    val caught = the[BpNotFoundRequest] thrownBy {
      Await.result(output)
    }
    caught.status should be(Status.NotFound)
    caught.getMessage should startWith("Not Found: Failed to find CustomerIdentifier for")
  }

  it should "return NotFound Status if Request lacks the hostname " in {
    // Execute
    val output = (CustomerIdFilter(serviceMatcher) andThen serviceFilterTestService)(Request("/bar"))

    // Validate
    val caught = the[BpNotFoundRequest] thrownBy {
      Await.result(output)
    }
    caught.status should be(Status.NotFound)
    caught.getMessage should startWith("Not Found: Failed to find CustomerIdentifier for")
    caught.getMessage should include("null-hostname")
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
    val testService = Service.mk[SessionIdRequest, Response] {
      req => {
        assert(req.serviceIdOpt == Some(one))
        assert(req.sessionIdOpt == Some(sessionId))
        Future.value(Response(Status.Ok))
      }
    }

    //  Execute
    val output = (SessionIdFilter(serviceMatcher, sessionStore) andThen testService)(CustomerIdRequest(request, cust1))

    //  Verify
    Await.result(output).status should be(Status.Ok)
  }

  it should "fail to find ServiceId and succeed to find SessionId, but forward it to upstream Service" in {

    //  Allocate and Session
    val sessionId = sessionid.untagged
    val cooki = sessionId.asCookie()

    //  Create request
    val request = req("enterprise", "/blah")
    request.addCookie(cooki)

    //  test service
    val testService = Service.mk[SessionIdRequest, Response] {
      req => {
        assert(req.serviceIdOpt.isEmpty)
        assert(req.sessionIdOpt == Some(sessionId))
        Future.value(Response(Status.Ok))
      }
    }

    //  Execute
    val output = (SessionIdFilter(serviceMatcher, sessionStore) andThen testService)(CustomerIdRequest(request, cust1))

    //  Verify
    Await.result(output).status should be(Status.Ok)
  }

  it should "fail to find SessionId and succeed to find ServiceId, but forward it to upstream Service" in {

    //  Create request
    val request = req("enterprise", "/ent")

    //  test service
    val testService = Service.mk[SessionIdRequest, Response] {
      req => {
        assert(req.serviceIdOpt == Some(one))
        assert(req.sessionIdOpt.isEmpty)
        Future.value(Response(Status.Ok))
      }
    }

    //  Execute
    val output = (SessionIdFilter(serviceMatcher, sessionStore) andThen testService)(CustomerIdRequest(request, cust1))

    //  Verify
    Await.result(output).status should be(Status.Ok)
  }

  behavior of "IdentityFilter"

  it should "succeed and return output of upstream Service, if Session is found for SignedId" in {
    val testService = Service.mk[AccessIdRequest[Int], Response] {
      request => {
        assert(request.id == Identity(999))
        Future.value(Response(Status.Ok))
      }
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
    Await.result(output).status should be(Status.Ok)
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
    val resp = Await.result(output)
    resp.status should be(Status.Found)
    resp.location.get should be(test1LoginManager.redirectLocation(request))
    val sessionIdZ = SignedId.fromResponse(resp).toOption
    sessionIdZ should not be (None)
    sessionIdZ should not be (Some(sessionId))
    val reqZ = getRequestFromSessionId(sessionIdZ.get)
    Await.result(reqZ).uri should be(request.uri)
  }

  it should "return a Unauthorized response with login URL, if it fails Session lookup using SignedId" in {

    // Allocate and Session
    val sessionId = sessionid.untagged
    val cooki = sessionId.asCookie()

    // Create request
    val request = req("enterprise", "/ent")
    request.addCookie(cooki)
    request.accept = Seq("application/json")

    // Execute
    val output = (IdentityFilter[Request](sessionStore) andThen identityFilterTestService)(
      BorderRequest(request, cust1, one, sessionId))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Unauthorized)
    resp.contentString should include( s""""redirect_url" : "${test1LoginManager.redirectLocation(request)}"""")
    val sessionIdZ = SignedId.fromResponse(resp).toOption
    sessionIdZ should not be (None)
    sessionIdZ should not be (Some(sessionId))
    val reqZ = getRequestFromSessionId(sessionIdZ.get)
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
    val caught = the[Exception] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal("oopsie")
  }

  it should "propagate the Exception thrown by SessionStore.update operation" in {
    //  Mock SessionStore client
    case object FailingUpdateMockClient extends memcached.MockClient {
      override def set(key: String, flags: Int, expiry: Time, value: Buf): Future[Unit] = {
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
    val caught = the[Exception] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal("whoopsie")
  }

  behavior of "ExceptionFilter"

  it should "succeed and act as a passthru for the valid Response returned by Service" in {
    val testService = Service.mk[Request, Response] { req => Future.value(Response(Status.Ok))}

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be(Status.Ok)
  }

  it should "succeed and convert the BpUnauthorizedRequest exception into error Response" in {
    val testService = Service.mk[Request, Response] { req =>
      Future.exception(BpUnauthorizedRequest("some unauthorized error"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be(Status.Unauthorized)
    Await.result(output).contentType should be(Some("text/plain"))
    Await.result(output).contentString should be("Oops, something went wrong, please try your action again")
  }

  it should "succeed and convert the BpSessionStoreError exception into error Response" in {
    val testService = Service.mk[Request, Response] { req =>
      Future.exception(new BpSessionStoreError("update failed"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be(Status.InternalServerError)
    Await.result(output).contentString should be("Oops, something went wrong, please try your action again")
  }

  it should "succeed and convert the BpAccessIssuerError exception into JSON error Response" in {
    val testService = Service.mk[Request, Response] { req =>
      throw BpIdentityProviderError("Some access issuer error")
    }

    // Login POST request
    val request = req("enterprise", cust1.loginManager.loginConfirm.toString)
    request.accept = Seq("application/json")

    // Execute
    val output = (ExceptionFilter() andThen testService)(request)

    // Validate
    Await.result(output).status should be(Status.InternalServerError)
    Await.result(output).contentType should be(Some("application/json"))
    Await.result(output).contentString should include("Oops, something went wrong, please try your action again")

  }

  it should "succeed and convert the BpIdentityProviderError exception into error Response" in {
    val testService = Service.mk[Request, Response] { req =>
      Future.exception(BpIdentityProviderError("Some identity provider error"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be(Status.InternalServerError)
  }

  it should "succeed and convert the BpCommunicationError exception into error Response" in {
    val testService = Service.mk[Request, Response] { req =>
      Future.exception(BpCommunicationError("Some identity provider error"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be(Status.InternalServerError)
  }

  it should "succeed and convert the BpNotFoundRequest exception into error Response" in {
    val testService = Service.mk[Request, Response] { req =>
      Future.exception(BpNotFoundRequest("Some identity provider error"))
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be(Status.NotFound)
  }

  it should "succeed and convert the Runtime exception into error Response" in {
    val testService = Service.mk[Request, Response] { req =>
      throw new RuntimeException("some weird exception")
    }

    // Execute
    val output = (ExceptionFilter() andThen testService)(req("enterprise", "/ent"))

    // Validate
    Await.result(output).status should be(Status.InternalServerError)
  }

  behavior of "SendToIdentityProvider"

  it should "send a request for unauth SessionId to loginConfirm path to IdentityService chain" in {
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = reqPost("enterprise", cust1.loginManager.loginConfirm.toString, Buf.Empty)

    // Original request
    val output = (SendToIdentityProvider(workingMap, sessionStore) andThen testService)(
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    //  Validate
    Await.result(output).status should be(Status.Ok)
  }

  it should "send a request w/o SessionId to loginConfirm path to IdentityService chain" in {
    val identityProvider = Service.mk[BorderRequest, Response] { req =>
      val storedReq = Await.result(sessionStore.get[Request](req.sessionId)).get.data
      storedReq.path should be(cust1.defaultServiceId.path.toString)
      Response(Status.Ok).toFuture
    }
    val identityProviderMap = Map("test1.type" -> identityProvider)
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}

    // Login POST request
    val request = reqPost("enterprise", cust1.loginManager.loginConfirm.toString, Buf.Empty)

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService)(
      SessionIdRequest(request, cust1, Some(one), None))

    //  Validate
    Await.result(output).status should be(Status.Ok)
  }

  it should "send a request w/o SessionId w/ destination to loginConfirm path to IdentityService chain" in {
    val identityProvider = Service.mk[BorderRequest, Response] { req =>
      val storedReq = Await.result(sessionStore.get[Request](req.sessionId)).get.data
      storedReq.path should be("blah")
      Response(Status.Ok).toFuture
    }
    val identityProviderMap = Map("test1.type" -> identityProvider)
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}

    // Login POST request
    val request = reqPost("enterprise", cust1.loginManager.loginConfirm.toString, Buf.Empty,
      ("destination" -> "blah"))

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService)(
      SessionIdRequest(request, cust1, Some(one), None))

    //  Validate
    Await.result(output).status should be(Status.Ok)
  }

  it should "send the request w/ authenticated SessionId to follow-on service" in {
    val identityProvider = Service.mk[BorderRequest, Response] { _ => fail("Must not invoke identity service")}
    val identityProviderMap = Map("tokenmaster.basic" -> identityProvider)
    val testService = Service.mk[SessionIdRequest, Response] { _ =>
      Response(Status.NotAcceptable).toFuture
    }

    // Allocate and Session
    val sessionId = sessionid.authenticated
    val cooki = sessionId.asCookie()

    // Login POST request
    val request = reqPost("enterprise", cust1.loginManager.loginConfirm.toString, Buf.Empty)
    request.addCookie(cooki)

    // Execute
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService)(
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    // Validate
    Await.result(output).status should be(Status.NotAcceptable)
  }

  it should "redirect the request w/ unauth SessionId for protected service to login page" in {
    val identityProvider = Service.mk[BorderRequest, Response] { _ => fail("Must not invoke identity service")}
    val identityProviderMap = Map("tokenmaster.basic" -> identityProvider)
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login request
    val request = req("enterprise", "ent")

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService)(
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Found)
    resp.location.get should be(test1LoginManager.redirectLocation(request))
    val sessionIdZ = SignedId.fromResponse(resp).get
    sessionIdZ should be(sessionId)
  }

  it should "respond to the request w/ unauth SessionId for protected service with json response" in {
    val identityProvider = Service.mk[BorderRequest, Response] { _ => fail("Must not invoke identity service")}
    val identityProviderMap = Map("tokenmaster.basic" -> identityProvider)
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login request
    val request = req("enterprise", "ent")
    request.accept = Seq("application/json")

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService)(
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Unauthorized)
    resp.contentType.get should include("application/json")
    resp.contentString should include( s""""redirect_url" : "${test1LoginManager.redirectLocation(request)}"""")
    val sessionIdZ = SignedId.fromResponse(resp).get
    sessionIdZ should be(sessionId)
  }

  it should "redirect the request w/ unauth SessionId for protected service to login page for test2" in {
    val identityProvider = Service.mk[BorderRequest, Response] { _ => fail("Must not invoke identity service")}
    val identityProviderMap = Map("test2.type" -> identityProvider)
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login request
    val request = req("sky", "umb")
    request.headerMap.add("X-Forwarded-Proto", "https")

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService)(
      SessionIdRequest(request, cust2, Some(two), Some(sessionId)))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Found)
    resp.location.get should be(test2LoginManager.redirectLocation(request))
    val sessionIdZ = SignedId.fromResponse(resp).get
    sessionIdZ should be(sessionId)
  }

  it should "redirect the request w/ unauth SessionId to unprotected service to follow-on service" in {
    val identityProvider = Service.mk[BorderRequest, Response] { _ => fail("Must not invoke identity service")}
    val identityProviderMap = Map("tokenmaster.basic" -> identityProvider)
    val testService = Service.mk[SessionIdRequest, Response] { _ => Response(Status.NotAcceptable).toFuture}

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login request
    val request = req("enterprise", "check")

    // Execute
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService)(
      SessionIdRequest(request, cust1, Some(unproCheckpointSid), Some(sessionId)))

    // Validate
    Await.result(output).status should be(Status.NotAcceptable)
  }

  it should "redirect the request w/ unauth SessionId to unknown path to login page" in {
    val identityProvider = Service.mk[BorderRequest, Response] { _ => fail("Must not invoke identity service")}
    val identityProviderMap = Map("tokenmaster.basic" -> identityProvider)
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login request
    val request = req("enterprise", "unknown")

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService)(
      SessionIdRequest(request, cust1, None, Some(sessionId)))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Found)
    resp.location.get should be(test1LoginManager.redirectLocation(request))
    val sessionIdZ = SignedId.fromResponse(resp).get
    sessionIdZ should be(sessionId)
  }

  it should "redirect the request w/o SessionId for protected service to login page" in {
    val identityProvider = Service.mk[BorderRequest, Response] { _ => fail("Must not invoke identity service")}
    val identityProviderMap = Map("tokenmaster.basic" -> identityProvider)
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}

    // Login request
    val request = req("enterprise", "ent")

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService)(
      SessionIdRequest(request, cust1, Some(one), None))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Found)
    resp.location.get should be(test1LoginManager.redirectLocation(request))
    val sessionIdZ = SignedId.fromResponse(resp).toOption
    sessionIdZ should not be (None)
    val reqZ = getRequestFromSessionId(sessionIdZ.get)
    Await.result(reqZ).uri should be(request.uri)
  }

  it should "redirect the request w/o SessionId for unprotected service to follow-on service" in {
    val identityProvider = Service.mk[BorderRequest, Response] { _ => fail("Must not invoke identity service")}
    val identityProviderMap = Map("tokenmaster.basic" -> identityProvider)
    val testService = Service.mk[SessionIdRequest, Response] { _ => Response(Status.NotAcceptable).toFuture}

    // Login request
    val request = req("enterprise", "check")

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService)(
      SessionIdRequest(request, cust1, Some(unproCheckpointSid), None))

    // Validate
    Await.result(output).status should be(Status.NotAcceptable)
  }

  it should "redirect the request w/o SessionId for unknown service to login page" in {
    val identityProvider = Service.mk[BorderRequest, Response] { _ => fail("Must not invoke identity service")}
    val identityProviderMap = Map("tokenmaster.basic" -> identityProvider)
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}

    // Login request
    val request = req("enterprise", "unknown")

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen testService)(
      SessionIdRequest(request, cust1, None, None))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Found)
    resp.location.get should be(test1LoginManager.redirectLocation(request))
    val sessionIdZ = SignedId.fromResponse(resp).toOption
    sessionIdZ should not be (None)
    val reqZ = getRequestFromSessionId(sessionIdZ.get)
    Await.result(reqZ).uri should be(request.uri)
  }

  it should "throw a BpIdentityProviderError if it fails to find IdentityProvider service chain" in {
    val identityProviderMap = Map("foo" -> workingService)

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = reqPost("enterprise", cust1.loginManager.loginConfirm.toString, Buf.Empty)

    // Execute
    val output = (SendToIdentityProvider(identityProviderMap, sessionStore) andThen sessionIdFilterTestService)(
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    // Validate
    val caught = the[BpIdentityProviderError] thrownBy {
      Await.result(output)
    }
    caught.getMessage should include(
      "Failed to find IdentityProvider Service Chain for loginManager type: test1.type")
  }

  it should "propagate the Exception thrown while storing the Session using SessionStore.update" in {
    val identityProvider = Service.mk[BorderRequest, Response] { _ => fail("Must not invoke identity service")}
    val identityProviderMap = Map("tokenmaster.basic" -> identityProvider)
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}

    // Mock sessionStore
    val mockSessionStore = MemcachedStore(FailingMockClient)

    // Create request
    val request = reqPost("enterprise", cust1.loginManager.loginConfirm.toString, Buf.Empty)

    // Original request
    val output = (SendToIdentityProvider(identityProviderMap, mockSessionStore) andThen testService)(
      SessionIdRequest(request, cust1, Some(one), None))

    // Verify
    val caught = the[Exception] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal("oopsie")
  }

  behavior of "SendToAccessIssuer"

  it should "send the request to AccessIssuer chain if session is authenticated and trying to reach a valid service" in {
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}

    //  Allocate and Session
    val sessionId = sessionid.authenticated

    //  Create request
    val request = req("enterprise", "ent")

    //  Execute
    val output = (SendToAccessIssuer(workingMap) andThen testService)(
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    //  Verify
    Await.result(output).status should be(Status.Ok)
  }

  it should "redirect to default serviceId if session is authenticated and trying to reach Root path" in {
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}

    //  Allocate and Session
    val sessionId = sessionid.authenticated

    //  Create request
    val request = req("enterprise", "")

    //  Execute
    val output = (SendToAccessIssuer(workingMap) andThen testService)(
      SessionIdRequest(request, cust1, None, Some(sessionId)))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Found)
    resp.location.get should be(one.path.toString)
  }

  it should "forward to next service if session is authenticated but trying to reach unknown path" in {
    val testService = Service.mk[SessionIdRequest, Response] { _ =>
      Response(Status.NotFound).toFuture
    }

    //  Allocate and Session
    val sessionId = sessionid.authenticated

    //  Create request
    val request = req("enterprise", "/unknown")

    //  Execute
    val output = (SendToAccessIssuer(workingMap) andThen testService)(
      SessionIdRequest(request, cust1, None, Some(sessionId)))

    //  Verify
    Await.result(output).status should be(Status.NotFound)
  }

  it should "throw a BpAccessIssuerError if it fails to find AccessIssuer service chain" in {
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
    val caught = the[BpAccessIssuerError] thrownBy {
      Await.result(output)
    }
    caught.getMessage should include("Failed to find AccessIssuer Service Chain for loginManager type: test1.type")
  }

  behavior of "SendToUnprotectedService"

  it should "send request w/ auth SessionId to unprotected upstream service path" in {
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains unproCheckpointSid.path.toString => Service.mk[Request, Response] { req =>
          Response(Status.Ok).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {
      // Allocate and Session
      val sessionId = sessionid.authenticated

      // Login POST request
      val request = req("enterprise", "/check")

      // Original request
      val output = (SendToUnprotectedService(sessionStore) andThen testService)(
        SessionIdRequest(request, cust1, Some(unproCheckpointSid), Some(sessionId)))

      //  Validate
      Await.result(output).status should be(Status.Ok)
    } finally {
      server.close()
    }
  }

  it should "send request w/ untagged SessionId to unprotected upstream service path" in {
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains unproCheckpointSid.path.toString => Service.mk[Request, Response] { req =>
          Response(Status.Ok).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {
      // Allocate and Session
      val sessionId = sessionid.untagged

      // Login POST request
      val request = req("enterprise", "/check")

      // Original request
      val output = (SendToUnprotectedService(sessionStore) andThen testService)(
        SessionIdRequest(request, cust1, Some(unproCheckpointSid), Some(sessionId)))

      //  Validate
      Await.result(output).status should be(Status.Ok)
    } finally {
      server.close()
    }
  }

  it should "send request w/ untagged SessionId to unknown path to follow-on service" in {
    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = req("enterprise", "unknown")

    // Original request
    val output = (SendToUnprotectedService(sessionStore) andThen sessionIdFilterTestService)(
      SessionIdRequest(request, cust1, None, Some(sessionId)))

    //  Validate
    Await.result(output).status should be(Status.Ok)
  }

  it should "send request w/ untagged SessionId to protected service to follow-on service" in {
    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val request = req("enterprise", "ent")

    // Original request
    val output = (SendToUnprotectedService(sessionStore) andThen sessionIdFilterTestService)(
      SessionIdRequest(request, cust1, Some(one), Some(sessionId)))

    //  Validate
    Await.result(output).status should be(Status.Ok)
  }

  it should "send request w/o SessionId to unprotected upstream service path" in {
    val testService = Service.mk[SessionIdRequest, Response] { _ => fail("Must not invoke this service")}
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains unproCheckpointSid.path.toString => Service.mk[Request, Response] { req =>
          Response(Status.Ok).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {
      // Login POST request
      val request = req("enterprise", "/check")

      // Original request
      val output = (SendToUnprotectedService(sessionStore) andThen testService)(
        SessionIdRequest(request, cust1, Some(unproCheckpointSid), None))

      //  Validate
      Await.result(output).status should be(Status.Ok)
      SignedId.fromResponse(Await.result(output)).isSuccess should be(true)
      val reqZ = sessionDataFromResponse(Await.result(output))
      Await.result(reqZ).uri should be(cust1.defaultServiceId.path.toString)
    } finally {
      server.close()
    }
  }

  behavior of "AccessFilter"

  case class TestAccessResponse(access: Access[String]) extends AccessResponse[String]

  it should "succeed and include service token in the request and invoke the REST API of upstream service" in {
    val accessService = Service.mk[AccessRequest[Int], AccessResponse[String]] {
      request => TestAccessResponse (Access("blah")).toFuture
    }
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains one.path.toString => Service.mk[Request, Response] { req =>
          assert(req.uri == one.path.toString)
          assert(req.headerMap.get("Auth-Token") == Some("blah"))
          Response(Status.Ok).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {

      // Allocate and Session
      val sessionId = sessionid.authenticated

      // Create request
      val request = req("enterprise", "/ent")

      // Execute
      val output = (AccessFilter[Int, String] andThen accessService)(
        AccessIdRequest(request, cust1, one, sessionId, Id(10)))

      // Validate
      Await.result(output).status should be(Status.Ok)
    } finally {
      server.close()
    }
  }

  behavior of "RewriteFilter"

  it should "succeed and include service token in the request and invoke the REST API of upstream service" in {
    val testService = Service.mk[BorderRequest, Response] {
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
    val testService = Service.mk[BorderRequest, Response] {
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
    Await.result(output).contentType.get should include("application/json")
    Await.result(output).contentString should include(s""""redirect_url" : "/abc%0d%0atest:abc%0d%0a"""")
    Await.result(output).cookies.get(SignedId.sessionIdCookieName) should be (None)
  }
}
