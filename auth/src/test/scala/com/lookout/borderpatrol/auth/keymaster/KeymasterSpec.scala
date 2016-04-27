package com.lookout.borderpatrol.auth.keymaster

import com.lookout.borderpatrol.Binder
import com.lookout.borderpatrol.auth.keymaster.Keymaster._
import com.lookout.borderpatrol.auth._
import com.lookout.borderpatrol.errors.{BpBadRequest, BpForbiddenRequest}
import com.lookout.borderpatrol.sessionx.SessionStores.MemcachedStore
import com.lookout.borderpatrol.sessionx._
import com.lookout.borderpatrol.test._
import com.lookout.borderpatrol.util.Combinators.tap
import com.nimbusds.jwt.{PlainJWT, JWTClaimsSet}
import com.twitter.finagle.http.service.RoutingService
import com.twitter.finagle.memcached.GetResult
import com.twitter.finagle.{Service, memcached}
import com.twitter.finagle.http._
import com.twitter.util.{Await, Future}

import org.scalatest.mock.MockitoSugar
import org.mockito.Mockito._


class KeymasterSpec extends BorderPatrolSuite with MockitoSugar {
  import coreTestHelpers.{secretStore => store, _}
  import keymasterTestHelpers._
  import Tokens._
  import OAuth2._

  override def afterEach(): Unit = {
    try {
      super.afterEach() // To be stackable, must call super.afterEach
    }
    finally {
      Binder.clear
    }
  }

  //  Tokens
  val serviceToken2 = ServiceToken("SomeServiceTokenData2")
  val serviceTokens = ServiceTokens().add("service1", ServiceToken("SomeServiceTokenData1"))
  val tokens = Tokens(MasterToken("masterT"), serviceTokens)
  val tokens2 = tokens.add("one", serviceToken2)

  // Method to decode SessionData from the sessionId
  def getTokensFromSessionId(sid: SignedId): Future[Tokens] =
    (for {
      sessionMaybe <- sessionStore.get[Tokens](sid)
    } yield sessionMaybe.fold[Identity[Tokens]](EmptyIdentity)(s => Id(s.data))).map(i => i match {
      case Id(tokens) => tokens
      case EmptyIdentity => null
    })

  val keymasterLoginFilterTestService = Service.mk[IdentifyRequest[Credential], IdentifyResponse[Tokens]] {
    req => Future(KeymasterIdentifyRes(tokens)) }

  behavior of "KeymasterIdentityProvider"

  it should "succeed and return IdentityResponse with tokens received from upstream Keymaster Service" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains keymasterIdEndpoint.path.toString => Service.mk[Request, Response] { req =>
          assert(req.path == cust1k.loginManager.identityEndpoint.path.toString)
          tap(Response(Status.Ok))(res => {
            res.contentString = TokensEncoder(tokens).toString()
            res.contentType = "application/json"
          }).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {
      // Allocate and Session
      val sessionId = sessionid.untagged

      // Login POST request
      val loginRequest = req("umbrella.k", "/loginConfirm", "username" -> "foo", "password" -> "bar")

      //  Request
      val sessionIdRequest = BorderRequest(loginRequest, cust1k, one, sessionId)

      // Execute
      val output = KeymasterIdentityProvider().apply(
        KeymasterIdentifyReq(sessionIdRequest, InternalAuthCredential("foo", "bar", cust1k, one)))

      // Validate
      Await.result(output).identity should be(Id(tokens))
    } finally {
      server.close()
    }
  }

  it should "throw BpForbiddenRequest if Keymaster returns the Forbidden Status code" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains keymasterIdEndpoint.path.toString => Service.mk[Request, Response] { req =>
          Response(Status.Forbidden).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {
      // Allocate and Session
      val sessionId = sessionid.untagged

      // Login POST request
      val loginRequest = req("sky.k", "/signin", ("code" -> "XYZ123"))

      //  Request
      val sessionIdRequest = BorderRequest(loginRequest, cust2k, two, sessionId)

      // Execute
      val output = KeymasterIdentityProvider().apply(
        KeymasterIdentifyReq(sessionIdRequest, OAuth2CodeCredential("foo", "bar", cust2k, two)))

      // Validate
      val caught = the[BpForbiddenRequest] thrownBy {
        Await.result(output)
      }
      caught.getMessage should include("Failed to authenticate user")
      caught.status should be(Status.Forbidden)
    } finally {
      server.close()
    }
  }

  it should "propagate the error status from Keymaster service in the BpIdentityProviderError exception" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains keymasterIdEndpoint.path.toString => Service.mk[Request, Response] { req =>
          Response(Status.NotAcceptable).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {
      // Allocate and Session
      val sessionId = sessionid.untagged

      // Login POST request
      val loginRequest = req("sky.k", "/signin", ("code" -> "XYZ123"))

      //  Request
      val sessionIdRequest = BorderRequest(loginRequest, cust2k, two, sessionId)

      // Execute
      val output = KeymasterIdentityProvider().apply(
        KeymasterIdentifyReq(sessionIdRequest, OAuth2CodeCredential("foo", "bar", cust2k, two)))

      // Validate
      val caught = the[BpIdentityProviderError] thrownBy {
        Await.result(output)
      }
      caught.getMessage should include("Failed to authenticate user, with status: ")
      caught.status should be(Status.InternalServerError)
    } finally {
      server.close()
    }
  }

  it should "propagate the failure parsing the resp from Keymaster service as an BpTokenParsingError exception" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains keymasterIdEndpoint.path.toString => Service.mk[Request, Response] { req =>
          tap(Response(Status.Ok))(res => {
            res.contentString = """{"key":"data"}"""
            res.contentType = "application/json"
          }).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {
      // Allocate and Session
      val sessionId = sessionid.untagged

      // Login POST request
      val loginRequest = req("umbrella.k", "/loginConfirm", "username" -> "foo", "password" -> "bar")

      //  Request
      val sessionIdRequest = BorderRequest(loginRequest, cust1k, one, sessionId)

      // Execute
      val output = KeymasterIdentityProvider().apply(
        KeymasterIdentifyReq(sessionIdRequest, InternalAuthCredential("foo", "bar", cust1k, one)))

      // Validate
      val caught = the[BpTokenParsingError] thrownBy {
        Await.result(output)
      }
      caught.getMessage should include("Failed to parse token with: ")
    } finally {
      server.close()
    }
  }

  behavior of "KeymasterTransformFilter"

  it should "succeed and transform the username and password to Keymaster Credential" in {
    val testService = Service.mk[KeymasterIdentifyReq, Response] {
      req =>
        assert(req.credential.serviceId == one)
        assert(req.serviceId == one)
        req.credential match {
          case a: InternalAuthCredential => assert(a.uniqueId == "test@example.com")
          case _ => assert(false)
        }
        Future(Response(Status.Ok))
    }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("umbrella.k", "/loginConfirm", ("username" -> "test@example.com"), ("password" -> "bar"))

    // Execute
    val output = (KeymasterTransformFilter(oAuth2CodeVerify) andThen testService)(
      BorderRequest(loginRequest, cust1k, one, sessionId))

    // Validate
    Await.result(output).status should be(Status.Ok)
  }

  it should "succeed and transform the oAuth2 code to Keymaster Credential" in {
    val testService = Service.mk[KeymasterIdentifyReq, Response] {
      req =>
        assert(req.credential.serviceId == two)
        assert(req.serviceId == two)
        req.credential match {
          case a: OAuth2CodeCredential => assert(a.uniqueId == "test@example.com")
          case _ => assert(false)
        }
        Future(Response(Status.Ok))
    }

    val idToken = new PlainJWT(new JWTClaimsSet.Builder().subject("SomeIdToken")
      .claim("upn", "test@example.com").build)

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("sky.k", "/signin", ("code" -> "XYZ123"))

    //  Request
    val sessionIdRequest = BorderRequest(loginRequest, cust2k, two, sessionId)

    // Mock the oAuth2 verifier
    val mockVerify = mock[OAuth2CodeVerify]
    when(mockVerify.codeToClaimsSet(sessionIdRequest, umbrellaLoginManager)).thenReturn(
      Future(idToken.getJWTClaimsSet))

    // Execute
    val output = (KeymasterTransformFilter(mockVerify) andThen testService)(sessionIdRequest)

    // Validate
    Await.result(output).status should be(Status.Ok)
  }

  it should "return BpBadRequest Status if username or password is not present in the Request" in {
    val testService = Service.mk[KeymasterIdentifyReq, Response] { request => Future(Response(Status.Ok)) }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("umbrella.k", "/login", ("username" -> "foo"))

    // Execute
    val output = (KeymasterTransformFilter(oAuth2CodeVerify) andThen testService)(
      BorderRequest(loginRequest, cust1k, one, sessionId))

    // Validate
    val caught = the [BpBadRequest] thrownBy {
      Await.result(output)
    }
    caught.getMessage should include ("Failed to find username and/or password in the Request")
  }

  behavior of "KeymasterPostLoginFilter"

  it should "succeed and saves tokens for internal auth, sends redirect with tokens returned by keymaster IDP" in {
    val testService = Service.mk[IdentifyRequest[Credential], IdentifyResponse[Tokens]] {
      request =>
        assert(request.credential.uniqueId == "test@example.com")
        Future(KeymasterIdentifyRes(tokens))
    }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("umbrella.k", "/login")

    // Original request
    val origReq = req("umbrella.k", "/dang", ("fake" -> "drake"))
    sessionStore.update[Request](Session(sessionId, origReq))

    // Credential
    val credential = InternalAuthCredential("test@example.com", "password", cust1k, one)

    // Execute
    val output = (KeymasterPostLoginFilter(sessionStore) andThen testService)(
      KeymasterIdentifyReq(BorderRequest(loginRequest, cust1k, one, sessionId), credential))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Found)
    resp.location.get should startWith("/dang")
    val sessionIdZ = SignedId.fromResponse(resp).get
    sessionIdZ should not be(None)
    sessionIdZ should not be(Some(sessionId))
    val tokensz = getTokensFromSessionId(sessionIdZ)
    Await.result(tokensz) should be(tokens)
  }

  it should "succeed and saves tokens for AAD auth, sends redirect with tokens returned by keymaster IDP" in {
    val testService = Service.mk[IdentifyRequest[Credential], IdentifyResponse[Tokens]] {
      request =>
        assert(request.credential.uniqueId == "test@example.com")
        Future.value(KeymasterIdentifyRes(tokens))
    }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("sky.k", "/signin", ("code" -> "XYZ123"))

    // Original request
    val origReq = req("sky.k", "/umb", ("fake" -> "drake"))
    sessionStore.update[Request](Session(sessionId, origReq))

    // Credential
    val credential = OAuth2CodeCredential("test@example.com", "password", cust2k, two)

    // Execute
    val output = (KeymasterPostLoginFilter(sessionStore) andThen testService)(
      KeymasterIdentifyReq(BorderRequest(loginRequest, cust2k, two, sessionId), credential))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Found)
    resp.location.get should startWith("/umb")
    val sessionIdZ = SignedId.fromResponse(resp).get
    sessionIdZ should not be(None)
    sessionIdZ should not be(Some(sessionId))
    val tokensz = getTokensFromSessionId(sessionIdZ)
    Await.result(tokensz) should be(tokens)
  }

  it should "succeed and saves tokens for internal auth, sends json response for redirect" in {
    val testService = Service.mk[IdentifyRequest[Credential], IdentifyResponse[Tokens]] {
      request =>
        assert(request.credential.uniqueId == "test@example.com")
        Future(KeymasterIdentifyRes(tokens))
    }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("umbrella.k", "/login")
    loginRequest.accept = Seq("application/json")

    // Original request
    val origReq = req("umbrella.k", "/dang", ("fake" -> "drake"))
    sessionStore.update[Request](Session(sessionId, origReq))

    // Credential
    val credential = InternalAuthCredential("test@example.com", "password", cust1k, one)

    // Execute
    val output = (KeymasterPostLoginFilter(sessionStore) andThen testService)(
      KeymasterIdentifyReq(BorderRequest(loginRequest, cust1k, one, sessionId), credential))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Ok)
    resp.contentType.get should include("application/json")
    resp.contentString should include (""""redirect_url" : "/dang?fake=drake"""")
    val sessionIdZ = SignedId.fromResponse(resp).get
    sessionIdZ should not be(None)
    sessionIdZ should not be(Some(sessionId))
    val tokensz = getTokensFromSessionId(sessionIdZ)
    Await.result(tokensz) should be(tokens)
  }

  it should "return BpOriginalRequestNotFound if it fails find the original request from sessionStore" in {
    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("umbrella.k", "/login", ("username" -> "foo"), ("password" -> "bar"))

    // Credential
    val credential = InternalAuthCredential("test@example.com", "password", cust1k, one)

    // Execute
    val output = (KeymasterPostLoginFilter(sessionStore) andThen keymasterLoginFilterTestService)(
      KeymasterIdentifyReq(BorderRequest(loginRequest, cust1k, one, sessionId), credential))

    // Validate
    val caught = the [BpOriginalRequestNotFound] thrownBy {
      Await.result(output)
    }
  }

  it should "propagate the Exception thrown by Session lookup operation" in {
    //  Mock SessionStore client
    case object FailingMockClient extends memcached.MockClient {
      override def getResult(keys: Iterable[String]): Future[GetResult] = {
        Future.exception(new Exception("oopsie"))
      }
    }

    // Mock sessionStore
    val mockSessionStore = MemcachedStore(FailingMockClient)

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("umbrella.k", "/login", ("username" -> "foo"), ("password" -> "bar"))

    // Credential
    val credential = InternalAuthCredential("test@example.com", "password", cust1k, one)

    // Execute
    val output = (KeymasterPostLoginFilter(mockSessionStore) andThen keymasterLoginFilterTestService)(
      KeymasterIdentifyReq(BorderRequest(loginRequest, cust1k, one, sessionId), credential))

    // Validate
    val caught = the [Exception] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal ("oopsie")
  }

  behavior of "KeymasterAccessIssuer"

  it should "succeed, return service token found in the ServiceTokens cache" in {
    val sessionId = sessionid.untagged

    // Execute
    val output = KeymasterAccessIssuer(sessionStore).apply(
      KeymasterAccessReq(Id(tokens2), cust1k, one, sessionId))

    // Validate
    Await.result(output).access.access should be (serviceToken2)
  }

  it should "succeed, save in SessionStore and return the ServiceToken received from the Keymaster Service" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains keymasterAccessEndpoint.path.toString => Service.mk[Request, Response] { req =>
          assert(req.path == cust1k.loginManager.accessEndpoint.path.toString)
          tap(Response(Status.Ok))(res => {
            res.contentString = TokensEncoder(tokens2).toString()
            res.contentType = "application/json"
          }).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {
      val sessionId = sessionid.untagged
      sessionStore.update[Tokens](Session(sessionId, tokens))

      // Execute
      val output = KeymasterAccessIssuer(sessionStore).apply(
        KeymasterAccessReq(Id(tokens), cust1k, one, sessionId))

      // Validate
      Await.result(output).access.access should be(serviceToken2)
      val tokIt = getTokensFromSessionId(sessionId)
      Await.result(tokIt) should be(tokens2)
    } finally {
      server.close()
    }
  }

  it should "propagate the error Status code returned by the Keymaster service, as the BpAccessIssuerError exception" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains keymasterAccessEndpoint.path.toString => Service.mk[Request, Response] { req =>
          Response(Status.NotFound).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {
      val sessionId = sessionid.untagged

      // Execute
      val output = KeymasterAccessIssuer(sessionStore).apply(
        KeymasterAccessReq(Id(tokens), cust1k, one, sessionId))

      // Validate
      val caught = the[BpAccessIssuerError] thrownBy {
        Await.result(output)
      }
      caught.getMessage should include("Failed to permit access to the service: 'one', with: ")
      caught.getMessage should include(s"${Status.NotFound.code}")
      caught.status should be(Status.InternalServerError)
    } finally {
      server.close()
    }
  }

  it should "propagate the failure to parse resp content from Keymaster service, as BpAccessIssuerError exception" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains keymasterAccessEndpoint.path.toString => Service.mk[Request, Response] { req =>
          tap(Response(Status.Ok))(res => {
            res.contentString = "invalid string"
            res.contentType = "application/json"
          }).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {
      val sessionId = sessionid.untagged

      // Execute
      val output = KeymasterAccessIssuer(sessionStore).apply(
        KeymasterAccessReq(Id(tokens), cust1k, one, sessionId))

      // Validate
      val caught = the[BpTokenParsingError] thrownBy {
        Await.result(output)
      }
      caught.getMessage should include("Failed to parse token with: in Keymaster Access Response")
    } finally {
      server.close()
    }
  }

  it should "throw a BpForbiddenRequest when it fails to find the ServiceToken in the Keymaster response" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains keymasterAccessEndpoint.path.toString => Service.mk[Request, Response] { req =>
          tap(Response(Status.Ok))(res => {
            res.contentString = TokensEncoder(tokens).toString()
            res.contentType = "application/json"
          }).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {
      val sessionId = sessionid.untagged

      // Execute
      val output = KeymasterAccessIssuer(sessionStore).apply(
        KeymasterAccessReq(Id(tokens), cust1k, one, sessionId))

      // Validate
      val caught = the[BpForbiddenRequest] thrownBy {
        Await.result(output)
      }
      caught.getMessage should be("Forbidden: Failed to permit access to the service: 'one'")
      caught.status should be(Status.Forbidden)
    } finally {
      server.close()
    }
  }

  behavior of "AccessFilter"

  it should "succeed and include service token in the request and invoke the REST API of upstream service" in {
    val accessService = Service.mk[AccessRequest[Tokens], AccessResponse[ServiceToken]] {
      request => KeymasterAccessRes(Access(serviceToken2)).toFuture
    }
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains one.path.toString => Service.mk[Request, Response] { req =>
          assert(req.headerMap.get("Auth-Token") == Some(serviceToken2.value))
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
      val request = req("umbrella.k", "/ent")

      // Execute
      val output = (AccessFilter[Tokens, ServiceToken] andThen accessService)(
        AccessIdRequest(request, cust1k, one, sessionId, Id(tokens)))

      // Validate
      Await.result(output).status should be(Status.Ok)
    } finally {
      server.close()
    }
  }

  it should "propagate the failure status code returned by upstream service" in {
    val accessService = Service.mk[AccessRequest[Tokens], AccessResponse[ServiceToken]] {
      _ => KeymasterAccessRes(Access(serviceToken2)).toFuture
    }
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains one.path.toString => Service.mk[Request, Response] { req =>
          assert(req.headerMap.get("Auth-Token") == Some(serviceToken2.value))
          Response(Status.NotFound).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {
      // Allocate and Session
      val sessionId = sessionid.authenticated

      // Create request
      val request = req("umbrella.k", "/ent/whatever")

      // Execute
      val output = (AccessFilter[Tokens, ServiceToken] andThen accessService)(
        AccessIdRequest(request, cust1k, one, sessionId, Id(tokens)))

      // Validate
      Await.result(output).status should be(Status.NotFound)
    } finally {
      server.close()
    }
  }

  it should "propagate the exception returned by Access Issuer Service" in {
    val accessService = Service.mk[AccessRequest[Tokens], AccessResponse[ServiceToken]] {
      request => Future.exception(new Exception("Oopsie"))
    }
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains one.path.toString => Service.mk[Request, Response] { req =>
          tap(Response(Status.Ok))(res => {
            res.contentString = TokensEncoder(tokens).toString()
            res.contentType = "application/json"
          }).toFuture
        }
        case _ =>
          fail("must not get here")
      }
    )
    try {

      // Allocate and Session
      val sessionId = sessionid.authenticated

      // Create request
      val request = req("umbrella.k", "/ent/something")

      // Execute
      val output = (AccessFilter[Tokens, ServiceToken] andThen accessService)(
        AccessIdRequest(request, cust1k, one, sessionId, Id(tokens)))

      // Validate
      val caught = the[Exception] thrownBy {
        Await.result(output)
      }
    } finally {
      server.close()
    }
  }

  behavior of "keymasterIdentityProviderChain"

  it should "succeed and invoke the GET on identityManager" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains keymasterIdEndpoint.path.toString => Service.mk[Request, Response] { req =>
          tap(Response(Status.Ok)) { res =>
            res.contentString = TokensEncoder(tokens).toString()
            res.contentType = "application/json"
          }.toFuture
        }
        case _ => fail("must not get here")
      }
    )
    try {
      // Allocate and Session
      val sessionId = sessionid.untagged

      // Login manager request
      val loginRequest = req("umbrella.k", "/loginConfirm",
        ("username" -> "foo"), ("password" -> "bar"))

      // Original request
      val origReq = req("umbrella.k", "/ent", ("fake" -> "drake"))
      sessionStore.update[Request](Session(sessionId, origReq))

      // Execute
      val output = keymasterIdentityProviderChain(sessionStore).apply(
        BorderRequest(loginRequest, cust1k, one, sessionId))

      // Validate
      val resp = Await.result(output)
      resp.status should be(Status.Found)
      resp.location.get should startWith("/ent")

    } finally {
      server.close()
    }
  }

  behavior of "keymasterAccessIssuerChain"

  it should "succeed and invoke the GET on accessManager" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains keymasterAccessEndpoint.path.toString => Service.mk[Request, Response] { req =>
          tap(Response(Status.Ok)) { res =>
            res.contentString = TokensEncoder(tokens2).toString()
            res.contentType = "application/json"
          }.toFuture
        }
        case p1 if p1 contains one.path.toString => Service.mk[Request, Response] { _ => Response(Status.Ok).toFuture}
        case _ => fail("must not get here")
      }
    )
    try {
      // Allocate and Session
      val sessionId = sessionid.untagged

      // Original request
      val origReq = req("umbrella.k", "/ent")
      sessionStore.update[Tokens](Session(sessionId, tokens))

      // Execute
      val output = keymasterAccessIssuerChain(sessionStore).apply(
        BorderRequest(origReq, cust1k, one, sessionId))

      // Validate
      Await.result(output).status should be(Status.Ok)
    } finally {
      server.close()
    }
  }
}
