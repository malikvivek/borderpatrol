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
import com.twitter.io.Buf
import com.twitter.util.{Time, Await, Future}
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
    val accessToken = new PlainJWT(new JWTClaimsSet.Builder().subject("SomeAccessToken")
      .claim("upn", "test1@example.com")
      .claim("tid", "tid-tid-tid-tid")
      .build)
 
    val groups = new java.util.ArrayList[String]()
    groups.add("group1")
    groups.add("group2")
    val idToken = new PlainJWT(new JWTClaimsSet.Builder().subject("SomeIdToken")
      .claim("upn", "test2@example.com")
      .claim("groups", groups)
      .build)

  // Method to decode SessionData from the sessionId
  def getTokensFromSessionId(sid: SignedId): Future[Tokens] =
    (for {
      sessionMaybe <- sessionStore.get[Tokens](sid)
    } yield sessionMaybe.fold[Identity[Tokens]](EmptyIdentity)(s => Id(s.data))).map {
      case Id(tokens) => tokens
      case EmptyIdentity => null
    }

  behavior of "KeymasterPostLoginFilter"

  it should "succeed and saves tokens for internal auth, sends redirect with tokens returned by keymaster IDP" in {
    val testService = Service.mk[BorderRequest, IdentifyResponse[Tokens]] {
      req => Future(KeymasterIdentifyRes(tokens)) }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("enterprise", "/login")

    // Original request
    val origReq = req("enterprise", "/dang", ("fake" -> "drake"))
    sessionStore.update[Request](Session(sessionId, origReq))

    // Execute
    val output = (KeymasterPostLoginFilter(sessionStore) andThen testService)(
      BorderRequest(loginRequest, cust1, one, sessionId))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Found)
    resp.location.get should startWith("/dang")
    val sessionIdZ = SignedId.fromResponse(resp)
    sessionIdZ.isFailure should be(false)
    sessionIdZ.get should not be(sessionId)
    val tokensz = getTokensFromSessionId(sessionIdZ.get)
    Await.result(tokensz) should be(tokens)
  }

  it should "succeed and saves tokens for internal auth, sends json response for redirect" in {
    val testService = Service.mk[BorderRequest, IdentifyResponse[Tokens]] {
      req => Future(KeymasterIdentifyRes(tokens)) }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("enterprise", "/login")
    loginRequest.accept = Seq("application/json")

    // Original request
    val origReq = req("enterprise", "/dang", ("fake" -> "drake"))
    sessionStore.update[Request](Session(sessionId, origReq))

    // Execute
    val output = (KeymasterPostLoginFilter(sessionStore) andThen testService)(
      BorderRequest(loginRequest, cust1, one, sessionId))

    // Validate
    val resp = Await.result(output)
    resp.status should be(Status.Ok)
    resp.contentType.get should include("application/json")
    resp.contentString should include (""""redirect_url" : "/dang?fake=drake"""")
    val sessionIdZ = SignedId.fromResponse(resp)
    sessionIdZ.isFailure should be(false)
    sessionIdZ.get should not be(sessionId)
    val tokensz = getTokensFromSessionId(sessionIdZ.get)
    Await.result(tokensz) should be(tokens)
  }

  it should "throw BpOriginalRequestNotFound if it fails find the original request from sessionStore" in {
    val testService = Service.mk[BorderRequest, IdentifyResponse[Tokens]] {
      req => Future(KeymasterIdentifyRes(tokens)) }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("enterprise", "/login", ("username" -> "foo"), ("password" -> "bar"))

    // Execute
    val output = (KeymasterPostLoginFilter(sessionStore) andThen testService)(
      BorderRequest(loginRequest, cust1, one, sessionId))

    // Validate
    val caught = the [BpOriginalRequestNotFound] thrownBy {
      Await.result(output)
    }
    caught.msg should include("no request stored for ")
  }

  it should "propagate the Exception thrown by Session lookup operation" in {
    val testService = Service.mk[BorderRequest, IdentifyResponse[Tokens]] {
      req => Future(KeymasterIdentifyRes(tokens)) }

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
    val loginRequest = req("enterprise", "/login", ("username" -> "foo"), ("password" -> "bar"))

    // Execute
    val output = (KeymasterPostLoginFilter(mockSessionStore) andThen testService)(
      BorderRequest(loginRequest, cust1, one, sessionId))

    // Validate
    val caught = the [Exception] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal ("oopsie")
  }

  it should "propagate the Exception thrown by Session update operation" in {
    val testService = Service.mk[BorderRequest, IdentifyResponse[Tokens]] {
      req => Future(KeymasterIdentifyRes(tokens)) }

    //  Mock SessionStore client
    case object FailingMockClient extends memcached.MockClient {
      override def set(key: String, flags: Int, expiry: Time, value: Buf) : Future[Unit] = {
        Future.exception[Unit](new Exception("Session.update failed"))
      }
    }

    // Mock sessionStore
    val mockSessionStore = MemcachedStore(FailingMockClient)

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("enterprise", "/login", ("username" -> "foo"), ("password" -> "bar"))

    // Execute
    val output = (KeymasterPostLoginFilter(mockSessionStore) andThen testService)(
      BorderRequest(loginRequest, cust1, one, sessionId))

    // Validate
    val caught = the [Exception] thrownBy {
      Await.result(output)
    }
    caught.getMessage should equal ("Session.update failed")
  }

  behavior of "KeymasterProcessResponse"

  it should "succeed and return IdentityResponse with tokens received from upstream Keymaster Service" in {
    val testService = Service.mk[BorderRequest, Response] { req =>
      tap(Response(Status.Ok))(res => {
        res.contentString = TokensEncoder(tokens).toString()
        res.contentType = "application/json"
      }).toFuture
    }
    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("umbrella.k", "/loginConfirm", "username" -> "foo", "password" -> "bar")

    // Execute
    val output = (KeymasterProcessResponse() andThen testService)(
      BorderRequest(loginRequest, cust1, one, sessionId))

    // Validate
    Await.result(output).identity should be(Id(tokens))
  }

  it should "throw BpForbiddenRequest if Keymaster returns the Forbidden Status code" in {
    val testService = Service.mk[BorderRequest, Response] { _ => Response(Status.Forbidden).toFuture}

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("sky.k", "/signin", ("code" -> "XYZ123"))


    // Execute
    val output = (KeymasterProcessResponse() andThen testService)(
      BorderRequest(loginRequest, cust2, two, sessionId))

    // Validate
    val caught = the[BpForbiddenRequest] thrownBy {
      Await.result(output)
    }
    caught.getMessage should include("IdentityProvider failed to authenticate user")
    caught.status should be(Status.Forbidden)
  }

  it should "propagate the error status from Keymaster service in the BpIdentityProviderError exception" in {
    val testService = Service.mk[BorderRequest, Response] { _ => Response(Status.NotAcceptable).toFuture}

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("sky.k", "/signin", ("code" -> "XYZ123"))


    // Execute
    val output = (KeymasterProcessResponse() andThen testService)(
      BorderRequest(loginRequest, cust2, two, sessionId))

    // Validate
    val caught = the[BpIdentityProviderError] thrownBy {
      Await.result(output)
    }
    caught.getMessage should include("IdentityProvider failed to authenticate user, with status: ")
    caught.status should be(Status.InternalServerError)
  }

  it should "propagate the failure parsing the resp from Keymaster service as an BpTokenParsingError exception" in {
    val testService = Service.mk[BorderRequest, Response] { _ =>
      tap(Response(Status.Ok))(res => {
        res.contentString = """{"key":"data"}"""
        res.contentType = "application/json"
      }).toFuture
    }

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("umbrella.k", "/loginConfirm", "username" -> "foo", "password" -> "bar")

    // Execute
    val output = (KeymasterProcessResponse() andThen testService)(
      BorderRequest(loginRequest, cust2, two, sessionId))

    // Validate
    val caught = the[BpTokenParsingError] thrownBy {
      Await.result(output)
    }
    caught.getMessage should include("Failed to parse token with: ")
  }

  behavior of "KeymasterBasicAuth"

  it should "succeed to authenticate and return response with tokens" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains "identity" => Service.mk[Request, Response] { req =>
          Response(Status.Ok).toFuture
        }
        case _ => fail("we should not get here")
      }
  )
    try {
      // Allocate and Session
      val sessionId = sessionid.untagged

      // Login POST request
      val loginRequest = req("umbrella.k", "/loginConfirm", ("username" -> "test@example.com"), ("password" -> "bar"))

      // Execute
      val output = KeymasterBasicAuth().apply(BorderRequest(loginRequest, cust1k, one, sessionId))

      // Validate
      Await.result(output).status should be(Status.Ok)
    } finally {
      server.close()
    }
  }

  it should "throw BpBadRequest if username is not present in the Request" in {
    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("enterprise", "/login", ("username" -> "foo"))

    // Execute
    // Validate
    val caught = the[BpBadRequest] thrownBy {
      val output = KeymasterBasicAuth().apply(BorderRequest(loginRequest, cust1, one, sessionId))
    }
    caught.getMessage should include("Failed to find username and/or password in the Request")
  }

  it should "throw BpBadRequest if password is not present in the Request" in {
    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("enterprise", "/login", ("password" -> "foo"))

    // Execute
    // Validate
    val caught = the[BpBadRequest] thrownBy {
      val output = KeymasterBasicAuth().apply(BorderRequest(loginRequest, cust1, one, sessionId))
    }
    caught.getMessage should include("Failed to find username and/or password in the Request")
  }

  behavior of "KeymasterOAuth2Auth"

  it should "succeed to retrieve tokens for the given access and id tokens" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains "identity" => Service.mk[Request, Response] { req =>
          assert(req.path == cust2k.loginManager.identityEndpoint.path.toString)
          req.contentString.replaceAll("\\s", "") should be( """s=two&external_id=SomeAccessToken&idp_guid=ulm-guid&ent_guid=cust2-guid""")
          tap(Response(Status.Ok))(res => {
            res.contentString = TokensEncoder(tokens).toString()
            res.contentType = "application/json"
          }).toFuture
        }
        case _ => fail("we should not get here")
      }
    )
    try {
      // Allocate and Session
      val sessionId = sessionid.untagged

      // Login POST request
      val loginRequest = req("skyx", "/signin", ("code" -> "XYZ123"))

      //  Request
      val borderRequest = BorderRequest(loginRequest, cust2k, two, sessionId)

      // Mock the oAuth2 verifier
      val mockVerify = mock[OAuth2CodeVerify]
      when(mockVerify.codeToClaimsSet(borderRequest, umbrellaLoginManager)).thenReturn(
        Future.value((accessToken.getJWTClaimsSet, idToken.getJWTClaimsSet)))

      // Execute
      val output = KeymasterOAuth2Auth(mockVerify).apply(borderRequest)

      // Validate
      Await.result(output).status should be(Status.Ok)
    } finally {
      server.close()
    }
  }

  it should "throw BpBadRequest if it fails to find subject in the access token" in {
    val accessToken = new PlainJWT(new JWTClaimsSet.Builder()
      .claim("upn", "test1@example.com")
      .claim("tid", "tid-tid-tid-tid")
      .build)

    // Allocate and Session
    val sessionId = sessionid.untagged

    // Login POST request
    val loginRequest = req("skyx", "/signin", ("code" -> "XYZ123"))

    //  Request
    val borderRequest = BorderRequest(loginRequest, cust2k, two, sessionId)

    // Mock the oAuth2 verifier
    val mockVerify = mock[OAuth2CodeVerify]
    when(mockVerify.codeToClaimsSet(borderRequest, umbrellaLoginManager)).thenReturn(
      Future.value((accessToken.getJWTClaimsSet, idToken.getJWTClaimsSet)))

    // Execute
    val output = KeymasterOAuth2Auth(mockVerify).apply(borderRequest)

    // Validate
    val caught = the[BpBadRequest] thrownBy {
      Await.result(output).status should be(Status.Ok)
    }
    caught.msg should include("Failed to find 'sub' in the Access Token in the Request")
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

  behavior of "keymasterBasicServiceChain"

  it should "succeed to retrieve tokens from this service chain" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678",
      RoutingService.byPath {
        case p1 if p1 contains "identity" => Service.mk[Request, Response] { req =>
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
      val output = keymasterBasicServiceChain(sessionStore).apply(
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
