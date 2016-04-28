package com.lookout.borderpatrol.auth.keymaster

import com.lookout.borderpatrol.{Binder, ServiceIdentifier, CustomerIdentifier}
import com.lookout.borderpatrol.auth.keymaster.LoginManagers._
import com.lookout.borderpatrol.errors.{BpForbiddenRequest, BpBadRequest}
import com.lookout.borderpatrol.util.Combinators.tap
import com.lookout.borderpatrol.sessionx._
import com.lookout.borderpatrol.auth._
import com.lookout.borderpatrol.util.Helpers
import com.nimbusds.jwt.JWTClaimsSet
import com.twitter.finagle.stats.StatsReceiver
import com.twitter.finagle.{Filter, Service}
import com.twitter.finagle.http._
import com.twitter.logging.Logger
import com.twitter.util.Future
import scala.collection.JavaConverters._


object Keymaster {
  import Tokens._
  import OAuth2._

  case class KeymasterIdentifyRes(tokens: Tokens) extends IdentifyResponse[Tokens] {
    val identity = Identity(tokens)
  }
  case class KeymasterAccessReq(identity: Id[Tokens], customerId: CustomerIdentifier,
                                serviceId: ServiceIdentifier, sessionId: SignedId) extends AccessRequest[Tokens]
  case class KeymasterAccessRes(access: Access[ServiceToken]) extends AccessResponse[ServiceToken]

  /**
   * BasicAuthStateMixin
   *
   * This mixin trait that allows us to add interface to generate identity provider request using basic
   * credentials
   */
  trait BasicAuthStateMixin {
    val req: BorderRequest

    lazy val (username, password) = {
      (for {
        u <- Helpers.scrubQueryParams(req.req.params, "username")
        p <- Helpers.scrubQueryParams(req.req.params, "password")
      } yield (u, p)) match {
        case Some(c) => c
        case None => throw BpBadRequest("Failed to find username and/or password in the Request")
      }
    }

    private[this] def authPayload(grants: Set[String]): String =
      Request.queryString(("s", req.serviceId.name), ("email", username),
        ("password", password)).drop(1) /* Drop '?' */

    def authRequest(grants: Set[String]): Request =
      tap(Request(Method.Post, req.customerId.loginManager.identityEndpoint.path.toString)) { req =>
        req.contentType = "application/x-www-form-urlencoded"
        req.contentString = authPayload(grants)
      }

    def authenticate(grants: Set[String]): Future[Response] = {
      Binder.connect(req.customerId.loginManager.identityEndpoint, authRequest(grants))
    }
  }

  /**
   * OAuth2StateMixin
   *
   * This mixin trait that allows us to add interface to generate identity provider request using OAuth2
   * token credentials
   */
  trait OAuth2StateMixin {
    val accessClaimSet: JWTClaimsSet
    val idClaimSet: JWTClaimsSet
    val req: BorderRequest

    def aStringClaim(claim: String): String = wrapOps[String]({ () => accessClaimSet.getStringClaim(claim)},
      s"Failed to find '$claim' in the Access Token in the Request",
      BpBadRequest.apply)

    def aStringListClaim(claim: String): List[String] = wrapOps[List[String]](
      { () => accessClaimSet.getStringListClaim(claim).asScala.toList},
      s"Failed to find '$claim' in the Access Token in the Request",
      BpBadRequest.apply)

    def iStringClaim(claim: String): String = wrapOps[String]({ () => idClaimSet.getStringClaim(claim)},
      s"Failed to find '$claim' in the Id Token in the Request",
      BpBadRequest.apply)

    def iStringListClaim(claim: String): List[String] = wrapOps[List[String]](
      { () => idClaimSet.getStringListClaim(claim).asScala.toList},
      s"Failed to find '$claim' in the Id Token in the Request",
      BpBadRequest.apply)

    private[this] def authPayload(grants: Set[String]): String =
      Request.queryString(("s", req.serviceId.name), ("external_id", aStringClaim("sub")),
        ("idp_guid", req.customerId.loginManager.guid), ("ent_guid", req.customerId.guid))
        .drop(1) /* Drop '?' */

    def authRequest(grants: Set[String]): Request = {
      tap(Request(Method.Post, req.customerId.loginManager.identityEndpoint.path.toString)) { req =>
        req.contentType = "application/x-www-form-urlencoded"
        req.contentString = authPayload(grants)
      }
    }

    def authenticate(grants: Set[String]): Future[Response] = {
      Binder.connect(req.customerId.loginManager.identityEndpoint, authRequest(grants))
    }
  }

  /**
   * KeymasterPostLoginFilter
   *
   * - does all work done after successful login
   * - deletes unauthenticated session
   * - allocates new authenticated sessionId, saves the Tokens in that Session
   * - sends a "redirect" user's original request location
   *
   * @param store session store
   * @param secretStoreApi (implicit) secret store
   * @param statsReceiver (implicit) stats receiver
   */
  case class KeymasterPostLoginFilter(store: SessionStore)
                                     (implicit secretStoreApi: SecretStoreApi, statsReceiver: StatsReceiver)
    extends Filter[BorderRequest, Response, BorderRequest, IdentifyResponse[Tokens]] {
    private[this] val log = Logger.get(getClass.getPackage.getName)
    private[this] val statSessionAuthenticated = statsReceiver.counter("keymaster.idp.authenticated")

    /**
     * Grab the original request from the session store, otherwise just send them to the default location of '/'
     */
    def requestFromSessionStore(sessionId: SignedId): Future[Request] =
      store.get[Request](sessionId).flatMap {
        case Some(session) => Future.value(session.data)
        case None => Future.exception(BpOriginalRequestNotFound(s"no request stored for ${sessionId.toLogIdString}"))
      }

    def apply(req: BorderRequest,
              service: Service[BorderRequest, IdentifyResponse[Tokens]]): Future[Response] = {
      for {
        tokenResponse <- service(req)
        session <- Session(tokenResponse.identity.id, AuthenticatedTag)
        _ <- store.update[Tokens](session)
        originReq <- requestFromSessionStore(req.sessionId)
        _ <- store.delete(req.sessionId)
      } yield {
        statSessionAuthenticated.incr
        BorderAuth.formatRedirectResponse(req.req, Status.Ok, originReq.uri, Some(session.id),
          s"Session: ${req.sessionId.toLogIdString}} is authenticated, " +
            s"allocated new Session: ${session.id.toLogIdString} and redirecting to " +
            s"location: ${originReq.uri}")
      }
    }
  }

  /**
   * KeymasterProcessResponse
   *
   * - processes the authenticate response coming from Keymaster identity provider
   * - decodes JSON response into Master and Service token
   *
   * @param statsReceiver (implicit) stats receiver
   */
  case class KeymasterProcessResponse(implicit statsReceiver: StatsReceiver)
    extends Filter[BorderRequest, IdentifyResponse[Tokens], BorderRequest, Response] {
    private[this] val log = Logger.get(getClass.getPackage.getName)
    private[this] val statResponseParsingFailed = statsReceiver.counter("keymaster.idp.response.parsing.failed")
    private[this] val statResponseSuccess = statsReceiver.counter("keymaster.idp.response.success")
    private[this] val statResponseFailed = statsReceiver.counter("keymaster.idp.response.failed")
    private[this] val statResponseDenied = statsReceiver.counter("keymaster.idp.denied")

    /**
     * Sends credentials, if authenticated successfully will return a MasterToken otherwise a Future.exception
     */
    def apply(req: BorderRequest, service: Service[BorderRequest, Response]): Future[IdentifyResponse[Tokens]] = {
      service(req).flatMap(res => res.status match {
        //  Parse for Tokens if Status.Ok
        case Status.Ok =>
          Tokens.derive[Tokens](res.contentString).fold[Future[IdentifyResponse[Tokens]]](
            err => {
              statResponseParsingFailed.incr
              Future.exception(BpTokenParsingError(
                s"Failed to parse the Keymaster Identity Response with: ${err.getMessage}"))
            },
            t => {
              statResponseSuccess.incr
              Future.value(KeymasterIdentifyRes(t))
            }
          )
        case Status.Forbidden => {
          statResponseDenied.incr
          Future.exception(BpForbiddenRequest(s"IdentityProvider failed to authenticate user"))
        }
        case _ => {
          statResponseFailed.incr
          Future.exception(BpIdentityProviderError(Status.InternalServerError,
            s"IdentityProvider failed to authenticate user, with status: ${res.status}"))
        }
      })
    }
  }

  /**
   * KeymasterBasicAuth
   *
   * - performs basic authentication, sends username and password to Keymaster
   *
   * @param statsReceiver (implicit) stats receiver
   */
  case class KeymasterBasicAuth(implicit statsReceiver: StatsReceiver) extends Service[BorderRequest, Response] {
    private[this] val statRequestSends = statsReceiver.counter("keymaster.idp.basic.request.sends")

    case class BasicHelper(req: BorderRequest) extends BasicAuthStateMixin

    def apply(req: BorderRequest): Future[Response] = {
      statRequestSends.incr()
      val basicHelper = BasicHelper(req)
      Binder.connect(req.customerId.loginManager.identityEndpoint, basicHelper.authRequest(Set.empty))
    }
  }

  /**
   * KeymasterOAuth2Auth
   *
   * - performs oAuth2 authentication, sends token credentials to Keymaster
   *
   * @param oAuth2CodeVerify oAuth2 companion object to obtain token and verify them
   * @param statsReceiver (implicit) stats receiver
   */
  case class KeymasterOAuth2Auth(oAuth2CodeVerify: OAuth2CodeVerify)(implicit statsReceiver: StatsReceiver)
    extends Service[BorderRequest, Response] {

    case class OAuth2Helper(accessClaimSet: JWTClaimsSet, idClaimSet: JWTClaimsSet, req: BorderRequest)
      extends OAuth2StateMixin

    def apply(req: BorderRequest): Future[Response] = {
      for {
        (accessClaimSet, idClaimSet) <- oAuth2CodeVerify.codeToClaimsSet(req,
          req.customerId.loginManager.as[OAuth2LoginManager])
        oAuth2Helper <- OAuth2Helper(accessClaimSet, idClaimSet, req).toFuture
        resp <- Binder.connect(req.customerId.loginManager.identityEndpoint, oAuth2Helper.authRequest(Set.empty))
      } yield resp
    }
  }

  /**
   * A chain that performs the following:
   * - Basic auth (no provisioning & grants)
   */
  def keymasterBasicServiceChain(store: SessionStore)
                                (implicit secretStoreApi: SecretStoreApi,
                                 statsReceiver: StatsReceiver): Service[BorderRequest, Response] =
    KeymasterPostLoginFilter(store) andThen
      KeymasterProcessResponse() andThen
      KeymasterBasicAuth()

  /**
   * A chain that performs the following:
   * - OAuth2 auth (no provisioning & grants)
   */
  def keymasterOAuth2ServiceChain(store: SessionStore)
                                 (implicit secretStoreApi: SecretStoreApi,
                                  statsReceiver: StatsReceiver): Service[BorderRequest, Response] =
    KeymasterPostLoginFilter(store) andThen
      KeymasterProcessResponse() andThen
      KeymasterOAuth2Auth(new OAuth2CodeVerify)

  /**
   * KeymasterAccessIssuer
   *
   * - The access issuer will use the MasterToken to gain access to service tokens
   *
   * @param statsReceiver (implicit) stats receiver
   */
  case class KeymasterAccessIssuer(store: SessionStore)(implicit statsReceiver: StatsReceiver)
    extends AccessIssuer[Tokens, ServiceToken] {
    private[this] val log = Logger.get(getClass.getPackage.getName)
    private[this] val statRequestSends = statsReceiver.counter("keymaster.ai.request.sends")
    private[this] val statsResponseParsingFailed =
      statsReceiver.counter("keymaster.ai.response.parsing.failed")
    private[this] val statsResponseSuccess =
      statsReceiver.counter("keymaster.ai.response.success")
    private[this] val statAccessDenied =
      statsReceiver.counter("keymaster.ai.access.denied")
    private[this] val statsResponseFailed =
      statsReceiver.counter("keymaster.ai.response.failed")
    private[this] val statCacheHits = statsReceiver.counter("keymaster.ai.cache.hits")

    def api(accessRequest: AccessRequest[Tokens]): Request =
      tap(Request(Method.Post, accessRequest.customerId.loginManager.accessEndpoint.path.toString)) { req =>
        req.contentType = "application/x-www-form-urlencoded"
        req.contentString = Request.queryString("services" -> accessRequest.serviceId.name)
          .drop(1) /* Drop '?' */
        req.headerMap.add("Auth-Token", accessRequest.identity.id.master.value)
      }

    /**
     * Fetch a valid ServiceToken, will return a ServiceToken otherwise a Future.exception
     */
    def apply(req: AccessRequest[Tokens]): Future[AccessResponse[ServiceToken]] = {
      //  Check if ServiceToken is already available for Service
      req.identity.id.service(req.serviceId.name).fold[Future[ServiceToken]]({
        statRequestSends.incr()
        //  Fetch ServiceToken from the Keymaster
        Binder.connect(req.customerId.loginManager.accessEndpoint, api(req)).flatMap(res => res.status match {
          //  Parse for Tokens if Status.Ok
          case Status.Ok =>
            Tokens.derive[Tokens](res.contentString).fold[Future[ServiceToken]](
              err => {
                statsResponseParsingFailed.incr()
                Future.exception(BpTokenParsingError(s"in Keymaster Access Response with: ${err.getMessage}"))
              },
              tokens => {
                statsResponseSuccess.incr()
                tokens.service(req.serviceId.name).fold[Future[ServiceToken]]({
                  statAccessDenied.incr()
                  Future.exception(BpForbiddenRequest(
                    s"Failed to permit access to the service: '${req.serviceId.name}'"))
                })(st => for {
                  _ <- store.update(Session(req.sessionId, req.identity.id.add(req.serviceId.name, st)))
                } yield st)
              }
            )
          case _ => {
            statsResponseFailed.incr()
            Future.exception(BpAccessIssuerError(Status.InternalServerError,
              s"Failed to permit access to the service: '${req.serviceId.name}', with: ${res.status}"))
          }
        })
      })(t => {
        statCacheHits.incr()
        Future.value(t)
      }).map(t => KeymasterAccessRes(Access(t)))
    }
  }


  /**
   * Keymaster Access Issuer service Chain
   */
  def keymasterAccessIssuerChain(store: SessionStore)
                                (implicit secretStoreApi: SecretStoreApi,
                                 statsReceiver: StatsReceiver): Service[BorderRequest, Response] =
    RewriteFilter() andThen
      IdentityFilter[Tokens](store) andThen
      AccessFilter[Tokens, ServiceToken]() andThen
      KeymasterAccessIssuer(store)
}
