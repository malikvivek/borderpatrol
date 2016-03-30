package com.lookout.borderpatrol.auth.keymaster

import com.lookout.borderpatrol.auth.OAuth2.OAuth2CodeVerify
import com.lookout.borderpatrol.errors.{BpForbiddenRequest, BpBadRequest}
import com.lookout.borderpatrol.util.Combinators.tap
import com.lookout.borderpatrol.sessionx._
import com.lookout.borderpatrol._
import com.lookout.borderpatrol.Binder._
import com.lookout.borderpatrol.auth._
import com.lookout.borderpatrol.util.Helpers
import com.twitter.finagle.stats.StatsReceiver
import com.twitter.finagle.{Filter, Service}
import com.twitter.finagle.http._
import com.twitter.logging.Logger
import com.twitter.util.Future


object Keymaster {
  import Tokens._

  case class KeymasterIdentifyReq(req: Request, customerId: CustomerIdentifier, serviceId: ServiceIdentifier,
                                  sessionId: SignedId, credential: Credential) extends IdentifyRequest[Credential]
  object KeymasterIdentifyReq {
    def apply(sr: BorderRequest, credential: Credential): KeymasterIdentifyReq =
      KeymasterIdentifyReq(sr.req, sr.customerId, sr.serviceId, sr.sessionId, credential)
  }
  case class KeymasterIdentifyRes(tokens: Tokens) extends IdentifyResponse[Tokens] {
    val identity = Identity(tokens)
  }
  case class KeymasterAccessReq(identity: Id[Tokens], customerId: CustomerIdentifier,
                                serviceId: ServiceIdentifier, sessionId: SignedId) extends AccessRequest[Tokens]
  case class KeymasterAccessRes(access: Access[ServiceToken]) extends AccessResponse[ServiceToken]

  /**
   * The identity provider for Keymaster, will connect to the remote keymaster server to authenticate and get an
   * identity (master token)
   * @param binder Binder that binds to Keymaster identity service passed in the IdentityManager
   */
  case class KeymasterIdentityProvider(binder: MBinder[Manager])
                                      (implicit statsReceiver: StatsReceiver)
      extends IdentityProvider[Credential, Tokens] {
    private[this] val log = Logger.get(getClass.getPackage.getName)
    private[this] val statRequestSends = statsReceiver.counter("keymaster.identity.provider.request.sends")
    private[this] val statResponseParsingFailed =
      statsReceiver.counter("keymaster.identity.provider.response.parsing.failed")
    private[this] val statResponseSuccess =
      statsReceiver.counter("keymaster.identity.provider.response.success")
    private[this] val statResponseFailed =
      statsReceiver.counter("keymaster.identity.provider.response.failed")
    private[this] val statResponseDenied =
      statsReceiver.counter("keymaster.identity.provider.denied")

    /**
     * Sends credentials, if authenticated successfully will return a MasterToken otherwise a Future.exception
     */
    def apply(req: IdentifyRequest[Credential]): Future[IdentifyResponse[Tokens]] = {
      statRequestSends.incr

      //  Authenticate user by the Keymaster
      binder(BindRequest(req.credential.customerId.loginManager.identityManager, req.credential.toRequest))
        .flatMap(res => res.status match {
        //  Parse for Tokens if Status.Ok
        case Status.Ok =>
          Tokens.derive[Tokens](res.contentString).fold[Future[IdentifyResponse[Tokens]]](
            err => {
              statResponseParsingFailed.incr
              Future.exception(BpTokenParsingError("Failed to parse the Keymaster Identity Response"))
            },
            t => {
              statResponseSuccess.incr
              Future.value(KeymasterIdentifyRes(t))
            }
          )
        case Status.Forbidden => {
          statResponseDenied.incr
          Future.exception(BpIdentityProviderError(Status.Forbidden,
            s"IdentityProvider failed to authenticate user: '${req.credential.uniqueId}'"))
        }
        case _ => {
          statResponseFailed.incr
          Future.exception(BpIdentityProviderError(Status.InternalServerError,
            s"IdentityProvider failed to authenticate user: '${req.credential.uniqueId}', with status: ${res.status}"))
        }
      })
    }
  }

  /**
   * Handles Keymaster transforms for internal and OAuth2
   */
  case class KeymasterTransformFilter(oAuth2CodeVerify: OAuth2CodeVerify)(implicit statsReceiver: StatsReceiver)
      extends Filter[BorderRequest, Response, KeymasterIdentifyReq, Response] {

    def transformInternal(req: BorderRequest): Future[InternalAuthCredential] = {
      (for {
        u <- Helpers.scrubQueryParams(req.req.params, "username")
        p <- Helpers.scrubQueryParams(req.req.params, "password")
      } yield InternalAuthCredential(u, p, req.customerId, req.serviceId)) match {
        case Some(c) => Future.value(c)
        case None => Future.exception(new BpBadRequest("Failed to find username and/or password in the Request"))
      }
    }

    def transformOAuth2(req: BorderRequest, protoManager: OAuth2CodeProtoManager): Future[OAuth2CodeCredential] = {
      for {
          accessClaimSet <- oAuth2CodeVerify.codeToClaimsSet(req, protoManager)
      } yield OAuth2CodeCredential(accessClaimSet.getStringClaim("upn"), accessClaimSet.getSubject,
        req.customerId, req.serviceId)
    }

    def apply(req: BorderRequest,
              service: Service[KeymasterIdentifyReq, Response]): Future[Response] = {
      for {
        transformed: Credential <- req.customerId.loginManager.protoManager match {
          case a: InternalAuthProtoManager => transformInternal(req)
          case b: OAuth2CodeProtoManager => transformOAuth2(req, b)
        }
        resp <- service(KeymasterIdentifyReq(req, transformed))
      } yield resp
    }
  }

  /**
   * Handles logins to the KeymasterIdentityProvider:
   * - saves the Tokens after a successful login
   * - sends the User to their original request location from before they logged in or the default location based on
   * their service
   * @param store
   * @param secretStoreApi
   */
  case class KeymasterPostLoginFilter(store: SessionStore)
                                     (implicit secretStoreApi: SecretStoreApi, statsReceiver: StatsReceiver)
      extends Filter[KeymasterIdentifyReq, Response, IdentifyRequest[Credential], IdentifyResponse[Tokens]] {
    private[this] val log = Logger.get(getClass.getPackage.getName)
    private[this] val statSessionAuthenticated = statsReceiver.counter("keymaster.session.authenticated")

    /**
     * Grab the original request from the session store, otherwise just send them to the default location of '/'
     */
    def requestFromSessionStore(sessionId: SignedId): Future[Request] =
      store.get[Request](sessionId).flatMap {
        case Some(session) => Future.value(session.data)
        case None => Future.exception(BpOriginalRequestNotFound(s"no request stored for ${sessionId.toLogIdString}"))
      }

    def apply(req: KeymasterIdentifyReq,
              service: Service[IdentifyRequest[Credential], IdentifyResponse[Tokens]]): Future[Response] = {
      for {
          tokenResponse <- service(req)
          session <- Session(tokenResponse.identity.id, AuthenticatedTag)
          _ <- store.update[Tokens](session)
          originReq <- requestFromSessionStore(req.sessionId)
          _ <- store.delete(req.sessionId)
        } yield {
          statSessionAuthenticated.incr
          throw BpRedirectError(Status.Ok, originReq.uri, Some(session.id),
            s"Session: ${req.sessionId.toLogIdString}} is authenticated, " +
              s"allocated new Session: ${session.id.toLogIdString} and redirecting to " +
              s"location: ${originReq.uri}")
        }
    }
  }

  /**
   * The access issuer will use the MasterToken to gain access to service tokens
   * @param binder It binds to the Keymaster Access Issuer using info in AccessManager
   * @param store Session store
   */
  case class KeymasterAccessIssuer(binder: MBinder[Manager], store: SessionStore)
                                  (implicit statsReceiver: StatsReceiver)
      extends AccessIssuer[Tokens, ServiceToken] {
    private[this] val log = Logger.get(getClass.getPackage.getName)
    private[this] val statRequestSends = statsReceiver.counter("keymaster.access.issuer.request.sends")
    private[this] val statsResponseParsingFailed =
      statsReceiver.counter("keymaster.access.issuer.response.parsing.failed")
    private[this] val statsResponseSuccess =
      statsReceiver.counter("keymaster.access.issuer.response.success")
    private[this] val statAccessDenied =
      statsReceiver.counter("keymaster.access.issuer.access.denied")
    private[this] val statsResponseFailed =
      statsReceiver.counter("keymaster.access.issuer.response.failed")
    private[this] val statCacheHits = statsReceiver.counter("keymaster.access.issuer.cache.hits")

    def api(accessRequest: AccessRequest[Tokens]): Request =
      tap(Request(Method.Post, accessRequest.customerId.loginManager.accessManager.path.toString))(req => {
        req.contentType = "application/x-www-form-urlencoded"
        req.contentString = Request.queryString("services" -> accessRequest.serviceId.name)
          .drop(1) /* Drop '?' */
        req.headerMap.add("Auth-Token", accessRequest.identity.id.master.value)
      })

    /**
     * Fetch a valid ServiceToken, will return a ServiceToken otherwise a Future.exception
     */
    def apply(req: AccessRequest[Tokens]): Future[AccessResponse[ServiceToken]] = {
      //  Check if ServiceToken is already available for Service
      req.identity.id.service(req.serviceId.name).fold[Future[ServiceToken]]({
        statRequestSends.incr()
        //  Fetch ServiceToken from the Keymaster
        binder(BindRequest(req.customerId.loginManager.accessManager, api(req))).flatMap(res => res.status match {
          //  Parse for Tokens if Status.Ok
          case Status.Ok =>
            Tokens.derive[Tokens](res.contentString).fold[Future[ServiceToken]](
              e => {
                statsResponseParsingFailed.incr()
                Future.exception(BpTokenParsingError("in Keymaster Access Response"))
              },
              tokens => {
                statsResponseSuccess.incr()
                tokens.service(req.serviceId.name).fold[Future[ServiceToken]]({
                  statAccessDenied.incr()
                  Future.exception(new BpForbiddenRequest(
                    s"AccessIssuer denied access to the service: ${req.serviceId.name}"))
                })(st => for {
                  _ <- store.update(Session(req.sessionId, req.identity.id.add(req.serviceId.name, st)))
                } yield st)
              }
            )
          case _ => {
            statsResponseFailed.incr()
            Future.exception(BpAccessIssuerError(Status.InternalServerError,
              s"AccessIssuer failed to permit access to the service: '${req.serviceId.name}', " +
                s"with status: ${res.status}"))
          }
        })
      })(t => {
        statCacheHits.incr()
        Future.value(t)
      }).map(t => KeymasterAccessRes(Access(t)))
    }
  }

  /**
   *  Keymaster Identity provider service Chain
   * @param store
   */
  def keymasterIdentityProviderChain(store: SessionStore)(
    implicit secretStoreApi: SecretStoreApi, statsReceiver: StatsReceiver): Service[BorderRequest, Response] =
        KeymasterTransformFilter(new OAuth2CodeVerify) andThen
        KeymasterPostLoginFilter(store) andThen
        KeymasterIdentityProvider(ManagerBinder)


  /**
   * Keymaster Access Issuer service Chain
   * @param store
   */
  def keymasterAccessIssuerChain(store: SessionStore)(
    implicit secretStoreApi: SecretStoreApi, statsReceiver: StatsReceiver): Service[BorderRequest, Response] =
      RewriteFilter() andThen
        IdentityFilter[Tokens](store) andThen
        AccessFilter[Tokens, ServiceToken](ServiceIdentifierBinder) andThen
        KeymasterAccessIssuer(ManagerBinder, store)

}
