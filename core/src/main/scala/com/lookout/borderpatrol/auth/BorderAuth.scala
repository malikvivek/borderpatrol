package com.lookout.borderpatrol.auth

import com.lookout.borderpatrol.Binder.{BindRequest, MBinder}
import com.lookout.borderpatrol.util.Combinators._
import com.lookout.borderpatrol.{CustomerIdentifier, ServiceIdentifier, ServiceMatcher}
import com.lookout.borderpatrol.sessionx._
import com.twitter.finagle.http.path.{Root, Path}
import com.twitter.finagle.http._
import com.twitter.finagle.stats.StatsReceiver
import com.twitter.finagle.{SimpleFilter, Service, Filter}
import com.twitter.logging.Logger
import com.twitter.util.Future
import io.circe.Json
import io.circe.syntax._


/**
 * PODs
 */
case class CustomerIdRequest(req: Request, customerId: CustomerIdentifier)
case class SessionIdRequest(req: Request, customerId: CustomerIdentifier, serviceIdOpt: Option[ServiceIdentifier],
                            sessionIdOpt: Option[SignedId])
object SessionIdRequest {
  def apply(sr: CustomerIdRequest, serviceIdOpt: Option[ServiceIdentifier],
            sidOpt: Option[SignedId]): SessionIdRequest =
    SessionIdRequest(sr.req, sr.customerId, serviceIdOpt, sidOpt)
}
case class BorderRequest(req: Request, customerId: CustomerIdentifier, serviceId: ServiceIdentifier,
                            sessionId: SignedId)
object BorderRequest {
  def apply(br: SessionIdRequest, serviceId: ServiceIdentifier, sessionId: SignedId): BorderRequest =
    BorderRequest(br.req, br.customerId, serviceId, sessionId)
}
case class AccessIdRequest[A](req: Request, customerId: CustomerIdentifier, serviceId: ServiceIdentifier,
                              sessionId: SignedId, id: Id[A])
object AccessIdRequest {
  def apply[A](sr: BorderRequest, id: Id[A]): AccessIdRequest[A] =
    AccessIdRequest(sr.req, sr.customerId, sr.serviceId, sr.sessionId, id)
}

/**
 * Determines the service that the request is trying to contact
 * If the service doesn't exist, it returns a 404 Not Found response
 *
 * @param matcher
 */
case class CustomerIdFilter(matcher: ServiceMatcher)
    extends Filter[Request, Response, CustomerIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)

  def apply(req: Request, service: Service[CustomerIdRequest, Response]): Future[Response] = {
    req.host.flatMap(matcher.customerId) match {
      case Some(cid) =>
        log.debug(s"Processing: Request(${req.method}, ${req.host.get}${req.path} " +
          s"with CustomerIdentifier: ${cid.subdomain}")
         service(CustomerIdRequest(req, cid))

      case None => tap(Response(Status.NotFound))(r => {
        log.debug("Failed to find CustomerIdentifier for " +
          s"Request(${req.method}, ${req.host.fold("null-hostname")(h => s"${h}${req.path}")})")
        r.contentString = s"${req.path}: Unknown Path/Service(${Status.NotFound.code})"
        r.contentType = "text/plain"
      }).toFuture
    }
  }
}

/**
 * Ensures we have a SignedId present in this request, sending a Redirect to the service login page if it doesn't
 */
case class SessionIdFilter(matcher: ServiceMatcher, store: SessionStore)(implicit secretStore: SecretStoreApi)
    extends Filter[CustomerIdRequest, Response, SessionIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)

  /**
   * Passes the SignedId to the next in the filter chain. If any failures decoding the SignedId occur
   * (expired, not there, etc), we will terminate early and send a redirect
   * @param req
   * @param service
   */
  def apply(req: CustomerIdRequest, service: Service[SessionIdRequest, Response]): Future[Response] = {
    service(SessionIdRequest(req,
      matcher.serviceId(Path(req.req.path)),
      SignedId.fromRequest(req.req, SignedId.sessionIdCookieName).toOption))
  }
}

/**
 * Send the request on IdentityProvider chain
 *
 * @param identityProviderMap
 * @param store
 * @param secretStore
 */
case class SendToIdentityProvider(identityProviderMap: Map[String, Service[BorderRequest, Response]],
                                  store: SessionStore)(implicit secretStore: SecretStoreApi)
  extends SimpleFilter[SessionIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)


  def sendToIdentityProvider(req: BorderRequest): Future[Response] = {
    log.debug(s"Send: ${req.req} for Session: ${req.sessionId.toLogIdString} " +
      s"to identity provider chain for service: ${req.serviceId.name}")
    identityProviderMap.get(req.customerId.loginManager.identityManager.name) match {
      case Some(ip) => ip(req)
      case None => throw IdentityProviderError(Status.NotFound, "Failed to find IdentityProvider Service Chain for " +
        req.customerId.loginManager.identityManager.name)
    }
  }

  /**
   * If content type is application/json, then return 401 with redirect location in the content body.
   * Otherwise, return a 302 redirect
   */
  def redirectToLogin(req: SessionIdRequest, sessionId: SignedId): Response = {
    val location = req.customerId.loginManager.protoManager.redirectLocation(req.req.host)
    req.req.contentType match {
      case Some("application/json") =>
        log.debug(s"Return 401 for the ${req.req} for Untagged Session: ${sessionId.toLogIdString} " +
          s"to login service, location: $location")
        tap(Response(Status.Unauthorized))(res => {
          res.addCookie(sessionId.asCookie())
          res.contentString = Json.obj(("login_url", location.asJson)).toString()
          res.contentType = "application/json"
        })
      case _ =>
        log.debug(s"Redirecting the ${req.req} for Untagged Session: ${sessionId.toLogIdString} " +
          s"to login service, location: $location")
        tap(Response(Status.Found))(res => {
          res.addCookie(sessionId.asCookie())
          res.location = location
        })
    }
  }

  def apply(req: SessionIdRequest, service: Service[SessionIdRequest, Response]): Future[Response] =
    (req.req.method, req.sessionIdOpt.map(_.tag), req.serviceIdOpt) match {

      /* 1. POST to loginConfirm path w/ untagged SessionId, dispatch to Identity Provider chain */
      case (Method.Post, Some(Untagged), _)
        if Path(req.req.path).startsWith(req.customerId.loginManager.protoManager.loginConfirm) => {
        sendToIdentityProvider(BorderRequest(req, req.customerId.defaultServiceId, req.sessionIdOpt.get))
      }

      /**
       * 2. POST to loginConfirm path w/o SessionId, allocate SessionId, dispatch to Identity Provider chain
       *    It creates default request on the fly and for location it uses defaultServiceId or target_url param
       */
      case (Method.Post, None, _)
        if Path(req.req.path).startsWith(req.customerId.loginManager.protoManager.loginConfirm) => {
        for {
          sessionId <- SignedId.untagged
          location <-
            req.req.params.get("target_url").fold(req.customerId.defaultServiceId.path.toString)(l => l).toFuture
          savedReq <- tap(Request(location))(r => r.addCookie(sessionId.asCookie())).toFuture
          session <- Session(sessionId, savedReq).toFuture
          _ <- store.update(session)
          resp <- sendToIdentityProvider(BorderRequest(req, req.customerId.defaultServiceId, sessionId))
        } yield resp
      }

      /* 3. Request w/ untagged SessionId & Service, redirect it to Login */
      case (_, Some(Untagged), Some(serviceId)) if serviceId.protekted =>
        redirectToLogin(req, req.sessionIdOpt.get).toFuture

      /* 4. Request w/ untagged SessionId, no Service, redirect it to Login */
      case (_, Some(Untagged), None) =>
        redirectToLogin(req, req.sessionIdOpt.get).toFuture

      /* 5. Request w/o SessionId, allocate SessionId and redirect it to Login */
      case (_, None, _) =>
        for {
          session <- Session(req.req)
          _ <- store.update(session)
        } yield redirectToLogin(req, session.id)

      /* Everything else */
      case _ => service(req)
    }
}

/**
 * Send the request on AccessIssuer chain
 *
 * This filter only deals with Authneticated SessionIds or forwards it to next filter
 *
 * @param accessIssuerMap
 */
case class SendToAccessIssuer(accessIssuerMap: Map[String, Service[BorderRequest, Response]])
    extends SimpleFilter[SessionIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)

  def sendToAccessIssuer(req: BorderRequest): Future[Response] = {
    log.debug(s"Send: ${req.req} for Session: ${req.sessionId.toLogIdString} " +
      s"to access issuer chain for service: ${req.serviceId.name}")
    accessIssuerMap.get(req.customerId.loginManager.accessManager.name) match {
      case Some(ip) => ip(req)
      case None => throw AccessIssuerError(Status.NotFound, "Failed to find AccessIssuer Service Chain for " +
        req.customerId.loginManager.accessManager.name)
    }
  }

  def redirectToService(req: BorderRequest): Response = {
    log.debug(s"Redirecting the ${req.req} for Authenticated Session: ${req.sessionId.toLogIdString} " +
      s"to upstream service, location: ${req.serviceId.path}")
    tap(Response(Status.Found))(res => res.location = req.serviceId.path.toString)
  }

  def apply(req: SessionIdRequest, service: Service[SessionIdRequest, Response]): Future[Response] =
    (req.sessionIdOpt.map(_.tag), req.serviceIdOpt) match {

      /* 1. Request for protected service w/ authenticated Sessionid, dispatch via accessIssuer chain */
      case (Some(AuthenticatedTag), Some(serviceId)) if serviceId.protekted =>
        sendToAccessIssuer(BorderRequest(req, serviceId, req.sessionIdOpt.get))

      /* 2. Request for Root w/ authenticated Sessionid, redirect to default service */
      case (Some(AuthenticatedTag), None) if Root.startsWith(Path(req.req.path)) =>
        redirectToService(BorderRequest(req, req.customerId.defaultServiceId, req.sessionIdOpt.get)).toFuture

      /* Everything else */
      case _ => service(req)
    }
}

/**
 * Send the request to Unprotected Service
 *
 * This filter only deals with the Request has SessionId (Authenticate or Untagged) and destined to unprotected
 * Service. Everything else is forwarded to the next filter in the chain.
 *
 * @param serviceBinder
 * @param statsReceiver
 */
case class SendToUnprotectedService(serviceBinder: MBinder[ServiceIdentifier])(implicit statsReceiver: StatsReceiver)
    extends SimpleFilter[SessionIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)
  private[this] val requestSends = statsReceiver.counter("unprotected.upstream.service.request.sends")
  private[this] val unprotectedServiceChain = RewriteFilter() andThen Service.mk[BorderRequest, Response] {
    br => serviceBinder(BindRequest(br.serviceId, br.req)) }

  def sendToUnprotectedService(req: BorderRequest): Future[Response] = {
    requestSends.incr
    log.debug(s"Send: ${req.req} for Session: ${req.sessionId.toLogIdString} " +
      s"to the unprotected upstream service: ${req.serviceId.name}")
    /* Route through a Rewrite filter */
    unprotectedServiceChain(req)
  }

  def apply(req: SessionIdRequest, service: Service[SessionIdRequest, Response]): Future[Response] =
    (req.sessionIdOpt, req.serviceIdOpt) match {

      /* 1. Request dispatch to unprotected service */
      case (Some(sessionId), Some(serviceId)) if !serviceId.protekted =>
        sendToUnprotectedService(BorderRequest(req, serviceId, sessionId))

      /* Everything else */
      case _ => service(req)
    }
}

/**
 * Logout Service
 * - Deletes the session
 * - sets the empty cookie in response
 * - redirects to default service path
 */
case class LogoutService(store: SessionStore)(implicit secretStore: SecretStoreApi)
  extends Service[CustomerIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)

  def apply(req: CustomerIdRequest): Future[Response] = {
    SignedId.fromRequest(req.req, SignedId.sessionIdCookieName).foreach(sid => {
      log.debug(s"Logging out Session: ${sid.toLogIdString}")
      store.delete(sid)
    })
    tap(Response(Status.Found)) { res =>
      // Redirect to service or the logged out path
      res.location = req.customerId.loginManager.protoManager.loggedOutUrl.fold(
        req.customerId.defaultServiceId.path.toString)(_.toString)

      // Expire all BP cookies present in the Request
      req.req.cookies.foreach[Unit] {
        case (name: String, cookie: Cookie) if name.startsWith("border_") =>
          res.addCookie(SignedId.toExpiredCookie(name))
        case _ =>
      }
      log.debug(s"After logout, redirecting to: ${res.location}")
    }.toFuture
  }
}

/**
 * Determines the identity of the requester, if no identity it responds with a redirect to the login page for that
 * service
 */
case class IdentityFilter[A : SessionDataEncoder](store: SessionStore)(implicit secretStore: SecretStoreApi)
    extends Filter[BorderRequest, Response, AccessIdRequest[A], Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)

  def identity(sessionId: SignedId): Future[Identity[A]] =
    (for {
      sessionMaybe <- store.get[A](sessionId)
    } yield sessionMaybe.fold[Identity[A]](EmptyIdentity)(s => Id(s.data))) handle {
      case e =>
        log.warning(s"Failed to retrieve Identity for Session: ${sessionId.toLogIdString}, " +
          s"from sessionStore with: ${e.getMessage}")
        EmptyIdentity
    }

  def apply(req: BorderRequest, service: Service[AccessIdRequest[A], Response]): Future[Response] =
    identity(req.sessionId).flatMap {
      case id: Id[A] => service(AccessIdRequest(req, id))
      case EmptyIdentity => for {
        s <- Session(req.req)
        _ <- store.update(s)
      } yield tap(Response(Status.Found)) { res =>
          /**
           * Session allocated, redirect to same location again (it could be unprotected and may not
           * need authentication)
           */
          res.location = req.req.uri
          res.addCookie(s.id.asCookie()) // add SignedId value as a Cookie
          log.info(s"Failed to find Session: ${req.sessionId.toLogIdString} for Request: ${req.req}, " +
            s"allocating a new session: ${s.id.toLogIdString}, redirecting to location: ${res.location}")
        }
    }
}

/**
 * This filter acquires the access and then forwards the request to upstream service
 *
 * @param binder It binds to the upstream service endpoint using the info passed in ServiceIdentifier
 */
case class AccessFilter[A, B](binder: MBinder[ServiceIdentifier])(implicit statsReceiver: StatsReceiver)
    extends Filter[AccessIdRequest[A], Response, AccessRequest[A], AccessResponse[B]] {
  private[this] val log = Logger.get(getClass.getPackage.getName)
  private[this] val requestSends = statsReceiver.counter("upstream.service.request.sends")

  def apply(req: AccessIdRequest[A],
            accessService: Service[AccessRequest[A], AccessResponse[B]]): Future[Response] =
    accessService(AccessRequest(req.id, req.customerId, req.serviceId, req.sessionId)).flatMap(
      accessResp => binder(BindRequest(req.serviceId,
        tap(req.req) { r => {
          requestSends.incr
          log.debug(s"Send: ${req.req} for Session: ${req.sessionId.toLogIdString} " +
            s"to the protected upstream service: ${req.serviceId.name}")
          r.headerMap.add("Auth-Token", accessResp.access.access.toString)
        }})
      )
    )
}

/**
 * This filter rewrites Request Path as per the ServiceIdentifier configuration
 */
case class RewriteFilter() extends SimpleFilter[BorderRequest, Response] {
  def apply(req: BorderRequest,
            service: Service[BorderRequest, Response]): Future[Response] = {
    service(BorderRequest(tap(req.req) { r =>
      // Rewrite the URI (i.e. path)
      r.uri = req.serviceId.rewritePath.fold(r.uri)(p =>
        r.uri.replaceFirst(req.serviceId.path.toString, p.toString))
    }, req.customerId, req.serviceId, req.sessionId))
  }
}

/**
 * Top level filter that maps exceptions into appropriate status codes
 */
case class ExceptionFilter() extends SimpleFilter[Request, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)

  private[this] def warningAndResponse(msg: String, status: Status): Response = {
    log.warning(msg)
    tap(Response(status))(
      r => { r.contentString = msg; r.contentType = "text/plain" }
    )
  }

  /**
   * Tells the service how to handle certain types of servable errors (i.e. PetstoreError)
   */
  def errorHandler: PartialFunction[Throwable, Response] = {
    case error: SessionError => warningAndResponse(error.getMessage, Status.InternalServerError)
    case error: AccessDenied => warningAndResponse("AccessDenied: " + error.getMessage, error.status)
    case error: AccessIssuerError => warningAndResponse(error.getMessage, error.status)
    case error: IdentityProviderError => warningAndResponse(error.getMessage, error.status)
    case error: Exception =>
      log.error(error, error.getMessage)
      tap(Response(Status.InternalServerError))(
        r => { r.contentString = error.getMessage; r.contentType = "text/plain" }
      )
  }

  def apply(req: Request, service: Service[Request, Response]): Future[Response] =
    service(req) handle errorHandler
}
