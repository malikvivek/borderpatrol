package com.lookout.borderpatrol.auth

import com.lookout.borderpatrol.Binder.{BindRequest, MBinder}
import com.lookout.borderpatrol.util.Combinators._
import com.lookout.borderpatrol.{CustomerIdentifier, LoginManager, ServiceIdentifier, ServiceMatcher}
import com.lookout.borderpatrol.sessionx._
import com.twitter.finagle.http.path.{Root, Path}
import com.twitter.finagle.http.{Cookie, Status, Request, Response}
import com.twitter.finagle.stats.StatsReceiver
import com.twitter.finagle.{SimpleFilter, Service, Filter}
import com.twitter.logging.{Logger, Level}
import com.twitter.util.Future
import scala.util.{Failure, Success}

/**
 * PODs
 */
case class CustomerIdRequest(req: Request, customerId: CustomerIdentifier)
case class SessionIdRequest(req: Request, customerId: CustomerIdentifier, sessionId: SignedId)
object SessionIdRequest {
  def apply(sr: CustomerIdRequest, sid: SignedId): SessionIdRequest =
    SessionIdRequest(sr.req, sr.customerId, sid)
}
case class BorderRequest(req: Request, customerId: CustomerIdentifier, serviceId: ServiceIdentifier,
                            sessionId: SignedId)
object BorderRequest {
  def apply(br: SessionIdRequest, serviceId: ServiceIdentifier): BorderRequest =
    BorderRequest(br.req, br.customerId, serviceId, br.sessionId)
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
    req.host.flatMap(matcher.subdomain) match {
      case Some(cid) => {
        log.debug(s"Processing: Request(${req.method} " +
          s"${req.host.fold("null-hostname")(h => s"${h}${req.path}")}) " +
          s"with CustomerIdentifier: ${cid.subdomain}")
         service(CustomerIdRequest(req, cid))
      }
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
case class SessionIdFilter(store: SessionStore)(implicit secretStore: SecretStoreApi)
    extends Filter[CustomerIdRequest, Response, SessionIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)

  /**
   * Passes the SignedId to the next in the filter chain. If any failures decoding the SignedId occur
   * (expired, not there, etc), we will terminate early and send a redirect
   * @param req
   * @param service
   */
  def apply(req: CustomerIdRequest, service: Service[SessionIdRequest, Response]): Future[Response] =
    SignedId.fromRequest(req.req, SignedId.sessionIdCookieName) match {
      case Success(sessionId) => service(SessionIdRequest(req, sessionId))
      case Failure(e) =>
        for {
          session <- Session(req.req)
          _ <- store.update(session)
        } yield tap(Response(Status.Found)) { res =>
          /**
           * Session allocated, redirect to same location again (it could be unprotected and may not
           * need authentication)
           */
          res.location = req.req.uri
          res.addCookie(session.id.asCookie())
          log.debug(s"${req.req}, allocating a new session: " +
            s"${session.id.toLogIdString}, redirecting to location: ${res.location}")
        }
    }
}

/**
 * This is a border service that glues the main chain with
 * - unprotected upstream service chain
 * - identityProvider chain or
 * - accessIssuer chain
 *
 * E.g.
 * - If SignedId is authenticated
 *   - if path is NOT a service path, then return Status NotFound
 *   - if path is a service path, then send feed it into accessIssuer chain
 * - If SignedId is NOT authenticated
 *   - if path is NOT a LoginManager path, then redirect it to LoginManager path
 *   - if path is a LoginManager path, then feed it into identityProvider chain
 *
 * @param accessIssuerMap
 * @param identityProviderMap
 */
case class BorderService(identityProviderMap: Map[String, Service[BorderRequest, Response]],
                         accessIssuerMap: Map[String, Service[BorderRequest, Response]],
                         matcher: ServiceMatcher,
                         serviceBinder: MBinder[ServiceIdentifier])(implicit statsReceiver: StatsReceiver)
    extends Service[SessionIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)
  private[this] val requestSends = statsReceiver.counter("unprotected.upstream.service.request.sends")
  private[this] val unprotectedServiceChain = RewriteFilter() andThen Service.mk[BorderRequest, Response] {
    br => serviceBinder(BindRequest(br.serviceId, br.req)) }


  def sendToIdentityProvider(req: BorderRequest): Future[Response] = {
    log.debug(s"Send: ${req.req} for Session: ${req.sessionId.toLogIdString} " +
      s"to identity provider chain for service: ${req.serviceId.name}")
    identityProviderMap.get(req.customerId.loginManager.identityManager.name) match {
      case Some(ip) => ip(req)
      case None => throw IdentityProviderError(Status.NotFound, "Failed to find IdentityProvider Service Chain for " +
        req.customerId.loginManager.identityManager.name)
    }
  }

  def sendToAccessIssuer(req: BorderRequest): Future[Response] = {
    log.debug(s"Send: ${req.req} for Session: ${req.sessionId.toLogIdString} " +
      s"to access issuer chain for service: ${req.serviceId.name}")
    accessIssuerMap.get(req.customerId.loginManager.accessManager.name) match {
      case Some(ip) => ip(req)
      case None => throw AccessIssuerError(Status.NotFound, "Failed to find AccessIssuer Service Chain for " +
        req.customerId.loginManager.accessManager.name)
    }
  }

  def sendToUnprotectedService(req: BorderRequest): Future[Response] = {
    requestSends.incr
    log.debug(s"Send: ${req.req} for Session: ${req.sessionId.toLogIdString} " +
      s"to the unprotected upstream service: ${req.serviceId.name}")
    /* Route through a Rewrite filter */
    unprotectedServiceChain(req)
  }

  def redirectTo(location: String): Response =
    tap(Response(Status.Found))(res => res.location = location)

  def redirectToService(req: BorderRequest): Future[Response] = {
    log.debug(s"Redirecting the ${req.req} for Authenticated Session: ${req.sessionId.toLogIdString} " +
      s"to upstream service, location: ${req.serviceId.path}")
    redirectTo(req.serviceId.path.toString).toFuture
  }

  def redirectToLogin(req: SessionIdRequest): Future[Response] = {
    val path = req.customerId.loginManager.protoManager.redirectLocation(req.req.host)
    log.debug(s"Redirecting the ${req.req} for Untagged Session: ${req.sessionId.toLogIdString} " +
      s"to login service, location: ${path}")
    redirectTo(path).toFuture
  }

  /**
   * Matching order:
   * 1. Untagged/Authenticated, ServiceIdentifier NOT found, but path matches Root i.e. "/"
   * 2. Untagged, ServiceIdentifier found/Not, but path matches LoginManager confirm path
   * 3. Untagged/Authenticated, Unprotected ServiceIdentifier found
   * 4. Authenticated, protected ServiceIdentifier found
   * 5. Authenticated, ServiceIdentifier NOT found
   * 6. Untagged
   *
   * @param req
   * @return
   */
  def apply(req: SessionIdRequest): Future[Response] =
    (req.sessionId.tag, matcher.path(Path(req.req.path))) match {
      /* 1. redirect to default service */
      case (_, None) if Root.startsWith(Path(req.req.path)) =>
        redirectToService(BorderRequest(req, req.customerId.defaultServiceId))
      /* 2. dispatch to Identity Provider chain */
      case (Untagged, _) if req.customerId.isLoginManagerPath(Path(req.req.path)) =>
        sendToIdentityProvider(BorderRequest(req, req.customerId.defaultServiceId))
      /* 3. dispatch to unprotected service */
      case (_, Some(serviceId)) if !serviceId.protekted => sendToUnprotectedService(BorderRequest(req, serviceId))
      /* 4. dispatch to protected service via accessIssuer chain */
      case (AuthenticatedTag, Some(serviceId)) => sendToAccessIssuer(BorderRequest(req, serviceId))
      /* 5. return a NotFound */
      case (AuthenticatedTag, None) => Response(Status.NotFound).toFuture
      /* 6. redirect it to Login */
      case (Untagged, _) => redirectToLogin(req)
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
      case e => {
        log.warning(s"Failed to retrieve Identity for Session: ${sessionId.toLogIdString}, " +
          s"from sessionStore with: ${e.getMessage}")
        EmptyIdentity
      }
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
    case error: Exception => {
      log.error(error, error.getMessage)
      tap(Response(Status.InternalServerError))(
        r => { r.contentString = error.getMessage; r.contentType = "text/plain" }
      )
    }
  }

  def apply(req: Request, service: Service[Request, Response]): Future[Response] =
    service(req) handle errorHandler
}
