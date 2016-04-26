package com.lookout.borderpatrol.auth

import com.lookout.borderpatrol.{ServiceMatcher, ServiceIdentifier, CustomerIdentifier}
import com.lookout.borderpatrol.{Binder, BpCoreError}
import com.lookout.borderpatrol.util.Combinators._
import com.lookout.borderpatrol.errors.{BpBorderError, BpNotFoundRequest}
import com.lookout.borderpatrol.util.Helpers
import com.lookout.borderpatrol.sessionx._
import com.twitter.finagle.http.path.{Root, Path}
import com.twitter.finagle.http._
import com.twitter.finagle.stats.StatsReceiver
import com.twitter.finagle.{SimpleFilter, Service, Filter}
import com.twitter.logging.Logger
import com.twitter.util.Future
import io.circe.Json
import io.circe.syntax._
import org.jboss.netty.handler.codec.http.QueryStringDecoder

import scala.util.{Try, Failure, Success}


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

object BorderAuth {
  private[this] val log = Logger.get(getClass.getPackage.getName)

  private[this] def expectsJson(req: Request): Boolean = {
    val decoder = Try(new QueryStringDecoder(req.uri)).toOption
    decoder.exists(_.getPath.endsWith(".json")) ||
      req.headerMap.get("Accept").exists(_.contains(MediaType.Json))
  }

  /* Convert a redirect into a response palatable to the client */
  def formatRedirectResponse(req: Request, status: Status, location: String, sessionIdOpt: Option[SignedId],
                             msg: String): Response = {
    log.info(msg)
    tap(Response())(res => {
      sessionIdOpt.foreach(sessionId => res.addCookie(sessionId.asCookie()))
      expectsJson(req) match {
        case true =>
          res.status = status
          res.contentString = Json.fromFields(Seq(
            ("msg_source", "borderpatrol".asJson),
            ("redirect_url", location.asJson))).toString()
          res.setContentTypeJson()
        case _ =>
          // Change the Status to be 302
          res.status = Status.Found
          res.location = location
          res.contentType = "text/plain"
      }})
  }

  /* Convert this error into a response appropriate to the client */
  def formatLogoutResponse(req: Request, status: Status, location: String, msg: String): Response = {
    log.info(msg)
    tap(Response())(res => {
      // Expire all BP cookies present in the Request
      req.cookies.foreach[Unit] {
        case (name: String, cookie: Cookie) if name.startsWith("border_") =>
          res.addCookie(SignedId.toExpiredCookie(name))
        case _ =>
      }
      expectsJson(req) match {
        case true =>
          res.status = status
          res.contentString = Json.fromFields(Seq(
            ("msg_source", "borderpatrol".asJson),
            ("redirect_url", location.asJson))).toString()
          res.setContentTypeJson()
        case _ =>
          res.status = Status.Found
          res.location = location
          res.contentType = "text/plain"
          println(s"***$location")
      }})
  }
}
/**
 * Determines the service that the request is trying to contact
 * If the service doesn't exist, it returns a 404 Not Found response
 *
 * @param matcher
 */
case class CustomerIdFilter(matcher: ServiceMatcher)(implicit statsReceiver: StatsReceiver)
    extends Filter[Request, Response, CustomerIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)

  def apply(req: Request, service: Service[CustomerIdRequest, Response]): Future[Response] = {
    for {
      custIdOpt <- Future.value(req.host.flatMap(matcher.customerId))
      resp <- custIdOpt match {
        case None => Future.exception(new BpNotFoundRequest("Failed to find CustomerIdentifier for " +
          s"Request(${req.method}, ${req.host.fold("null-hostname")(h => s"$h${req.path}")})"))
        case Some(cid) =>
          log.debug(s"Processing: Request(${req.method}, ${req.host.get}${req.path} " +
            s"with CustomerIdentifier: ${cid.subdomain}")
          service(CustomerIdRequest(req, cid))
      }
    } yield resp
  }
}

/**
 * Ensures we have a SignedId present in this request, sending a Redirect to the service login page if it doesn't
 */
case class SessionIdFilter(matcher: ServiceMatcher, store: SessionStore)(
  implicit secretStore: SecretStoreApi, statsReceiver: StatsReceiver)
    extends Filter[CustomerIdRequest, Response, SessionIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)
  private[this] val statSessionNotFound = statsReceiver.counter("req.session.id.notfound")

  /**
   * Passes the SignedId to the next in the filter chain. If any failures decoding the SignedId occur
   * (expired, not there, etc), we will terminate early and send a redirect
   * @param req
   * @param service
   */
  def apply(req: CustomerIdRequest, service: Service[SessionIdRequest, Response]): Future[Response] = {
    for {
      sessionIdOpt <- Future.value(SignedId.fromRequest(req.req, SignedId.sessionIdCookieName) match {
        case Success(s) => Some(s)
        case Failure(e) =>
          statSessionNotFound.incr()
          log.debug(s"Did not find the sessionId in ${req.req}, reason: ${e.getMessage}")
          None
      })
      serviceIdOpt <- Future.value(matcher.serviceId(Path(req.req.path)))
      resp <- service(SessionIdRequest(req, serviceIdOpt, sessionIdOpt))
    } yield resp
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
                                  store: SessionStore)(
  implicit secretStore: SecretStoreApi, statsReceiver: StatsReceiver)
    extends SimpleFilter[SessionIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)
  private[this] val statLoginRedirects = statsReceiver.counter("req.login.required.redirects")
  private[this] val statIdentityProvider = statsReceiver.counter("req.identity.provider.forwards")

  def sendToIdentityProvider(req: BorderRequest): Future[Response] = {
    log.debug(s"Send: ${req.req} for Session: ${req.sessionId.toLogIdString} " +
      s"to identity provider chain for service: ${req.serviceId.name}")
    identityProviderMap.get(req.customerId.loginManager.tyfe) match {
      case Some(ip) => statIdentityProvider.incr(); ip(req)
      case None => Future.exception(BpIdentityProviderError(Status.NotFound,
        s"Failed to find IdentityProvider Service Chain for loginManager type: ${req.customerId.loginManager.tyfe}"))
    }
  }

  /**
   * Generate a redirect error
   */
  def redirectToLogin(req: SessionIdRequest, sessionIdOpt: Option[SignedId]): Future[Response] = {
    for {
      location <- req.customerId.loginManager.redirectLocation(req.req).toFuture
      sessionId <- sessionIdOpt match {
        case Some(sessionId) => sessionId.toFuture
        case None =>
          /** Allocate a new sessionId */
          for {
            session <- Session(req.req)
            _ <- store.update(session)
          } yield session.id
      }
    } yield {
        statLoginRedirects.incr()
        BorderAuth.formatRedirectResponse(req.req, Status.Unauthorized, location, Some(sessionId),
          s"Redirecting the ${req.req} for Untagged Session: ${sessionId.toLogIdString} " +
            s"to login service, location: ${location}")
      }
  }

  def apply(req: SessionIdRequest, service: Service[SessionIdRequest, Response]): Future[Response] = {
    (req.sessionIdOpt.map(_.tag), req.serviceIdOpt) match {

      /* 1. loginConfirm path w/ untagged SessionId, dispatch to Identity Provider chain */
      case (Some(Untagged), _)
        if Path(req.req.path).startsWith(req.customerId.loginManager.loginConfirm) => {
        sendToIdentityProvider(BorderRequest(req, req.customerId.defaultServiceId, req.sessionIdOpt.get))
      }

      /**
       * 2. POST to loginConfirm path w/o SessionId, allocate SessionId, dispatch to Identity Provider chain
       *    It creates default request on the fly and for location it uses defaultServiceId or destination param
       */
      case (None, _)
        if Path(req.req.path).startsWith(req.customerId.loginManager.loginConfirm) => {
        val location = Helpers.scrubQueryParams(req.req.params, "destination")
          .getOrElse(req.customerId.defaultServiceId.path.toString)
        for {
          sessionId <- SignedId.untagged
          session <- Session(sessionId, Request(location)).toFuture
          _ <- store.update(session)
          resp <- sendToIdentityProvider(BorderRequest(req, req.customerId.defaultServiceId, sessionId))
        } yield resp
      }

      /* 3. Request w/ untagged SessionId, protected Service, redirect it to Login */
      case (Some(Untagged), Some(serviceId)) if serviceId.protekted => redirectToLogin(req, req.sessionIdOpt)

      /* 4. Request w/ untagged SessionId, no Service, redirect it to Login */
      case (Some(Untagged), None) => redirectToLogin(req, req.sessionIdOpt)

      /* 5. Request w/o SessionId, protected Service, redirect it to Login */
      case (None, Some(serviceId)) if serviceId.protekted => redirectToLogin(req, None)

      /* 5. Request w/o SessionId, no Service, redirect it to Login */
      case (None, None) => redirectToLogin(req, None)

      /* Everything else */
      case _ => service(req)
    }
  }
}

/**
 * Send the request on AccessIssuer chain
 *
 * This filter only deals with Authenticated SessionIds or forwards it to next filter
 *
 * @param accessIssuerMap
 */
case class SendToAccessIssuer(accessIssuerMap: Map[String, Service[BorderRequest, Response]])(
  implicit statsReceiver: StatsReceiver)
    extends SimpleFilter[SessionIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)
  private[this] val statAccessIssuer = statsReceiver.counter("req.access.issuer.forwards")

  def sendToAccessIssuer(req: BorderRequest): Future[Response] = {
    log.debug(s"Send: ${req.req} for Session: ${req.sessionId.toLogIdString} " +
      s"to access issuer chain for service: ${req.serviceId.name}")
    accessIssuerMap.get(req.customerId.loginManager.tyfe) match {
      case Some(ip) => statAccessIssuer.incr(); ip(req)
      case None => Future.exception(BpAccessIssuerError(Status.NotFound,
        s"Failed to find AccessIssuer Service Chain for loginManager type: ${req.customerId.loginManager.tyfe}"))
    }
  }

  def apply(req: SessionIdRequest, service: Service[SessionIdRequest, Response]): Future[Response] = {
    (req.sessionIdOpt.map(_.tag), req.serviceIdOpt) match {

      /* 1. Request for protected service w/ authenticated Sessionid, dispatch via accessIssuer chain */
      case (Some(AuthenticatedTag), Some(serviceId)) if serviceId.protekted =>
        sendToAccessIssuer(BorderRequest(req, serviceId, req.sessionIdOpt.get))

      /* 2. Request for Root w/ authenticated Sessionid, redirect to default service */
      case (Some(AuthenticatedTag), None) if Root.startsWith(Path(req.req.path)) =>
        BorderAuth.formatRedirectResponse(req.req, Status.NotFound, req.customerId.defaultServiceId.path.toString,
          req.sessionIdOpt,
          s"Redirecting the ${req.req} for Authenticated Session: ${req.sessionIdOpt.get.toLogIdString} " +
            s"to upstream service, location: ${req.customerId.defaultServiceId.path}").toFuture

      /* Everything else */
      case _ => service(req)
    }
  }
}

/**
 * Send the request to Unprotected Service
 *
 * This filter only deals with the Request has SessionId (Authenticate or Untagged) and destined to unprotected
 * Service. Everything else is forwarded to the next filter in the chain.
 *
 * @param store
 * @param secretStore
 * @param statsReceiver
 */
case class SendToUnprotectedService(store: SessionStore)
                                   (implicit secretStore: SecretStoreApi, statsReceiver: StatsReceiver)
    extends SimpleFilter[SessionIdRequest, Response] {
  private[this] val log = Logger.get(getClass.getPackage.getName)
  private[this] val statRequestSends = statsReceiver.counter("req.unprotected.upstream.service.forwards")
  private[this] val unprotectedServiceChain = RewriteFilter() andThen Service.mk[BorderRequest, Response] {
    br => Binder.connect(br.serviceId.endpoint, br.req) }

  def sendToUnprotectedService(req: BorderRequest): Future[Response] = {
    statRequestSends.incr
    log.debug(s"Send: ${req.req} for Session: ${req.sessionId.toLogIdString} " +
      s"to the unprotected upstream service: ${req.serviceId.name}")
    /* Route through a Rewrite filter */
    unprotectedServiceChain(req)
  }

  def apply(req: SessionIdRequest, service: Service[SessionIdRequest, Response]): Future[Response] =
    (req.sessionIdOpt, req.serviceIdOpt) match {

      /* 1. Request w/ SessionId, dispatch to unprotected service */
      case (Some(sessionId), Some(serviceId)) if !serviceId.protekted =>
        sendToUnprotectedService(BorderRequest(req, serviceId, sessionId))

      /* 1. Request w/o SessionId, dispatch to unprotected service */
      case (None, Some(serviceId)) if !serviceId.protekted =>
        for {
          sessionId <- SignedId.untagged
          session <- Session(sessionId, Request(req.customerId.defaultServiceId.path.toString)).toFuture
          _ <- store.update(session)
          resp <- sendToUnprotectedService(BorderRequest(req, serviceId, sessionId))
          _ <- (resp.addCookie(sessionId.asCookie())).toFuture
        } yield resp

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
    // Redirect to suggested url or the logged out path or default service
    val location = Helpers.scrubQueryParams(req.req.params, "destination")
      .fold(req.customerId.defaultServiceId.path.toString)(_.toString)

    BorderAuth.formatLogoutResponse(req.req, Status.Ok, location,
      s"After logout, redirecting to: $location").toFuture
  }
}

/**
 * Determines the identity of the requester, if no identity it responds with a redirect to the login page for that
 * service
 */
case class IdentityFilter[A : SessionDataEncoder](store: SessionStore)(
  implicit secretStore: SecretStoreApi, statsReceiver: StatsReceiver)
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

  def apply(req: BorderRequest, service: Service[AccessIdRequest[A], Response]): Future[Response] = {
    identity(req.sessionId).flatMap {
      case id: Id[A] => service(AccessIdRequest(req, id))
      case EmptyIdentity => for {
        session <- Session(req.req)
        _ <- store.update(session)
      } yield {
        val location = req.customerId.loginManager.redirectLocation(req.req)
        BorderAuth.formatRedirectResponse(req.req, Status.Unauthorized, location, Some(session.id),
          s"Failed to find Session: ${req.sessionId.toLogIdString} for: ${req.req}, " +
            s"allocating a new session: ${session.id.toLogIdString}, redirecting to location: ${location}")
      }
    }
  }
}

/**
 * This filter acquires the access and then forwards the request to upstream service
 *
 */
case class AccessFilter[A, B](implicit statsReceiver: StatsReceiver)
    extends Filter[AccessIdRequest[A], Response, AccessRequest[A], AccessResponse[B]] {
  private[this] val log = Logger.get(getClass.getPackage.getName)
  private[this] val statRequestSends = statsReceiver.counter("req.upstream.service.request.forwards")

  def apply(req: AccessIdRequest[A],
            accessService: Service[AccessRequest[A], AccessResponse[B]]): Future[Response] = {
    for {
      accessResp <- accessService(AccessRequest(req.id, req.customerId, req.serviceId, req.sessionId))
      resp <- Binder.connect(req.serviceId.endpoint,
        tap(req.req) { r =>
          statRequestSends.incr
          log.debug(s"Send: ${req.req} for Session: ${req.sessionId.toLogIdString} " +
            s"to the protected upstream service: ${req.serviceId.name}")
          r.headerMap.add("Auth-Token", accessResp.access.access.toString)
        }
      )
    } yield resp
  }
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

  /**
   * Determines if the client expects to receive `application/json` content type.
   */
  private[this] def expectsJson(req: Request): Boolean = {
    val decoder = Try(new QueryStringDecoder(req.uri)).toOption
    decoder.exists(_.getPath.endsWith(".json")) ||
      req.headerMap.get("Accept").exists(_.contains(MediaType.Json))
  }

  private[this] def warningAndResponse(req: Request, msg: String, status: Status): Response = {
    log.warning(msg)
    tap(Response(status))(res => {
      expectsJson(req) match {
        case true =>
          res.contentString = Json.fromFields(Seq(
            ("msg_source", "borderpatrol".asJson))).toString()
          res.contentType = "application/json"
        case _ =>
          res.contentType = "text/plain"
      }
    })
  }

  /**
   * Tells the service how to handle certain types of servable errors (i.e. PetstoreError)
   */
  def errorHandler(req: Request): PartialFunction[Throwable, Response] = {
    case error: BpAccessIssuerError => warningAndResponse(req, error.getMessage, error.status)
    case error: BpIdentityProviderError => warningAndResponse(req, error.getMessage, error.status)
    case error: BpBorderError => warningAndResponse(req, error.getMessage, error.status)
    case error: BpCoreError => warningAndResponse(req, error.getMessage, Status.InternalServerError)
    case error: BpSessionError => warningAndResponse(req, error.getMessage, Status.InternalServerError)
    case error: BpAuthError => warningAndResponse(req, error.getMessage, Status.InternalServerError)
    case error: Exception => warningAndResponse(req, error.getMessage, Status.InternalServerError)
  }

  def apply(req: Request, service: Service[Request, Response]): Future[Response] = {
    service(req) handle errorHandler(req)
  }
}
