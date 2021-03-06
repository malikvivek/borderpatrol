package com.lookout.borderpatrol.auth.tokenmaster

import java.net.URL
import com.lookout.borderpatrol.auth.{BorderRequest, BpForbiddenRequest, BpInvalidRequest}
import com.lookout.borderpatrol.{Endpoint, LoginManager}
import com.lookout.borderpatrol.util.Helpers
import com.lookout.borderpatrol.util.Combinators.tap
import com.twitter.finagle.http.{Method, Request, Response}
import com.twitter.finagle.http.path.Path
import com.twitter.logging.Logger
import com.twitter.util.Future


object LoginManagers {
  private[this] val log = Logger.get(getClass.getPackage.getName)

  /**
   * BasicAuthLoginManagerMixin
   *
   * A mixin to incorporate basic authentication functionality
   */
  trait BasicAuthLoginManagerMixin {
    val authorizePath: Path
    def redirectLocation(req: Request, params: Tuple2[String, String]*): String =
      Request.queryString(authorizePath.toString, params:_*)
  }

  /**
   * OAuth2LoginManagerMixin
   *
   * A mixin to incorporate OAuth2 authentication functionality
   */
  trait OAuth2LoginManagerMixin {
    val name: String
    val loginConfirm: Path
    val authorizeEndpoint: Endpoint
    val tokenEndpoint: Endpoint
    val certificateEndpoint: Endpoint
    val clientId: String
    val clientSecret: String

    def redirectLocation(req: Request, params: Tuple2[String, String]*): String = {
      val hostStr = req.host.getOrElse(throw BpInvalidRequest(s"Host not found in ${req}"))
      val scheme = req.headerMap.getOrElse("X-Forwarded-Proto", "http")
      val prompt = req.params.get("action") match {
        case Some(a) if a == "consent" => Map("prompt" -> "admin_consent")
        case _ => Map.empty[String, String]
      }
      /* Send URL with query string */
      val paramsMap = Map(("response_type", "code"), ("state", "foo"), ("client_id", clientId),
        ("redirect_uri", s"$scheme://$hostStr$loginConfirm")) ++ params ++ prompt

      authorizeEndpoint.hosts.headOption.fold("")(_.toString) +
        Request.queryString(authorizeEndpoint.path.toString, paramsMap)
    }

    def codeToToken(req: BorderRequest): Future[Response] = {
      val hostStr = req.req.host.getOrElse(throw BpInvalidRequest(s"Host not found in ${req.req}"))
      val scheme = req.req.headerMap.getOrElse("X-Forwarded-Proto", "http")
      val code = Helpers.scrubQueryParams(req.req.params, "code").fold {
        (Helpers.scrubQueryParams(req.req.params, "error"),
          Helpers.scrubQueryParams(req.req.params, "error_description")) match {
          case (Some(er), Some(erD)) =>
            throw BpForbiddenRequest(s"OAuth2 authentication failed with error: '$er: $erD'")
          case _ => throw BpForbiddenRequest(s"OAuth2 code not found in HTTP ${req.req}")
        }
      }(co => co)
      val request = tap(Request(Method.Post, tokenEndpoint.path.toString))(re => {
        re.contentType = "application/x-www-form-urlencoded"
        re.contentString = Request.queryString(("grant_type", "authorization_code"), ("client_id", clientId),
          ("code", code), ("redirect_uri", s"$scheme://$hostStr$loginConfirm"),
          ("client_secret", clientSecret), ("resource", "00000002-0000-0000-c000-000000000000"))
          .drop(1) /* Drop '?' */
      })
      log.debug(s"Sending: Request(GET ${tokenEndpoint.path}) to fetch tokens " +
        s"with SessionId: ${req.sessionId.toLogIdString}, " +
        s"IPAddress: '${req.req.xForwardedFor.getOrElse("No IP Address")}'" )
      tokenEndpoint.send(request)
    }
  }

  /**
   * Internal authentication, that merely redirects user to internal service that does the authentication
   *
   * @param name name of the login manager
   * @param guid
   * @param loginConfirm path owned by borderpatrol. The interal login form POSTs here
   * @param loggedOutUrl destination after the logout
   * @param authorizePath path of the internal login form
   * @param identityEndpoint endpoint that does identity provisioning for the cloud
   * @param accessEndpoint endpoint that does access issuing for the cloud
   */
  case class BasicLoginManager(name: String, tyfe: String, guid: String, loginConfirm: Path, loggedOutUrl: Option[URL],
                               authorizePath: Path, identityEndpoint: Endpoint, accessEndpoint: Endpoint)
      extends LoginManager with BasicAuthLoginManagerMixin

  /**
   * OAuth code framework, that redirects user to OAuth2 server.
   *
   * @param name name of the login manager
   * @param guid
   * @param loginConfirm path owned by borderpatrol. The OAuth2 server posts the oAuth2 code on this path
   * @param loggedOutUrl destination after the logout
   * @param identityEndpoint endpoint that does identity provisioning for the cloud
   * @param accessEndpoint endpoint that does access issuing for the cloud
   * @param authorizeEndpoint External endpoint of the OAuth2 service where client is redirected for authentication
   * @param tokenEndpoint External endpoint of the OAuth2 server to convert OAuth2 code to OAuth2 token
   * @param certificateEndpoint External endpoint of the OAuth2 server to fetch certificate to verify token signature
   * @param clientId Id used for communicating with OAuth2 server
   * @param clientSecret Secret used for communicating with OAuth2 server
   */
  case class OAuth2LoginManager(name: String, tyfe: String, guid: String, loginConfirm: Path, loggedOutUrl: Option[URL],
                                identityEndpoint: Endpoint, accessEndpoint: Endpoint, authorizeEndpoint: Endpoint,
                                tokenEndpoint: Endpoint, certificateEndpoint: Endpoint,
                                clientId: String, clientSecret: String)
      extends LoginManager with OAuth2LoginManagerMixin
}
