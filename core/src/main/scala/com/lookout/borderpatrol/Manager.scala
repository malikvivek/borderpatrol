package com.lookout.borderpatrol

import java.net.URL
import com.twitter.finagle.http.{Method, Response, Request}
import com.twitter.finagle.http.path.Path
import com.twitter.logging.Logger
import com.twitter.util.Future

/**
 * Manager represents upstream access and identity managers
 * @param name name of the manager
 * @param path path to the manager
 * @param hosts endpoints for the manager
 */
case class Manager(name: String, path: Path, hosts: Set[URL])

/**
 * Login Manager defines various collections of the identity manager, access manager and proto manager.
 * The customerIdentifier configuration picks the login manager appropriate for their cloud.
 *
 * @param name name of the login manager
 * @param identityManager identity manager used by the given login manager
 * @param accessManager access manager
 * @param protoManager protocol used by the login manager
 */
case class LoginManager(name: String, identityManager: Manager, accessManager: Manager,
                        protoManager: ProtoManager)

/**
 * ProtoManager defines parameters specific to the protocol
 */
trait ProtoManager {
  val loginConfirm: Path
  val loggedOutUrl: Option[URL]
  def redirectLocation: String
  def isMatchingPath(p: Path): Boolean = Set(loginConfirm).filter(p.startsWith(_)).nonEmpty
}

/**
 * Internal authentication, that merely redirects user to internal service that does the authentication
 *
 * @param loginConfirm path intercepted by bordetpatrol and internal authentication service posts
 *                     the authentication response on this path
 * @param authorizePath path of the internal authentication service where client is redirected
 * @param loggedOutUrl A url where user is redirected after the Logout
 */
case class InternalAuthProtoManager(loginConfirm: Path, authorizePath: Path, loggedOutUrl: Option[URL])
    extends ProtoManager {
  def redirectLocation: String = authorizePath.toString
}

/**
 * OAuth code framework, that redirects user to OAuth2 server.
 *
 * @param bpExternalEndpoint Externally visible BorderPatrol URL
 * @param loginConfirm path intercepted by borderpatrol and OAuth2 server posts the oAuth2 code on this path
 * @param authorizeUrl URL of the OAuth2 service where client is redirected for authenticaiton
 * @param tokenUrl URL of the OAuth2 server to convert OAuth2 code to OAuth2 token
 * @param certificateUrl URL of the OAuth2 server to fetch the certificate for verifying token signature
 * @param loggedOutUrl A Url where user is redirected after the Logout
 * @param clientId Id used for communicating with OAuth2 server
 * @param clientSecret Secret used for communicating with OAuth2 server
 */
case class OAuth2CodeProtoManager(bpExternalEndpoint: URL, loginConfirm: Path, authorizeUrl: URL, tokenUrl: URL,
                                  certificateUrl: URL, loggedOutUrl: Option[URL], clientId: String,
                                  clientSecret: String)
    extends ProtoManager{
  private[this] val log = Logger.get(getClass.getPackage.getName)

  def redirectLocation: String =
    Request.queryString(authorizeUrl.toString, ("response_type", "code"), ("state", "foo"),
      ("client_id", clientId),
      ("redirect_uri", s"$bpExternalEndpoint$loginConfirm"))

  def codeToToken(code: String): Future[Response] = {
    val request = util.Combinators.tap(Request(Method.Post, tokenUrl.toString))(re => {
      re.contentType = "application/x-www-form-urlencoded"
      re.contentString = Request.queryString(("grant_type", "authorization_code"), ("client_id", clientId),
        ("code", code),
        ("redirect_uri", s"$bpExternalEndpoint$loginConfirm"),
        ("client_secret", clientSecret), ("resource", "00000002-0000-0000-c000-000000000000"))
        .drop(1) /* Drop '?' */
    })
    log.debug(s"Sending: ${request} to location: ${tokenUrl}")
    BinderBase.connect(tokenUrl.toString, Set(tokenUrl), request)
  }
}
