package com.lookout.borderpatrol

import java.net.URL
import com.twitter.finagle.http.{Method, Response, Request}
import com.twitter.finagle.http.path.Path
import com.twitter.logging.Logger
import com.twitter.util.Future

case class Manager(name: String, path: Path, hosts: Set[URL])

case class LoginManager(name: String, identityManager: Manager, accessManager: Manager,
                        protoManager: ProtoManager)

trait ProtoManager {
  val loginConfirm: Path
  def redirectLocation(host: Option[String]): String
  def isMatchingPath(p: Path): Boolean = Set(loginConfirm).filter(p.startsWith(_)).nonEmpty
}

case class InternalAuthProtoManager(loginConfirm: Path, authorizePath: Path)
    extends ProtoManager {
  def redirectLocation(host: Option[String]): String = authorizePath.toString
}

case class OAuth2CodeProtoManager(loginConfirm: Path, authorizeUrl: URL, tokenUrl: URL, certificateUrl: URL,
                                  clientId: String, clientSecret: String)
    extends ProtoManager{
  private[this] val log = Logger.get(getClass.getPackage.getName)

  def redirectLocation(host: Option[String]): String = {
    val hostStr = host.getOrElse(throw new Exception("Host not found in HTTP Request"))
    Request.queryString(authorizeUrl.toString, ("response_type", "code"), ("state", "foo"),
      ("client_id", clientId), ("redirect_uri", "http://" + hostStr + loginConfirm.toString))
  }
  def codeToToken(host: Option[String], code: String): Future[Response] = {
    val hostStr = host.getOrElse(throw new Exception("Host not found in HTTP Request"))
    val request = util.Combinators.tap(Request(Method.Post, tokenUrl.toString))(re => {
      re.contentType = "application/x-www-form-urlencoded"
      re.contentString = Request.queryString(("grant_type", "authorization_code"), ("client_id", clientId),
        ("code", code), ("redirect_uri", "http://" + hostStr + loginConfirm.toString),
        ("client_secret", clientSecret), ("resource", "00000002-0000-0000-c000-000000000000"))
        .drop(1) /* Drop '?' */
    })
    log.debug(s"Sending: ${request} to location: ${tokenUrl}")
    BinderBase.connect(tokenUrl.toString, Set(tokenUrl), request)
  }
}
