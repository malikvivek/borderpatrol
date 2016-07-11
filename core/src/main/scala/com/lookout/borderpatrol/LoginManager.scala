package com.lookout.borderpatrol

import java.net.URL

import com.twitter.finagle.http.Request
import com.twitter.finagle.http.path.Path


/**
 * Login Manager defines collections of variables and endpoints, which together defines a policy
 *
 * The customerIdentifier configuration picks the login manager appropriate for their cloud.
 */
trait LoginManager {
  val name: String
  val tyfe: String
  val guid: String
  val loginConfirm: Path
  val loggedOutUrl: Option[URL]
  val identityEndpoint: Endpoint
  val accessEndpoint: Endpoint
  def redirectLocation(req: Request, params: Tuple2[String, String]*): String
}
