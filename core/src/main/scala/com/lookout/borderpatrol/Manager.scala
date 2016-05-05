package com.lookout.borderpatrol

import java.net.URL

import com.twitter.finagle.http.Request
import com.twitter.finagle.http.path.Path


/**
 * Manager represents upstream access and identity managers
 * @param name name of the manager
 * @param path path to the manager
 * @param hosts endpoints for the manager
 */
case class Endpoint(name: String, path: Path, hosts: Set[URL])

/**
 * Login Manager defines various collections of the identity manager, access manager and proto manager.
 * The customerIdentifier configuration picks the login manager appropriate for their cloud.
 */
trait LoginManager {
  val name: String
  val tyfe: String
  val guid: String
  val loginConfirm: Path
  val identityEndpoint: Endpoint
  val accessEndpoint: Endpoint
  def redirectLocation(req: Request, params: Tuple2[String, String]*): String
}
