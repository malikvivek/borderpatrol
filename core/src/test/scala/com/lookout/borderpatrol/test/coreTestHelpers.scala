package com.lookout.borderpatrol.test

import java.net.URL

import com.lookout.borderpatrol._
import com.lookout.borderpatrol.sessionx._
import com.lookout.borderpatrol.sessionx.SecretStores.InMemorySecretStore
import com.twitter.finagle.http.path.Path
import com.twitter.finagle.http.{RequestBuilder, Request}
import com.twitter.finagle.stats.NullStatsReceiver
import com.twitter.io.Buf
import com.twitter.bijection.Injection
import com.twitter.util.{Await, Time}


object coreTestHelpers {
  import com.lookout.borderpatrol.crypto.Generator.{EntropyGenerator => Entropy}
  /**
   * Common usage of secrets across tests
   */
  object secrets {
    val current = Secret(Injection.short2BigEndian(1), Secret.currentExpiry, Entropy(16))
    val previous = Secret(Injection.short2BigEndian(2), Time.fromMilliseconds(0), Entropy(16))
    val invalid = Secret(Injection.short2BigEndian(3), Time.now, Entropy(16)) // not in store
    val testSecrets = Secrets(current, previous)
    val testExpiredSecrets = Secrets(invalid, previous)
  }
  implicit val secretStore = InMemorySecretStore(secrets.testSecrets)

  /**
   * Test stats receiver
   */
  implicit val bpTestStatsReceiver = NullStatsReceiver

  /**
   * Common usage of sessionid across tests
   */
  object sessionid {

    def untagged: SignedId = Await.result(SignedId.untagged)

    def authenticated: SignedId = Await.result(SignedId.authenticated)

    def expired: SignedId =
      SignedId(Time.fromMilliseconds(0), Entropy(16), secrets.current, Untagged)

    def invalid: SignedId = untagged.copy(entropy = Entropy(16))
  }

  object sessions {
    def create[A](a: A): Session[A] = Session(sessionid.untagged, a)
  }

  //  urls
  val urls = Set(new URL("http://localhost:5678"))
  val bpPort: Int = 8080

  //  endpoints
  val tokenmasterIdEndpoint = Endpoint("tokenmasterIdEndpoint", Path("/identityProvider"), urls)
  val tokenmasterAccessEndpoint = Endpoint("tokenmasterAccessEndpoint", Path("/accessIssuer"), urls)

  // Login Managers
  case object test1LoginManager extends LoginManager {
    val name: String = "test1LoginManager"
    val tyfe: String = "test1.type"
    val guid: String = "test1.guid"
    val loginConfirm: Path = Path("/test1/confirm")
    val identityEndpoint: Endpoint = tokenmasterIdEndpoint
    val accessEndpoint: Endpoint = tokenmasterAccessEndpoint
    def redirectLocation(req: Request, params: Tuple2[String, String]*): String = "/test1/redirect"
  }
  case object test2LoginManager extends LoginManager {
    val name: String = "test2LoginManager"
    val tyfe: String = "test2.type"
    val guid: String = "test2.guid"
    val loginConfirm: Path = Path("/test2/confirm")
    val identityEndpoint: Endpoint = tokenmasterIdEndpoint
    val accessEndpoint: Endpoint = tokenmasterAccessEndpoint
    def redirectLocation(req: Request, params: Tuple2[String, String]*): String = "/test2/redirect"
  }
  val loginManagers = Set(test1LoginManager.asInstanceOf[LoginManager],
    test2LoginManager.asInstanceOf[LoginManager])

  // sids
  val one = ServiceIdentifier("one", urls, Path("/ent"), None, true)
  val oneTwo = ServiceIdentifier("oneTwo", urls, Path("/ent2"), None, true)
  val two = ServiceIdentifier("two", urls, Path("/umb"), Some(Path("/broken/umb")), true)
  val three = ServiceIdentifier("three", urls, Path("/rain"), None, true)
  val unproCheckpointSid = ServiceIdentifier("login", urls, Path("/check"), None, false)
  val proCheckpointSid = ServiceIdentifier("checkpoint", urls, Path("/check/that"), None, true)

  // cids
  val cust1 = CustomerIdentifier("enterprise", "cust1-guid", one, test1LoginManager)
  val cust2 = CustomerIdentifier("sky", "cust2-guid", two, test2LoginManager)
  val cust3 = CustomerIdentifier("rainy", "cust3-guid", three, test2LoginManager)
  val cust4 = CustomerIdentifier("repeat", "cust4-guid", proCheckpointSid, test1LoginManager)

  // Matcher
  val cids = Set(cust1, cust2, cust3, cust4)
  val sids = Set(one, oneTwo, two, three, proCheckpointSid, unproCheckpointSid)
  val serviceMatcher = ServiceMatcher(cids, sids)

  // Store
  val sessionStore = SessionStores.InMemoryStore

  // Request helper
  def req(subdomain: String, path: String, params: Tuple2[String, String]*): Request =
    RequestBuilder().url(s"http://${subdomain + "."}example.com${Request.queryString(Path(path).toString,
      params:_*)}").buildGet()
  def reqPost(subdomain: String, path: String, content: Buf, params: Tuple2[String, String]*): Request =
    RequestBuilder().url(s"http://${subdomain + "."}example.com${Request.queryString(path, params:_*)}")
      .buildPost(content)
}
