package com.lookout.borderpatrol.test.sessionx

import java.net.URL

import com.lookout.borderpatrol.auth.OAuth2.OAuth2CodeVerify
import com.lookout.borderpatrol._
import com.lookout.borderpatrol.sessionx.SecretStores.InMemorySecretStore
import com.twitter.finagle.http.path.Path
import com.twitter.finagle.http.{RequestBuilder, Response, Request}
import com.twitter.finagle.stats.NullStatsReceiver
import com.twitter.io.Buf
import com.twitter.util._
import com.twitter.finagle.Service
import com.twitter.bijection.Injection
import com.twitter.util.{Await, Time}


object helpers {
  import com.lookout.borderpatrol.sessionx._
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
  val keymasterIdEndpoint = Endpoint("keymasterIdEndpoint", Path("/identityProvider"), urls)
  val keymasterAccessEndpoint = Endpoint("keymasterAccessEndpoint", Path("/accessIssuer"), urls)
  val ulmAuthorizeEndpoint = Endpoint("ulmAuthorizeEndpoint", Path("/authorize"), Set(new URL("http://example.com")))
  val ulmTokenEndpoint = Endpoint("ulmTokenEndpoint", Path("/token"), Set(new URL("http://localhost:4567")))
  val ulmCertificateEndpoint = Endpoint("ulmCertificateEndpoint", Path("/certificate"),
    Set(new URL("http://localhost:4567")))
  val rlmAuthorizeEndpoint = Endpoint("rlmAuthorizeEndpoint", Path("/authorize"),
    Set(new URL("http://localhost:9999")))
  val rlmTokenEndpoint = Endpoint("rlmTokenEndpoint", Path("/token"), Set(new URL("http://localhost:9999")))
  val rlmCertificateEndpoint = Endpoint("rlmCertificateEndpoint", Path("/certificate"),
    Set(new URL("http://localhost:9999")))
  val endpoints = Set(keymasterIdEndpoint, keymasterAccessEndpoint,
    ulmAuthorizeEndpoint, ulmTokenEndpoint, ulmCertificateEndpoint,
    rlmAuthorizeEndpoint, rlmTokenEndpoint, rlmCertificateEndpoint)

  val checkpointLoginManager = BasicLoginManager("checkpointLoginManager", "keymaster.basic", "cp-guid", Path("/loginConfirm"),
    Path("/check"), keymasterIdEndpoint, keymasterAccessEndpoint)

  val umbrellaLoginManager = OAuth2LoginManager("ulmLoginManager", "keymaster.oauth2", "ulm-guid", Path("/signin"),
    keymasterIdEndpoint, keymasterAccessEndpoint,
    ulmAuthorizeEndpoint, ulmTokenEndpoint, ulmCertificateEndpoint,
    "clientId", "clientSecret")

  val rainyLoginManager = OAuth2LoginManager("rlmProtoManager", "keymaster.oauth2", "rlm-guid", Path("/signblew"),
    keymasterIdEndpoint, keymasterAccessEndpoint,
    rlmAuthorizeEndpoint, rlmTokenEndpoint, rlmCertificateEndpoint,
    "clientId", "clientSecret")
  val loginManagers = Set(checkpointLoginManager.asInstanceOf[LoginManager],
    umbrellaLoginManager.asInstanceOf[LoginManager],
    rainyLoginManager.asInstanceOf[LoginManager])

  //  oAuth2 Code Verify object
  val oAuth2CodeVerify = new OAuth2CodeVerify

  // sids
  val one = ServiceIdentifier("one", urls, Path("/ent"), None, true)
  val oneTwo = ServiceIdentifier("oneTwo", urls, Path("/ent2"), None, true)
  val cust1 = CustomerIdentifier("enterprise", "cust1-guid", one, checkpointLoginManager)
  val two = ServiceIdentifier("two", urls, Path("/umb"), Some(Path("/broken/umb")), true)
  val cust2 = CustomerIdentifier("sky", "cust2-guid", two, umbrellaLoginManager)
  val three = ServiceIdentifier("three", urls, Path("/rain"), None, true)
  val cust3 = CustomerIdentifier("rainy", "cust3-guid", three, rainyLoginManager)
  val unproCheckpointSid = ServiceIdentifier("login", urls, Path("/check"), None, false)
  val proCheckpointSid = ServiceIdentifier("checkpoint", urls, Path("/check/that"), None, true)
  val cust4 = CustomerIdentifier("repeat", "cust4-guid", proCheckpointSid, checkpointLoginManager)
  val cids = Set(cust1, cust2, cust3, cust4)
  val sids = Set(one, oneTwo, two, three, proCheckpointSid, unproCheckpointSid)
  val serviceMatcher = ServiceMatcher(cids, sids)
  val sessionStore = SessionStores.InMemoryStore

  // Request helper
  def req(subdomain: String, path: String, params: Tuple2[String, String]*): Request =
    RequestBuilder().url(s"http://${subdomain + "."}example.com${Request.queryString(Path(path).toString,
      params:_*)}").buildGet()
  def reqPost(subdomain: String, path: String, content: Buf, params: Tuple2[String, String]*): Request =
    RequestBuilder().url(s"http://${subdomain + "."}example.com${Request.queryString(path, params:_*)}")
      .buildPost(content)
}
