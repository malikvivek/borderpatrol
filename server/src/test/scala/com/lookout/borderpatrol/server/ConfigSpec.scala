package com.lookout.borderpatrol.server

import java.net.URL

import com.lookout.borderpatrol.sessionx._
import com.lookout.borderpatrol.test.{sessionx, BorderPatrolSuite}
import com.lookout.borderpatrol._
import com.twitter.finagle.memcached
import com.twitter.finagle.http.path.Path
import cats.data.Xor
import io.circe._
import io.circe.jawn._
import io.circe.generic.auto._
import io.circe.syntax._


class ConfigSpec extends BorderPatrolSuite {
  import sessionx.helpers._
  import Config._

  override def afterEach(): Unit = {
    try {
      super.afterEach() // To be stackable, must call super.afterEach
    }
    finally {
      BinderBase.clear
    }
  }

  // Stores
  val memcachedSessionStore = SessionStores.MemcachedStore(new memcached.MockClient())
  val consulSecretStore = SecretStores.ConsulSecretStore("testBpKey", Set(new URL("http://localhost:1234")))

  // Helpers
  def decodeCids(json: Json, sids: Set[ServiceIdentifier], lms: Set[LoginManager]) : Set[CustomerIdentifier] = {
    Decoder.decodeCanBuildFrom[CustomerIdentifier, Set](decodeCustomerIdentifier(
      sids.map(sid => sid.name -> sid).toMap, lms.map(l => l.name -> l).toMap), implicitly).decodeJson(json) match {
      //parse(s).flatMap { json => d(Cursor(json).hcursor) } match {
      case Xor.Right(a) => a
      case Xor.Left(b) => throw new Exception(b.getMessage)
    }
  }
  def decodeCid(json: Json, sids: Set[ServiceIdentifier], lms: Set[LoginManager]) : CustomerIdentifier = {
    decodeCustomerIdentifier(sids.map(sid => sid.name -> sid).toMap,
      lms.map(l => l.name -> l).toMap).decodeJson(json) match {
      //parse(s).flatMap { json => d(Cursor(json).hcursor) } match {
      case Xor.Right(a) => a
      case Xor.Left(b) => throw new Exception(b.getMessage)
    }
  }
  def decodeLms(json: Json, ims: Set[Manager], ams: Set[Manager]) : Set[LoginManager] = {
    Decoder.decodeCanBuildFrom[LoginManager, Set](decodeLoginManager(ims.map(im => im.name -> im).toMap,
      ams.map(am => am.name -> am).toMap), implicitly).decodeJson(json) match {
      case Xor.Right(a) => a
      case Xor.Left(b) => throw new Exception(b.getMessage)
    }
  }
  def decodeLm(json: Json, ims: Set[Manager], ams: Set[Manager]) : LoginManager = {
    decodeLoginManager(ims.map(im => im.name -> im).toMap,
      ams.map(am => am.name -> am).toMap).decodeJson(json) match {
    //parse(s).flatMap { json => d(Cursor(json).hcursor) } match {
      case Xor.Right(a) => a
      case Xor.Left(b) => throw new Exception(b.getMessage)
    }
  }

  behavior of "Config"

  it should "uphold encoding/decoding SecretStore" in {
    decodeSecretStore.decodeJson(defaultSecretStore.asInstanceOf[SecretStoreApi].asJson).toOption should
      be(Some(defaultSecretStore.asInstanceOf[SecretStoreApi]))
//    decodeSecretStore.decodeJson(consulSecretStore.asInstanceOf[SecretStoreApi].asJson).toOption should
//      be(Some(consulSecretStore.asInstanceOf[SecretStoreApi]))
    decodeSecretStore.decodeJson(Json.obj(("type", "InMemorySecretStore".asJson))).toOption should
      be(Some(defaultSecretStore.asInstanceOf[SecretStoreApi]))
    decodeSecretStore.decodeJson(Json.obj(("type", "ConsulSecretStore".asJson))).toOption should be(None)
    decodeSecretStore.decodeJson(Json.obj(("type", Json.string("woof")))).toOption should be(None)
  }

  it should "uphold encoding/decoding SessionStore" in {
    decodeSessionStore.decodeJson(defaultSessionStore.asInstanceOf[SessionStore].asJson).toOption should
      be(Some(defaultSessionStore.asInstanceOf[SessionStore]))
//    decodeSessionStore.decodeJson(memcachedSessionStore.asInstanceOf[SessionStore].asJson).toOption should
//      be(Some(memcachedSessionStore.asInstanceOf[SessionStore]))
    decodeSessionStore.decodeJson(Json.obj(("type", "InMemoryStore".asJson))).toOption should
      be(Some(defaultSessionStore.asInstanceOf[SessionStore]))
    decodeSessionStore.decodeJson(Json.obj(("type", "MemcachedStore".asJson))).toOption should be(None)
    decodeSessionStore.decodeJson(Json.obj(("type", Json.string("woof")))).toOption should be(None)
  }

  it should "uphold encoding/decoding ServiceIdentifier" in {
    def decodeFromJson(json: Json): ServiceIdentifier =
      decode[ServiceIdentifier](json.toString()) match {
        case Xor.Right(a) => a
        case Xor.Left(b) => ServiceIdentifier("failed", urls, Path("f"), None, false)
      }

    val partialContents = Json.fromFields(Seq(
      ("name", one.name.asJson),
      ("hosts", one.hosts.asJson),
      ("path", one.path.asJson)))
    decodeFromJson(one.asJson) should be(one)
    decodeFromJson(partialContents) should be(one)
    decodeFromJson(two.asJson) should be(two)
  }

  it should "uphold encoding/decoding CustomerIdentifier" in {
    decodeCid(cust1.asJson, sids, loginManagers) should be (cust1)
    decodeCid(cust2.asJson, sids, loginManagers) should be (cust2)
  }

  it should "uphold encoding/decoding Manager" in {
    def encodeDecode(m: Manager) : Manager = {
      val encoded = m.asJson
      decode[Manager](encoded.toString()) match {
        case Xor.Right(a) => a
        case Xor.Left(b) => Manager("failed", Path("f"), urls)
      }
    }
    encodeDecode(keymasterIdManager) should be (keymasterIdManager)
  }

  it should "uphold encoding/decoding LoginManager" in {
    decodeLm(checkpointLoginManager.asJson, Set(keymasterIdManager),
      Set(keymasterAccessManager)) should be (checkpointLoginManager)
    decodeLm(umbrellaLoginManager.asJson, Set(keymasterIdManager),
      Set(keymasterAccessManager)) should be (umbrellaLoginManager)
  }

  it should "raise a BpConfigError exception due to missing LoginManager in CustomerIdentifier config" in {
    val partialContents = Json.array(Json.fromFields(Seq(
        ("subdomain", "some".asJson),
        ("defaultServiceIdentifier", "one".asJson),
        ("loginManager", "bad".asJson))))

    val caught = the [Exception] thrownBy {
      decodeCids(partialContents, sids, loginManagers)
    }
    caught.getMessage should include ("LoginManager \"bad\" not found")
  }

  it should "raise a BpConfigError exception due to missing ServiceIdentifier in CustomerIdentifier config" in {
    val partialContents = Json.array(Json.fromFields(Seq(
        ("subdomain", "some".asJson),
        ("defaultServiceIdentifier", "bad".asJson),
        ("loginManager", "checkpoint".asJson))))

    val caught = the [Exception] thrownBy {
      decodeCids(partialContents, sids, loginManagers)
    }
    caught.getMessage should include ("ServiceIdentifier \"bad\" not found")
  }

  it should "succeed a BpConfigError exception if identityManager that is used in LoginManager is missing" in {
    val partialContents = loginManagers.asJson
    val caught = the [Exception] thrownBy {
      decodeLms(partialContents, Set(Manager("some", Path("/some"), urls)), Set(keymasterAccessManager))
    }
    caught.getMessage should include ("IdentityManager \"keymaster\" not found")
  }

  it should "raise a BpConfigError exception if identityManager that is used in LoginManager is missing" in {
    val partialContents = loginManagers.asJson
    val caught = the [Exception] thrownBy {
      decodeLms(partialContents, Set(Manager("some", Path("/some"), urls)), Set(keymasterAccessManager))
    }
    caught.getMessage should include ("IdentityManager \"keymaster\" not found")
  }

  it should "raise a BpConfigError exception if accessManager that is used in LoginManager is missing" in {
    val partialContents = loginManagers.asJson
    //println(partialContents)
    val caught = the [Exception] thrownBy {
      decodeLms(partialContents, Set(keymasterIdManager), Set(Manager("some", Path("/some"), urls)))
    }
    caught.getMessage should include ("AccessManager \"keymaster\" not found")
  }

  it should "raise a BpConfigError exception if duplicate are configured in idManagers config" in {
    val output = validateManagerConfig("identityManagers",
      Set(keymasterIdManager, Manager("keymaster", Path("/some"), urls)))
    output should contain ("Duplicate entries for key (name) are found in the field: identityManagers")
  }

  it should "raise a BpConfigError exception if duplicates are configured in accessManagers config" in {
    val output = validateManagerConfig("accessManagers",
      Set(keymasterAccessManager, Manager("keymaster", Path("/some"), urls)))
    output should contain ("Duplicate entries for key (name) are found in the field: accessManagers")
  }

  it should "raise a BpConfigError exception if duplicates are configured in loginManagers config" in {
    val output = validateLoginManagerConfig("loginManagers", loginManagers +
        LoginManager("checkpoint", keymasterIdManager, keymasterAccessManager,
          InternalAuthProtoManager("some", Path("/some"), Path("/some"))))
    output should contain ("Duplicate entries for key (name) are found in the field: loginManagers")
  }

  it should "raise a BpConfigError exception if duplicate paths are configured in serviceIdentifiers config" in {
    val output = validateServiceIdentifierConfig("serviceIdentifiers",
      sids + ServiceIdentifier("some", urls, Path("/ent"), None, false)
        + ServiceIdentifier("some", urls, Path("/some"), None, false))
    output should contain ("Duplicate entries for key (path) are found in the field: serviceIdentifiers")
  }

  it should "raise a BpConfigError exception if duplicate subdomains are configured in customerIdentifiers config" in {
    val output = validateCustomerIdentifierConfig("customerIdentifiers",
      cids + CustomerIdentifier("enterprise", two, checkpointLoginManager))
    output should contain ("Duplicate entries for key (subdomain) are found in the field: customerIdentifiers")
  }

  it should "validate Hosts configuration" in {
    val u1 = new URL("http://sample.com")
    val u2 = new URL("http://sample.com:8080/goto")
    val u3 = new URL("http://tample.com:2345/foo")
    val u4 = new URL("https://xample.com:2222")
    val u5 = new URL("https://ample.com:2221")
    val u11 = new URL("ftp://localhost:123")

    validateHostsConfig("some", "working1", Set(u1, u2)).isEmpty should be (true)
    validateHostsConfig("some", "working2", Set(u4)).isEmpty should be (true)
    validateHostsConfig("some", "failed1", Set(u3, u4)).mkString should include (
      "hosts configuration for failed1 in some: has differing protocols")
    validateHostsConfig("some", "failed2", Set(u11)).mkString should include (
      "hosts configuration for failed2 in some: has unsupported protocol")
    validateHostsConfig("some", "failed3", Set(u4, u5)).mkString should include (
      "hosts configuration for failed3 in some: https urls have mismatching hostnames")
  }
}
