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
import scala.reflect.io.File


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

  // StatdExporter
  val defaultStatsdExporterConfig = StatsdExporterConfig("host", 300, "prefix")

  // HealthCheckUrlsConfig
  val healthCheckUrls = Set(HealthCheckUrlConfig("node1", new URL("http://localhost:1234")))

  // Configs
  val serverConfig = ServerConfig(bpPort, defaultSecretStore, defaultSessionStore, defaultStatsdExporterConfig,
    healthCheckUrls, cids, sids, loginManagers, Set(keymasterIdManager), Set(keymasterAccessManager))
  val serverConfig1 = ServerConfig(bpPort, consulSecretStore, memcachedSessionStore, defaultStatsdExporterConfig,
    healthCheckUrls, cids, sids, loginManagers, Set(keymasterIdManager), Set(keymasterAccessManager))

  // Verify
  def verifyServerConfig(a: ServerConfig, b: ServerConfig): Unit = {
    a.secretStore.getClass should be (b.secretStore.getClass)
    a.sessionStore.getClass should be (b.sessionStore.getClass)
    assert(a.customerIdentifiers == b.customerIdentifiers)
    assert(a.serviceIdentifiers == b.serviceIdentifiers)
    assert(a.loginManagers == b.loginManagers)
    assert(a.identityManagers == b.identityManagers)
    assert(a.accessManagers == b.accessManagers)
  }

  behavior of "Config"

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
    def decode(s: String) : CustomerIdentifier = {
      implicit val d = decodeCustomerIdentifier(sids.map(sid => sid.name -> sid).toMap,
        loginManagers.map(l => l.name -> l).toMap)
      val out = parse(s).flatMap { json => d(Cursor(json).hcursor) }
      out match {
        case Xor.Right(a) => a
        case Xor.Left(b) => CustomerIdentifier("failed", one, checkpointLoginManager)
      }
    }

    decode(cust1.asJson.toString) should be (cust1)
    decode(cust2.asJson.toString) should be (cust2)
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

  it should "uphold encoding/decoding ServerConfig" in {
    def encodeDecode(config: ServerConfig): ServerConfig = {
      val encoded = config.asJson
      decode[ServerConfig](encoded.toString()) match {
        case Xor.Right(a) => a
        case Xor.Left(b) => ServerConfig(bpPort, defaultSecretStore, defaultSessionStore,
          defaultStatsdExporterConfig, Set(), Set(), Set(), Set(), Set(), Set())
      }
    }
    verifyServerConfig(encodeDecode(serverConfig), serverConfig)
    verifyServerConfig(encodeDecode(serverConfig1), serverConfig1)
  }

  it should "find managers and loginManagers by name" in {
    serverConfig.findLoginManager("checkpoint") should be(checkpointLoginManager)
    serverConfig.findIdentityManager("keymaster") should be(keymasterIdManager)
    serverConfig.findAccessManager("keymaster") should be(keymasterAccessManager)
    serverConfig.findServiceIdentifier("one") should be(one)
    the[BpInvalidConfigError] thrownBy {
      serverConfig.findLoginManager("foo")
    }
    the[BpInvalidConfigError] thrownBy {
      serverConfig.findIdentityManager("foo")
    }
    the[BpInvalidConfigError] thrownBy {
      serverConfig.findAccessManager("foo")
    }
    the[BpInvalidConfigError] thrownBy {
      serverConfig.findServiceIdentifier("foo")
    }
  }

  it should "succeed to build a valid ServerConfig from a file with valid contents" in {
    val validContents = serverConfig.asJson.toString()
    val tempValidFile = File.makeTemp("ServerConfigValid", ".tmp")
    tempValidFile.writeAll(validContents)

    val readConfig = readServerConfig(tempValidFile.toCanonical.toString)
    verifyServerConfig(readConfig, serverConfig)
  }

  it should "fail and raise an exception while reading from a file with invalid contents" in {
    val invalidContents = """[{"name":"one","path": {"str" :"customer1"},"subdomain":"customer1","login":"/login"}]"""
    val tempInvalidFile = File.makeTemp("ServerConfigSpecInvalid", ".tmp")
    tempInvalidFile.writeAll(invalidContents)
    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempInvalidFile.toCanonical.toString)
    }
    caught.getMessage should include ("failed to decode following field(s): listeningPort")
  }

  it should "raise a BpConfigError exception due to lack of listeningPort config" in {
    val partialContents = Json.fromFields(Seq(
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", cids.asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", Set(checkpointLoginManager).asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include ("failed to decode following field(s): listeningPort")
  }

  it should "raise a BpConfigError exception due to lack of Secret Store config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", cids.asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", Set(checkpointLoginManager).asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include ("failed to decode following field(s): secretStore")
  }

  it should "raise a BpConfigError exception due to invalid of Secret Store config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", Json.obj(("type", Json.string("woof")))),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", cids.asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", Set(checkpointLoginManager).asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include ("Invalid secretStore:failed to decode following field(s): secretStore")
  }

  it should "raise a BpConfigError exception due to lack of Session Store config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", consulSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", cids.asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", Set(checkpointLoginManager).asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include ("failed to decode following field(s): sessionStore")
  }

  it should "raise a BpConfigError exception due to invalid Session Store config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", consulSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", Json.obj(("type", Json.string("woof")))),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", cids.asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", Set(checkpointLoginManager).asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include ("Invalid sessionStore:failed to decode following field(s): sessionStore")
  }

  it should "raise a BpConfigError exception due to lack of Statsd Reporter config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("customerIdentifiers", cids.asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", Set(checkpointLoginManager).asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include ("failed to decode following field(s): statsdReporter")
  }

  it should "raise a BpConfigError exception due to lack of CustomerIdentifier config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", Set(checkpointLoginManager).asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include ("failed to decode following field(s): customerIdentifiers")
  }

  it should "raise a BpConfigError exception due to missing LoginManager in CustomerIdentifier config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("healthCheckUrls", healthCheckUrls.asJson),
      ("customerIdentifiers", Json.array(Json.fromFields(Seq(
        ("subdomain", "some".asJson),
        ("defaultServiceIdentifier", "one".asJson),
        ("loginManager", "bad".asJson))))),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", Set(checkpointLoginManager).asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include (
      "LoginManager \"bad\" not found:failed to decode following field(s): customerIdentifiers")
  }

  it should "raise a BpConfigError exception due to missing ServiceIdentifier in CustomerIdentifier config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", Json.array(Json.fromFields(Seq(
        ("subdomain", "some".asJson),
        ("defaultServiceIdentifier", "bad".asJson),
        ("loginManager", "checkpoint".asJson))))),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", Set(checkpointLoginManager).asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include (
      "ServiceIdentifier \"bad\" not found:failed to decode following field(s): customerIdentifiers")
  }

  it should "raise a BpConfigError exception due to lack of ServiceIdentifier config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", cids.asJson),
      ("loginManagers", Set(checkpointLoginManager).asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include ("failed to decode following field(s): serviceIdentifiers")
  }

  it should "raise a BpConfigError exception if identityManager that is used in LoginManager is missing" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", cids.asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", Set(checkpointLoginManager).asJson),
      ("identityManagers", Set(Manager("some", Path("/some"), urls)).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include (
      "IdentityManager \"keymaster\" not found:failed to decode following field(s): loginManagers")
  }

  it should "raise a BpConfigError exception if duplicate are configured in idManagers config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", cids.asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", loginManagers.asJson),
      ("identityManagers", Set(keymasterIdManager,
        Manager("keymaster", Path("/some"), urls)).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include ("Duplicate entries for key (name) are found in the field: identityManagers")
  }

  it should "raise a BpConfigError exception if accessManager that is used in LoginManager is missing" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", cids.asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", Set(checkpointLoginManager).asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(Manager("some", Path("/some"), urls)).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include (
      "AccessManager \"keymaster\" not found:failed to decode following field(s): loginManagers")
  }

  it should "raise a BpConfigError exception if duplicates are configured in accessManagers config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", cids.asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", loginManagers.asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager,
        Manager("keymaster", Path("/some"), urls)).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include ("Duplicate entries for key (name) are found in the field: accessManagers")
  }

  it should "raise a BpConfigError exception if duplicates are configured in loginManagers config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", cids.asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", (loginManagers +
        LoginManager("checkpoint", keymasterIdManager, keymasterAccessManager,
          InternalAuthProtoManager(Path("/some"), Path("/some"), None))).asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include ("Duplicate entries for key (name) are found in the field: loginManagers")
  }

  it should "raise a BpConfigError exception if duplicate paths are configured in serviceIdentifiers config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", cids.asJson),
      ("serviceIdentifiers", (sids + ServiceIdentifier("some", urls, Path("/ent"), None, false)).asJson),
      ("loginManagers", loginManagers.asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include (
      "Duplicate entries for key (path) are found in the field: serviceIdentifiers")
  }

  it should "raise a BpConfigError exception if duplicate subdomains are configured in customerIdentifiers config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", (cids + CustomerIdentifier("enterprise", two, checkpointLoginManager)).asJson),
      ("serviceIdentifiers", sids.asJson),
      ("loginManagers", loginManagers.asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include (
      "Duplicate entries for key (subdomain) are found in the field: customerIdentifiers")
  }

  it should "raise a BpConfigError exception when it catches multiple errors in the config" in {
    val partialContents = Json.fromFields(Seq(
      ("listeningPort", bpPort.asJson),
      ("secretStore", defaultSecretStore.asInstanceOf[SecretStoreApi].asJson),
      ("sessionStore", defaultSessionStore.asInstanceOf[SessionStore].asJson),
      ("statsdReporter", defaultStatsdExporterConfig.asJson),
      ("customerIdentifiers", (cids + CustomerIdentifier("enterprise", two, checkpointLoginManager)).asJson),
      ("serviceIdentifiers", (sids + ServiceIdentifier("some", urls, Path("/ent"), None, false)).asJson),
      ("loginManagers", loginManagers.asJson),
      ("identityManagers", Set(keymasterIdManager).asJson),
      ("accessManagers", Set(keymasterAccessManager).asJson)))

    val tempFile = File.makeTemp("ServerConfigTest", ".tmp")
    tempFile.writeAll(partialContents.toString)

    val caught = the [BpConfigError] thrownBy {
      readServerConfig(tempFile.toCanonical.toString)
    }
    caught.getMessage should include (
      "Duplicate entries for key (path) are found in the field: serviceIdentifiers")
    caught.getMessage should include (
      "Duplicate entries for key (subdomain) are found in the field: customerIdentifiers")
  }

  it should "validate URLs configuration" in {
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
