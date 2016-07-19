package com.lookout.borderpatrol.example

import java.net.URL

import com.lookout.borderpatrol._
import com.lookout.borderpatrol.auth.tokenmaster.LoginManagers.{BasicLoginManager, OAuth2LoginManager}
import com.lookout.borderpatrol.server._
import com.lookout.borderpatrol.sessionx._
import com.twitter.app.App
import cats.data.Xor
import com.twitter.finagle.http.path.Path
import com.twitter.logging.Logger
import io.circe.{Encoder, _}
import io.circe.jawn._
import io.circe.generic.auto._
import io.circe.syntax._
import scala.io.Source

case class StatsdExporterConfig(host: String, durationInSec: Int, prefix: String)


/**
 *  EndpointConfig
 */
case class EndpointConfig(name: String, path: Path, hosts: Set[URL]) {
  def toSimpleEndpoint: Endpoint = SimpleEndpoint(name, path, hosts)
}
object EndpointConfig {
  def fromEndpoint(e: Endpoint): EndpointConfig = EndpointConfig(e.name, e.path, e.hosts)
}

/**
 * Server Config
 */
case class ServerConfig(listeningPort: Int,
                        whitelistedDomains: List[String],
                        secretStore: SecretStoreApi,
                        sessionStore: SessionStore,
                        statsdExporterConfig: StatsdExporterConfig,
                        healthCheckEndpointConfigs: Set[EndpointConfig],
                        customerIdentifiers: Set[CustomerIdentifier],
                        serviceIdentifiers: Set[ServiceIdentifier],
                        loginManagers: Set[LoginManager],
                        endpointConfigs: Set[EndpointConfig]) {

  def findEndpoint(n: String): Endpoint = endpointConfigs.find(_.name == n)
    .fold(throw new BpInvalidConfigError(s"Failed to find endpoint for: $n"))(_.toSimpleEndpoint)

  def findLoginManager(n: String): LoginManager = loginManagers.find(_.name == n)
    .getOrElse(throw new BpInvalidConfigError("Failed to find LoginManager for: " + n))

  def findServiceIdentifier(n: String): ServiceIdentifier = serviceIdentifiers.find(_.name == n)
    .getOrElse(throw new BpInvalidConfigError("Failed to find ServiceIdentifier for: " + n))
}

/**
 * Where you will find the Secret Store and Session Store
 */
object ServerConfig {
  import Config._

  val defaultConfigFile = "bpConfig.json"
  private[this] val log = Logger.get(getClass.getPackage.getName)

  /**
   * Encoder/Decoder for LoginManager
   *
   * Note that Decoder for LoginManager does not work standalone, it can be only used
   * while decoding the entire Config due to dependency issues
   */
  implicit val encodeLoginManager: Encoder[LoginManager] = Encoder.instance {
    case blm: BasicLoginManager => blm.asJson
    case olm: OAuth2LoginManager => olm.asJson
  }
  implicit val encodeBasicLoginManager: Encoder[BasicLoginManager] = Encoder.instance { blm =>
    Json.fromFields(Seq(
      ("name", blm.name.asJson),
      ("type", blm.tyfe.asJson),
      ("guid", blm.guid.asJson),
      ("loginConfirm", blm.loginConfirm.asJson),
      ("loggedOutUrl", blm.loggedOutUrl.asJson),
      ("authorizePath", blm.authorizePath.asJson),
      ("identityEndpoint", blm.identityEndpoint.name.asJson),
      ("accessEndpoint", blm.accessEndpoint.name.asJson)
    ))
  }
  implicit val encodeOAuth2LoginManager: Encoder[OAuth2LoginManager] = Encoder.instance { olm =>
    Json.fromFields(Seq(
      ("name", olm.name.asJson),
      ("type", olm.tyfe.asJson),
      ("guid", olm.guid.asJson),
      ("loginConfirm", olm.loginConfirm.asJson),
      ("loggedOutUrl", olm.loggedOutUrl.asJson),
      ("identityEndpoint", olm.identityEndpoint.name.asJson),
      ("accessEndpoint", olm.accessEndpoint.name.asJson),
      ("authorizeEndpoint", olm.authorizeEndpoint.name.asJson),
      ("tokenEndpoint", olm.tokenEndpoint.name.asJson),
      ("certificateEndpoint", olm.certificateEndpoint.name.asJson),
      ("clientId", olm.clientId.asJson),
      ("clientSecret", olm.clientSecret.asJson)
    ))
  }
  def decodeLoginManager(eps: Map[String, EndpointConfig]): Decoder[LoginManager] = Decoder.instance { c =>
    c.downField("type").as[String].flatMap {
      case "tokenmaster.basic" => decodeBasicLoginManager(eps).apply(c)
      case "tokenmaster.oauth2" => decodeOAuth2LoginManager(eps).apply(c)
      case other => Xor.left(DecodingFailure(s"Login manager type: $other not found", c.history))
    }
  }
  def decodeBasicLoginManager(eps: Map[String, EndpointConfig]): Decoder[BasicLoginManager] = Decoder.instance { c =>
    for {
      name <- c.downField("name").as[String]
      tyfe <- c.downField("type").as[String]
      guid <- c.downField("guid").as[String]
      loginConfirm <- c.downField("loginConfirm").as[Path]
      loggedOutUrl <- c.downField("loggedOutUrl").as[Option[URL]]
      authorizePath <- c.downField("authorizePath").as[Path]
      ieName <- c.downField("identityEndpoint").as[String]
      ie <- Xor.fromOption(eps.get(ieName), DecodingFailure(s"identityEndpoint '$ieName' not found: ", c.history))
      aeName <- c.downField("accessEndpoint").as[String]
      ae <- Xor.fromOption(eps.get(aeName), DecodingFailure(s"accessEndpoint '$aeName' not found: ", c.history))
    } yield BasicLoginManager(name, tyfe, guid, loginConfirm, loggedOutUrl, authorizePath,
      ie.toSimpleEndpoint, ae.toSimpleEndpoint)
  }
  def decodeOAuth2LoginManager(eps: Map[String, EndpointConfig]): Decoder[OAuth2LoginManager] = Decoder.instance { c =>
    for {
      name <- c.downField("name").as[String]
      tyfe <- c.downField("type").as[String]
      guid <- c.downField("guid").as[String]
      loginConfirm <- c.downField("loginConfirm").as[Path]
      loggedOutUrl <- c.downField("loggedOutUrl").as[Option[URL]]
      ieName <- c.downField("identityEndpoint").as[String]
      ie <- Xor.fromOption(eps.get(ieName), DecodingFailure(s"identityEndpoint '$ieName' not found: ", c.history))
      aeName <- c.downField("accessEndpoint").as[String]
      ae <- Xor.fromOption(eps.get(aeName), DecodingFailure(s"accessEndpoint '$aeName' not found: ", c.history))
      auName <- c.downField("authorizeEndpoint").as[String]
      au <- Xor.fromOption(eps.get(auName), DecodingFailure(s"authorizeEndpoint '$auName' not found: ", c.history))
      teName <- c.downField("tokenEndpoint").as[String]
      te <- Xor.fromOption(eps.get(teName), DecodingFailure(s"tokenEndpoint '$teName' not found: ", c.history))
      ceName <- c.downField("certificateEndpoint").as[String]
      ce <- Xor.fromOption(eps.get(ceName),
        DecodingFailure(s"certificateEndpoint '$ceName' not found: ", c.history))
      clientId <- c.downField("clientId").as[String]
      clientSecret <- c.downField("clientSecret").as[String]
    } yield OAuth2LoginManager(name, tyfe, guid, loginConfirm, loggedOutUrl,
      ie.toSimpleEndpoint, ae.toSimpleEndpoint, au.toSimpleEndpoint, te.toSimpleEndpoint, ce.toSimpleEndpoint,
      clientId, clientSecret)
  }

  /**
   * Decoder for ServerConfig (Using circe default encoder for encoding)
   */
  implicit val serverConfigEncoder: Encoder[ServerConfig] = Encoder.instance { serverConfig =>
    Json.fromFields(Seq(
      ("listeningPort", serverConfig.listeningPort.asJson),
      ("secretStore", serverConfig.secretStore.asJson),
      ("sessionStore", serverConfig.sessionStore.asJson),
      ("statsdReporter", serverConfig.statsdExporterConfig.asJson),
      ("endpoints", serverConfig.endpointConfigs.asJson),
      ("loginManagers", serverConfig.loginManagers.asJson),
      ("serviceIdentifiers", serverConfig.serviceIdentifiers.asJson),
      ("customerIdentifiers", serverConfig.customerIdentifiers.asJson),
      ("healthCheckEndpoints", serverConfig.healthCheckEndpointConfigs.asJson)
    ))
  }
  implicit val serverConfigDecoder: Decoder[ServerConfig] = Decoder.instance { c =>
    for {
      listeningPort <- c.downField("listeningPort").as[Int]
      whitelistedDomains <- c.downField("whiteListedDomains").as[List[String]]
      secretStore <- c.downField("secretStore").as[SecretStoreApi]
      sessionStore <- c.downField("sessionStore").as[SessionStore]
      statsdExporterConfig <- c.downField("statsdReporter").as[StatsdExporterConfig]
      eps <-c.downField("endpoints").as[Set[EndpointConfig]]
      lms <- c.downField("loginManagers").as(Decoder.decodeCanBuildFrom[LoginManager, Set](
        decodeLoginManager(eps.map(ep => ep.name -> ep).toMap), implicitly))
      sids <- c.downField("serviceIdentifiers").as[Set[ServiceIdentifier]]
      cids <- c.downField("customerIdentifiers").as(Decoder.decodeCanBuildFrom[CustomerIdentifier, Set](
        decodeCustomerIdentifier(sids.map(sid => sid.name -> sid).toMap, lms.map(lm => lm.name -> lm).toMap),
        implicitly))
      healthCheckEndpointNames <- c.downField("healthCheckEndpoints").as[Option[Set[String]]].map(
        _.getOrElse(Set.empty))
      healthCheckEndpointConfigs <- Xor.fromOption(
        {
          val healthCheckEndpointOpts = healthCheckEndpointNames.map(hceName => eps.find(_.name == hceName))
          if (healthCheckEndpointOpts.contains(None)) None else Some(healthCheckEndpointOpts.flatten)
        },
        DecodingFailure(s"Failed to decode endpoint(s) in the healthCheckEndpoints: ", c.history))
    } yield ServerConfig(listeningPort, whitelistedDomains, secretStore, sessionStore, statsdExporterConfig,
      healthCheckEndpointConfigs, cids, sids, lms, eps)
  }

  /**
   * Validate Endpoint configuration
   *
   * @param field
   * @param endpoints
   * @return set of all the errors encountered during validation
   */
  def validateEndpointConfig(field: String, endpoints: Set[EndpointConfig]): Set[String] = {
    // Find if endpoints have duplicate entries
    (cond(endpoints.size > endpoints.map(m => m.name).size,
      s"Duplicate entries for key (name) are found in the field: ${field}") ++

      // Make sure hosts in Endpoint have http or https protocol
      endpoints.map(m => validateHostsConfig(field, m.name, m.hosts)).flatten)
  }

  /**
   * Validates the BorderPatrol Configuration
   * - for duplicates
   * - invalid host configurations
   *
   * @param serverConfig
   * @return set of all the errors encountered during validation
   */
  def validate(serverConfig: ServerConfig): Set[String] = {
    //  Validate Secret Store config
    validateSecretStoreConfig("secretStore", serverConfig.secretStore) ++ (

      //  Validate identityManagers config
      validateEndpointConfig("endpoints", serverConfig.endpointConfigs) ++

      //  Validate loginManagers config
      validateLoginManagerConfig("loginManagers", serverConfig.loginManagers) ++

      //  Validate serviceIdentifiers config
      validateServiceIdentifierConfig("serviceIdentifiers", serverConfig.serviceIdentifiers) ++

      //  Validate customerIdentifiers config
      validateCustomerIdentifierConfig("customerIdentifiers", serverConfig.customerIdentifiers) ++

      // Validate domain names config
      validateDomainNames("whitelistedDomains", serverConfig.whitelistedDomains))
  }

  /**
   * Reads BorderPatrol configuration from the given filename
   *
   * @param filename
   * @return ServerConfig
   */
  def readServerConfig(filename: String): ServerConfig = {
    /**
     * Parse the config using `circe`.
     */
    decode[ServerConfig](Source.fromFile(filename).mkString) match {
      /** Validate the parsed config */
      case Xor.Right(cfg) => validate(cfg) match {
        case s if s.isEmpty => cfg
        case s => throw BpConfigError(s.mkString("\n\t", "\n\t", "\n"))
      }
      case Xor.Left(err) => {
        log.info(s"BorderPatrol Config parsing failed with: ${err.getMessage}")
        val fields = "CursorOpDownField\\(([A-Za-z]+)\\)".r.findAllIn(err.getMessage).matchData.map(
          m => m.group(1)).mkString(",")
        val reason = err.getMessage.reverse.dropWhile(_ != ':').reverse
        throw BpConfigError(s"${reason}failed to decode following field(s): $fields")
      }
    }
  }
}

/**
 * A [[com.twitter.app.App]] mixin to use for Configuration. Defines flags
 * to configure the BorderPatrol Server
 */
trait ServerConfigMixin { self: App =>
  import ServerConfig._

  // Flag for Secret Store
  val configFile = flag("configFile", defaultConfigFile,
    "BorderPatrol config file in JSON format")
}

