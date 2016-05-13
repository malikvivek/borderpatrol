package com.lookout.borderpatrol.example

import com.lookout.borderpatrol._
import com.lookout.borderpatrol.auth.tokenmaster.LoginManagers.{BasicLoginManager, OAuth2LoginManager}
import com.lookout.borderpatrol.server.{BpConfigError, BpInvalidConfigError, Config, EndpointConfig}
import com.lookout.borderpatrol.sessionx._
import com.twitter.app.App
import cats.data.Xor
import com.twitter.logging.Logger
import io.circe.{Encoder, _}
import io.circe.jawn._
import io.circe.generic.auto._
import io.circe.syntax._
import scala.io.Source


case class StatsdExporterConfig(host: String, durationInSec: Int, prefix: String)

case class ServerConfig(listeningPort: Int,
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
  def decodeLoginManager(eps: Map[String, EndpointConfig]): Decoder[LoginManager] = Decoder.instance { c =>
    c.downField("type").as[String].flatMap {
      case "tokenmaster.basic" => decodeBasicLoginManager(eps).apply(c)
      case "tokenmaster.oauth2" => decodeOAuth2LoginManager(eps).apply(c)
      case other => Xor.left(DecodingFailure(s"Login manager type: $other not found", c.history))
    }
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
      ("customerIdentifiers", serverConfig.customerIdentifiers.asJson)
    ))
  }
  implicit val serverConfigDecoder: Decoder[ServerConfig] = Decoder.instance { c =>
    for {
      listeningPort <- c.downField("listeningPort").as[Int]
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
    } yield ServerConfig(listeningPort, secretStore, sessionStore, statsdExporterConfig,
      healthCheckEndpointConfigs, cids, sids, lms, eps)
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
      validateCustomerIdentifierConfig("customerIdentifiers", serverConfig.customerIdentifiers))
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

