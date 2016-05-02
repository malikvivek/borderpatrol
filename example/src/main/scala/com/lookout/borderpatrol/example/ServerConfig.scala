package com.lookout.borderpatrol.example

import com.lookout.borderpatrol._
import com.lookout.borderpatrol.auth.tokenmaster.LoginManagers.{OAuth2LoginManager, BasicLoginManager}
import com.lookout.borderpatrol.example.ServerConfig.StatsdExporterConfig
import com.lookout.borderpatrol.server.{BpConfigError, Config}
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


case class ServerConfig(listeningPortVal: Int,
                        secretStoreVal: SecretStoreApi,
                        sessionStoreVal: SessionStore,
                        statsdExporterConfigVal: StatsdExporterConfig,
                        healthCheckEndpointsVal: Set[Endpoint],
                        customerIdentifiersVal: Set[CustomerIdentifier],
                        serviceIdentifiersVal: Set[ServiceIdentifier],
                        loginManagersVal: Set[LoginManager],
                        endpointsVal: Set[Endpoint]) extends Config {
  def loginManagers: Set[LoginManager] = loginManagersVal
  def endpoints: Set[Endpoint] = endpointsVal
  def serviceIdentifiers: Set[ServiceIdentifier] = serviceIdentifiersVal
  def customerIdentifiers: Set[CustomerIdentifier] = customerIdentifiersVal
  def secretStore: SecretStoreApi = secretStoreVal
  def sessionStore: SessionStore = sessionStoreVal
}

/**
 * Where you will find the Secret Store and Session Store
 */
object ServerConfig {
  import Config._

  val defaultConfigFile = "bpConfig.json"
  private[this] val log = Logger.get(getClass.getPackage.getName)
  case class StatsdExporterConfig(host: String, durationInSec: Int, prefix: String)

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
  def decodeLoginManager(eps: Map[String, Endpoint]): Decoder[LoginManager] = Decoder.instance { c =>
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
      ("listeningPort", serverConfig.listeningPortVal.asJson),
      ("secretStore", serverConfig.secretStoreVal.asJson),
      ("sessionStore", serverConfig.sessionStoreVal.asJson),
      ("statsdReporter", serverConfig.statsdExporterConfigVal.asJson),
      ("endpoints", serverConfig.endpointsVal.asJson),
      ("loginManagers", serverConfig.loginManagersVal.asJson),
      ("serviceIdentifiers", serverConfig.serviceIdentifiersVal.asJson),
      ("customerIdentifiers", serverConfig.customerIdentifiersVal.asJson)))
  }
  implicit val serverConfigDecoder: Decoder[ServerConfig] = Decoder.instance { c =>
    for {
      listeningPort <- c.downField("listeningPort").as[Int]
      secretStore <- c.downField("secretStore").as[SecretStoreApi]
      sessionStore <- c.downField("sessionStore").as[SessionStore]
      statsdExporterConfig <- c.downField("statsdReporter").as[StatsdExporterConfig]
      eps <-c.downField("endpoints").as[Set[Endpoint]]
      lms <- c.downField("loginManagers").as(Decoder.decodeCanBuildFrom[LoginManager, Set](
        decodeLoginManager(eps.map(ep => ep.name -> ep).toMap), implicitly))
      sids <- c.downField("serviceIdentifiers").as[Set[ServiceIdentifier]]
      cids <- c.downField("customerIdentifiers").as(Decoder.decodeCanBuildFrom[CustomerIdentifier, Set](
        decodeCustomerIdentifier(sids.map(sid => sid.name -> sid).toMap, lms.map(lm => lm.name -> lm).toMap),
        implicitly))
      healthCheckEndpointNames <- c.downField("healthCheckEndpoints").as[Option[Set[String]]].map(
        _.getOrElse(Set.empty))
      healthCheckEndpoints <- Xor.fromOption(
        {
          val healthCheckEndpointOpts = healthCheckEndpointNames.map(hceName => eps.find(_.name == hceName))
          if (healthCheckEndpointOpts.contains(None)) None else Some(healthCheckEndpointOpts.flatten)
        },
        DecodingFailure(s"Failed to decode endpoint(s) in the healthCheckEndpoints: ", c.history))
    } yield ServerConfig(listeningPort, secretStore, sessionStore, statsdExporterConfig,
      healthCheckEndpoints, cids, sids, lms, eps)
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
    validateSecretStoreConfig("secretStore", serverConfig.secretStoreVal) ++ (

      //  Validate identityManagers config
      validateEndpointConfig("endpoints", serverConfig.endpointsVal) ++

      //  Validate loginManagers config
      validateLoginManagerConfig("loginManagers", serverConfig.loginManagersVal) ++

      //  Validate serviceIdentifiers config
      validateServiceIdentifierConfig("serviceIdentifiers", serverConfig.serviceIdentifiersVal) ++

      //  Validate customerIdentifiers config
      validateCustomerIdentifierConfig("customerIdentifiers", serverConfig.customerIdentifiersVal))
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

