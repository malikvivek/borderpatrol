package com.lookout.borderpatrol.server

import java.net.URL

import com.lookout.borderpatrol._
import com.lookout.borderpatrol.auth.tokenmaster.LoginManagers._
import com.lookout.borderpatrol.sessionx.SecretStores._
import com.lookout.borderpatrol.sessionx.SessionStores._
import com.lookout.borderpatrol.sessionx._
import com.twitter.finagle.Memcached
import com.twitter.finagle.http.path.Path
import cats.data.Xor
import com.twitter.logging.Logger
import io.circe.{Encoder, _}
import io.circe.generic.auto._
import io.circe.syntax._


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
 * Where you will find the Secret Store and Session Store
 */
object Config {
  val defaultSecretStore = SecretStores.InMemorySecretStore(Secrets(Secret(), Secret()))
  val defaultSessionStore = SessionStores.InMemoryStore
  private[this] val log = Logger.get(getClass.getPackage.getName)
  def cond[T](p: => Boolean, v: T) : Set[T] = if (p) Set(v) else Set.empty[T]

  // Encoder/Decoder for Path
  implicit val encodePath: Encoder[Path] = Encoder[String].contramap(_.toString)
  implicit val decodePath: Decoder[Path] = Decoder[String].map(Path(_))

  // Encoder/Decoder for URL
  implicit val encodeUrl: Encoder[URL] = Encoder[String].contramap(_.toString)
  implicit val decodeUrl: Decoder[URL] = Decoder[String].map(new URL(_))

  // Encoder/Decoder for SessionStore
  implicit val encodeSessionStore: Encoder[SessionStore] = Encoder.instance {
    case x: InMemoryStore.type => Json.obj(("type", Json.string("InMemoryStore")))
    case y: MemcachedStore =>  Json.obj(("type", Json.string("MemcachedStore")),
      ("hosts", Json.string("localhost:123")))
  }
  implicit val decodeSessionStore: Decoder[SessionStore] = Decoder.instance { c =>
    c.downField("type").as[String].flatMap {
      case "InMemoryStore" => Xor.right(defaultSessionStore)
      case "MemcachedStore"   => c.downField("hosts").as[String].map(hosts =>
        SessionStores.MemcachedStore(Memcached.client.newRichClient(s"memcached=${hosts}")))
      case other  => Xor.left(DecodingFailure(s"Invalid sessionStore: $other", c.history))
    }
  }

  // Encoder/Decoder for SecretStore
  implicit val encodeSecretStore: Encoder[SecretStoreApi] = Encoder.instance {
    case x: InMemorySecretStore => Json.obj(("type", Json.string(x.getClass.getSimpleName)))
    case y: ConsulSecretStore => Json.fromFields(Seq(
      ("type", y.getClass.getSimpleName.asJson),
      ("hosts", y.consulUrls.asJson),
      ("key", y.key.asJson)))
  }
  implicit val decodeSecretStore: Decoder[SecretStoreApi] = Decoder.instance { c =>
    c.downField("type").as[String].flatMap {
      case "InMemorySecretStore" => Xor.right(defaultSecretStore)
      case "ConsulSecretStore" =>
        for {
          hosts <- c.downField("hosts").as[Set[URL]]
          key <- c.downField("key").as[String]
        } yield ConsulSecretStore(key, hosts)
      case other  => Xor.left(DecodingFailure(s"Invalid secretStore: $other", c.history))
    }
  }

  /**
   * Encoder/Decoder for LoginManager
   *
   * Note that Decoder for LoginManager does not work standalone, it can be only used
   * while decoding the entire Config due to dependency issues
   */
  implicit val encodeBasicLoginManager: Encoder[BasicLoginManager] = Encoder.instance { blm =>
    Json.fromFields(Seq(
      ("name", blm.name.asJson),
      ("type", blm.tyfe.asJson),
      ("guid", blm.guid.asJson),
      ("loginConfirm", blm.loginConfirm.asJson),
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
      ("identityEndpoint", olm.identityEndpoint.name.asJson),
      ("accessEndpoint", olm.accessEndpoint.name.asJson),
      ("authorizeEndpoint", olm.authorizeEndpoint.name.asJson),
      ("tokenEndpoint", olm.tokenEndpoint.name.asJson),
      ("certificateEndpoint", olm.certificateEndpoint.name.asJson),
      ("clientId", olm.clientId.asJson),
      ("clientSecret", olm.clientSecret.asJson)
    ))
  }
  def decodeBasicLoginManager(eps: Map[String, EndpointConfig]): Decoder[BasicLoginManager] = Decoder.instance { c =>
    for {
      name <- c.downField("name").as[String]
      tyfe <- c.downField("type").as[String]
      guid <- c.downField("guid").as[String]
      loginConfirm <- c.downField("loginConfirm").as[Path]
      authorizePath <- c.downField("authorizePath").as[Path]
      ieName <- c.downField("identityEndpoint").as[String]
      ie <- Xor.fromOption(eps.get(ieName), DecodingFailure(s"identityEndpoint '$ieName' not found: ", c.history))
      aeName <- c.downField("accessEndpoint").as[String]
      ae <- Xor.fromOption(eps.get(aeName), DecodingFailure(s"accessEndpoint '$aeName' not found: ", c.history))
    } yield BasicLoginManager(name, tyfe, guid, loginConfirm, authorizePath,
      ie.toSimpleEndpoint, ae.toSimpleEndpoint)
  }
  def decodeOAuth2LoginManager(eps: Map[String, EndpointConfig]): Decoder[OAuth2LoginManager] = Decoder.instance { c =>
    for {
      name <- c.downField("name").as[String]
      tyfe <- c.downField("type").as[String]
      guid <- c.downField("guid").as[String]
      loginConfirm <- c.downField("loginConfirm").as[Path]
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
    } yield OAuth2LoginManager(name, tyfe, guid, loginConfirm,
      ie.toSimpleEndpoint, ae.toSimpleEndpoint, au.toSimpleEndpoint, te.toSimpleEndpoint, ce.toSimpleEndpoint,
      clientId, clientSecret)
  }

  // Encoder/Decoder for ServiceIdentifier
  implicit val encodeServiceIdentifier: Encoder[ServiceIdentifier] = Encoder.instance { sid =>
    Json.fromFields(Seq(
      ("name", sid.name.asJson),
      ("hosts", sid.hosts.asJson),
      ("path", sid.path.asJson),
      ("rewritePath", sid.rewritePath.asJson),
      ("protected", sid.protekted.asJson)))
  }
  implicit val decodeServiceIdentifier: Decoder[ServiceIdentifier] =
    Decoder.instance { c =>
      for {
        name <- c.downField("name").as[String]
        hosts <- c.downField("hosts").as[Set[URL]]
        path <- c.downField("path").as[Path]
        rewritePathOption <- c.downField("rewritePath").as[Option[Path]]
        protectedOption <- c.downField("protected").as[Option[Boolean]]
      } yield ServiceIdentifier(name, hosts, path, rewritePathOption, protectedOption.getOrElse(true))
    }

  // Encoder/Decoder for CustomerIdentifier
  implicit val encodeCustomerIdentifier: Encoder[CustomerIdentifier] = Encoder.instance { cid =>
    Json.fromFields(Seq(
      ("subdomain", cid.subdomain.asJson),
      ("guid", cid.guid.asJson),
      ("defaultServiceIdentifier", cid.defaultServiceId.name.asJson),
      ("loginManager", cid.loginManager.name.asJson)))
  }
  def decodeCustomerIdentifier(sids: Map[String, ServiceIdentifier], lms: Map[String, LoginManager]):
      Decoder[CustomerIdentifier] =
    Decoder.instance { c =>
      for {
        subdomain <- c.downField("subdomain").as[String]
        guid <- c.downField("guid").as[String]
        sidName <- c.downField("defaultServiceIdentifier").as[String]
        sid <- Xor.fromOption(sids.get(sidName),
          DecodingFailure(s"ServiceIdentifier '$sidName' not found: ", c.history)
        )
        lmName <- c.downField("loginManager").as[String]
        lm <- Xor.fromOption(lms.get(lmName),
          DecodingFailure(s"LoginManager '$lmName' not found: ", c.history)
        )
      } yield CustomerIdentifier(subdomain, guid, sid, lm)
    }

  /**
   * Validate Hosts (i.e. Set of URLs) configuration
   *
   * @param field
   * @param name
   * @param hosts
   * @return set of all the errors encountered during validation
   */
  def validateHostsConfig(field: String, name: String, hosts: Set[URL]): Set[String] = {
    // Make sure urls in Manager have matching protocol
    (cond[String](hosts.map(_.getProtocol()).size != 1,
      s"hosts configuration for ${name} in ${field}: has differing protocols") ++

    // Make sure hosts in Manager have either http or https protocol
    cond(!hosts.map(_.getProtocol()).mkString.matches("http[s]*"),
      s"hosts configuration for ${name} in ${field}: has unsupported protocol") ++

    // Make sure https hosts have a matching hostname
    cond(!hosts.filter(u => u.getProtocol == "https").isEmpty && hosts.map(u => u.getHost()).size != 1,
      s"hosts configuration for ${name} in ${field}: https urls have mismatching hostnames"))
  }

  /**
   * Validate SecretStore configuration
   *
   * @param field
   * @param secretStores
   * @return set of all the errors encountered during validation
   */
  def validateSecretStoreConfig(field: String, secretStores: SecretStoreApi): Set[String] = {
    secretStores match {
      case x: ConsulSecretStore => validateHostsConfig(field, "consulSecretStore", x.consulUrls)
      case _ => Set.empty[String]
    }
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
   * Validate Login Manager configurartion
   *
   * @param field
   * @param loginManagers
   * @return set of all the errors encountered during validation
   */
  def validateLoginManagerConfig(field: String, loginManagers: Set[LoginManager]): Set[String] = {
    // Find if loginManagers have duplicate entries
    cond(loginManagers.size > loginManagers.map(lm => lm.name).size,
      s"Duplicate entries for key (name) are found in the field: ${field}")
  }

  /**
   * Validate serviceIdentifier configuration
   *
   * @param field
   * @param sids
   * @return set of all the errors encountered during validation
   */
  def validateServiceIdentifierConfig(field: String, sids: Set[ServiceIdentifier]): Set[String] = {
    // Log an info message if ServiceIdentifiers have duplicate entries for combination of (name, protected)
    if (sids.size > sids.map(sid => sid.name).size)
      log.info("Potential Configuration Error Alert: " +
        "Duplicate entries for key(name) are found in the field: ServiceIdentifiers")

    // Find if ServiceIdentifiers have duplicate entries (same path)
    (cond(sids.size > sids.map(sid => sid.path).size,
      s"Duplicate entries for key (path) are found in the field: ${field}") ++

      // Make sure hosts in Serviceidentifier have http or https protocol
      sids.map(sid => validateHostsConfig(field, sid.name, sid.hosts)).flatten)
  }

  /**
   * Validate customerIdentifier configuration
   *
   * @param field
   * @param cids
   * @return set of all the errors encountered during validation
   */
  def validateCustomerIdentifierConfig(field: String, cids: Set[CustomerIdentifier]): Set[String] = {
    // Find if CustomerIdentifiers have duplicate entries
    cond(cids.size > cids.map(cid => cid.subdomain).size,
      s"Duplicate entries for key (subdomain) are found in the field: ${field}")
  }
}
