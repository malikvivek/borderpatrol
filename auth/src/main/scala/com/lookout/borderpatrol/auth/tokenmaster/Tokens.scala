package com.lookout.borderpatrol.auth.tokenmaster

import com.lookout.borderpatrol.sessionx.{BpSessionDataError, SessionDataEncoder}
import com.twitter.io.Buf
import io.circe._
import io.circe.syntax._
import scala.util.{Try, Success, Failure}


/**
 * A Token is an abstraction for the opaque string value for the JSON map that Tokenmaster returns
 */
sealed trait Token

/**
 * The token is missing
 */
case object EmptyToken extends Token

/**
 * Primary identifier, used to re-ask the issuing service for a service access token
 */
case class MasterToken(value: String) extends Token

/**
 * Service access token to be injected into request to service
 */
case class ServiceToken(value: String) extends Token {
  override def toString: String = value
}

/**
 * A mapping of service names to service tokens
 */
case class ServiceTokens(services: Map[String, ServiceToken] = Map.empty[String, ServiceToken]) {
  def find(name: String): Option[ServiceToken] =
    services.get(name)

  def add(name: String, token: ServiceToken): ServiceTokens =
    copy(services = (this.services + ((name, token))))
}

/**
 * This is the primary interface for accessing tokens
 * The incoming format from Tokenmaster is like this:
 * {
 *  "auth_service" : "MMM",
 *  "service_tokens" : { "service_a": "AAA", "service_b": "BBB" }
 * }
 *
 * @example
 *         Tokens.empty.service("service_name") // returns None
 *         decode[Tokens](jsonString) // result in circe decode result
 */
case class Tokens(master: MasterToken, services: ServiceTokens) {
  def service(name: String): Option[ServiceToken] =
    services.find(name)

  def add(name: String, serviceToken: ServiceToken): Tokens =
    copy(services = this.services.add(name, serviceToken))
}

object Tokens {

  import cats.data.Xor

  def derive[A : Decoder](input: String): Xor[Error, A] =
    jawn.decode[A](input)

  /**
   * MasterToken Encoder/Decoder
   * {"a"} -> MasterToken("a")
   */
  implicit val MasterTokenDecoder: Decoder[MasterToken] = Decoder[String].map(MasterToken(_))
  implicit val MasterTokenEncoder: Encoder[MasterToken] = Encoder[String].contramap(_.value)

  /**
   * Service Token Encoder/Decoder
   * {"service_name": "service_token"} -> ServiceToken("service_token")
   */
  implicit val ServiceTokenDecoder: Decoder[ServiceToken] = Decoder[String].map(ServiceToken(_))
  implicit val ServiceTokenEncoder: Encoder[ServiceToken] = Encoder[String].contramap(_.value)

  /**
   * {"a": "a", "b": "b"} -> ServiceTokens(Map((a->ServiceToken(a)), (b->ServiceToken(b)))
   */
  implicit val ServiceTokensDecoder: Decoder[ServiceTokens] = Decoder[Map[String, String]] map (m =>
      ServiceTokens(m.mapValues(ServiceToken(_))))
  implicit val ServiceTokensEncoder: Encoder[ServiceTokens] = Encoder.instance[ServiceTokens](st =>
    Json.fromFields(st.services.map(t => (t._1, Json.fromString(t._2.value))).toSeq))

  /**
   * Compose Tokens from Options
   * @return Tokens Options
   */
  private[this] def composeTokens(masterOpt: Option[MasterToken], servicesOpt: Option[ServiceTokens]):
      Option[Tokens] =
    (masterOpt, servicesOpt) match {
      case (None, None) => None
      case (Some(m), Some(s)) => Some(Tokens(m, s))
      case (Some(m), None) => Some(Tokens(m, ServiceTokens()))
      case (None, Some(s)) => Some(Tokens(MasterToken(""), s))
    }

  /**
   * Tokens Encoder/Decoder
   * {"auth_service": "a"} -> Tokens(MasterToken("a"), ServiceTokens())
   * {"service_tokens": {"a": "a", "b": "b"}} -> Tokens(MasterToken("a"),
   *                                                    ServiceTokens(Map((a->ServiceToken(a)), (b->ServiceToken(b)))
   * {} -> result error
   */
  implicit val TokensDecoder: Decoder[Tokens] = Decoder.instance {c =>
    for {
      masterOpt <- c.downField("auth_service").as[Option[MasterToken]]
      servicesOpt <- c.downField("service_tokens").as[Option[ServiceTokens]]
      tokens <- Xor.fromOption(composeTokens(masterOpt, servicesOpt),
        DecodingFailure(s"Failed to decode into Tokens: ", c.history))
    } yield tokens
  }
  implicit val TokensEncoder: Encoder[Tokens] = Encoder.instance {t =>
    Json.fromFields(Seq(
      ("auth_service", t.master.asJson),
      ("service_tokens", t.services.asJson)))
  }

  /**
   * Tokens (as Session Data) Encoder/Decoder
   */
  implicit val SessionDataTokenEncoder: SessionDataEncoder[Tokens] = new SessionDataEncoder[Tokens] {
    def encode(tokens: Tokens): Buf =
      SessionDataEncoder.encodeString.encode(TokensEncoder(tokens).toString())

    def decode(buf: Buf): Try[Tokens] =
      SessionDataEncoder.encodeString.decode(buf).flatMap(s =>
        derive[Tokens](s).fold[Try[Tokens]](
          e => Failure(BpSessionDataError(e)),
          t => Success(t)
        )
      )
  }
}

