package com.lookout.borderpatrol.auth.tokenmaster

import cats.data.Xor
import com.lookout.borderpatrol.sessionx._
import com.lookout.borderpatrol.test.BorderPatrolSuite
import com.twitter.io.Buf
import io.circe.Json
import scala.util.{Try, Success}
import io.circe.syntax._


class TokensSpec extends BorderPatrolSuite  {
  import Tokens._

  val sessionStore = SessionStores.InMemoryStore
  val serviceToken1 = new ServiceToken("SomeServiceTokenData1")
  val serviceToken2 = new ServiceToken("SomeServiceTokenData2")
  val serviceTokens = new ServiceTokens().add("service1", serviceToken1).add("service2", serviceToken2)
  val masterToken = MasterToken("masterT")
  val tokens = Tokens(masterToken, serviceTokens)
  val emptyTokens = Tokens(MasterToken(""), ServiceTokens())

  behavior of "ServiceToken"

  it should "uphold encoding/decoding ServiceToken" in {
    def encodeDecode(sTok: ServiceToken) : ServiceToken = {
      val encoded = sTok.asJson
      derive[ServiceToken](encoded.toString) match {
        case Xor.Right(a) => a
        case Xor.Left(b) => new ServiceToken("failed")
      }
    }
    encodeDecode(serviceToken1) should be (serviceToken1)
  }

  behavior of "ServiceTokens"

  it should "be able to find ServiceToken by service name" in {
    serviceTokens.find("service1") should be equals (serviceToken1)
    serviceTokens.find("service2") should be equals (serviceToken2)
  }

  it should "uphold encoding/decoding ServiceTokens" in {
    def encodeDecode(sToks: ServiceTokens) : ServiceTokens = {
      val encoded = sToks.asJson
      derive[ServiceTokens](encoded.toString) match {
        case Xor.Right(a) => a
        case Xor.Left(b) => ServiceTokens()
      }
    }
    encodeDecode(serviceTokens) should be (serviceTokens)
  }

  behavior of "Tokens"

  it should "be able to find the ServiceToken by service name" in {
    tokens.service("service1") should be equals (serviceToken1)
    tokens.service("service2") should be equals (serviceToken2)
    tokens.service("service3") should be equals (None)
  }

  it should "uphold encoding/decoding Tokens" in {
    def encodeDecode(toks: Tokens) : Tokens =
      TokensDecoder.decodeJson(TokensEncoder(toks)).fold[Tokens](e => emptyTokens, t => t)

    val partialContents1 = Json.fromFields(Seq(
      ("auth_service", masterToken.asJson)
    ))
    val partialContents2 = Json.fromFields(Seq(
      ("service_tokens", serviceTokens.asJson)
    ))

    encodeDecode(tokens) should be (tokens)
  }

  it should "uphold encoding/decoding partial Tokens" in {
    def encodeDecode(json: Json) : Tokens = {
      derive[Tokens](json.toString) match {
        case Xor.Right(a) => a
        case Xor.Left(b) => emptyTokens
      }
    }

    val partialContents1 = Json.fromFields(Seq(
      ("auth_service", masterToken.asJson)
    ))
    val partialContents2 = Json.fromFields(Seq(
      ("service_tokens", serviceTokens.asJson)
    ))

    //  Validate
    encodeDecode(partialContents1) should be (Tokens(masterToken, ServiceTokens()))
    encodeDecode(partialContents2) should be (Tokens(MasterToken(""), serviceTokens))
  }

  behavior of "SessionDataTokenEncoder"

  it should "uphold encoding/decoding for SessionDataTokenEncoder" in {
    def validate(s: Tokens)(implicit ev: SessionDataEncoder[Tokens]): Try[Tokens] = {
      ev.decode(ev.encode(s))
    }
    // Validate
    validate(tokens) should be (Success(tokens))
  }

  it should "not decode invalid data" in {
    def invalid(input: Buf)(implicit ev: SessionDataEncoder[Tokens]): Try[Tokens] =
      ev.decode(input)

    //  Execute
    val e = invalid(SessionDataEncoder.encodeString.encode( """{ "a" : "b" }""")).failure.exception

    // Validate
    e should be(a[BpSessionDataError])
    e.getMessage should include ("Failed to decode into Tokens:")
  }
}
