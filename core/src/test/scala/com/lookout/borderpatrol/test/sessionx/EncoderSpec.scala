package com.lookout.borderpatrol.test.sessionx

import com.lookout.borderpatrol.sessionx._
import com.lookout.borderpatrol.test._
import com.twitter.io.Buf
import com.twitter.finagle.http
import io.circe._
import io.circe.generic.auto._
import io.circe.syntax._
import scala.util.{Try, Success}


class EncoderSpec extends BorderPatrolSuite {
  import coreTestHelpers._

  behavior of "SecretEncoder"

  it should "be creatable" in {
    val secret = Secret()
    val secretEncoder = SecretEncoder[String](
      secret => "hello",
      string => Success(secret)
    )
    secretEncoder.encode(secret) should be("hello")
    secretEncoder.decode("hello").success.value should be(secret)
  }

  it should "uphold encoding/decoding identity" in {
    def identity(json: Json): Secret = {
      jawn.decode[Secret](json.noSpaces).fold(e => throw new Exception("error decoding Secret"), s => s)
    }

    identity(secrets.current.asJson) should be(secrets.current)
    Try(identity(10.asJson)).failure.exception should be(a[Exception])
  }

  behavior of "SignedIdEncoder"

  it should "uphold encoding/decoding identity" in {
    def identity[A](id: SignedId)(implicit ev: SignedIdEncoder[A]): SignedId =
      ev.decode(ev.encode(id)) getOrElse sessionid.untagged

    val id = sessionid.untagged
    identity[String](id) should be(id)
  }

  it should "not decode invalid data" in {
    def invalid[A](input: A)(implicit ev: SignedIdEncoder[A]): Try[SignedId] =
      ev.decode(input)

    invalid[String]("forged secret session id").failure.exception should be(a[BpSignedIdError])
  }

  behavior of "SessionDataEncoder"

  it should "uphold encoding/decoding identity" in {
    def identity[A](a: A)(implicit ev: SessionDataEncoder[A]): A =
      ev.decode(ev.encode(a)).get

    val data = "hello"
    identity(data) should be(data)
  }

  it should "not decode invalid data" in {
    def invalid[A](input: Buf)(implicit ev: SessionDataEncoder[A]): Try[A] =
      ev.decode(input)

    invalid[http.Request](Buf.U32BE(1)).failure.exception should be(a[BpSessionDataError])
  }

  behavior of "SecretsEncoder"

  it should "Encode then decode Secrets and they should be the same" in {
    val a1 = Secret()
    val b1 = Secret()
    val c = Secrets(a1,b1)
    jawn.decode[Secrets](c.asJson.noSpaces).toOption.value.current should be(a1)
    jawn.decode[Secrets](c.asJson.noSpaces).toOption.value.previous should be(b1)
  }
}
