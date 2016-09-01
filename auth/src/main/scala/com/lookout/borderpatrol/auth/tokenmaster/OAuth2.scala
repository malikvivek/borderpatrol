package com.lookout.borderpatrol.auth.tokenmaster

import java.security.PublicKey
import java.security.interfaces.{ECPublicKey, RSAPublicKey}
import javax.xml.bind.DatatypeConverter

import com.lookout.borderpatrol.auth._
import com.lookout.borderpatrol.auth.tokenmaster.LoginManagers.OAuth2LoginManagerMixin
import com.twitter.logging.Logger
import com.lookout.borderpatrol.sessionx._
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.{ECDSAVerifier, RSASSAVerifier}
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.{PlainJWT, SignedJWT, JWTClaimsSet}
import com.twitter.finagle.http.{Status, Request}
import com.twitter.util.Future
import io.circe._
import io.circe.syntax._
import io.circe.Encoder

import scala.util.{Failure, Success, Try}
import scala.xml.{NodeSeq, Elem}


object OAuth2 {
  import cats.data.Xor

  def derive[A : Decoder](input: String): Xor[Error, A] =
    jawn.decode[A](input)

  /**
   * AAD token
   * @param accessToken JWT Access Token
   * @param idToken JWT ID Token
   */
  case class AadToken(accessToken: String, idToken: String)

  /**
   * AadToken Encoder/Decoder
   */
  implicit val AadTokenEncoder: Encoder[AadToken] = Encoder.instance {t =>
    Json.fromFields(Seq(
      ("access_token", t.accessToken.asJson),
      ("id_token", t.idToken.asJson)))
  }

  implicit val AadTokenDecoder: Decoder[AadToken] = Decoder.instance {c =>
    for {
      accessToken <- c.downField("access_token").as[String]
      idToken <- c.downField("id_token").as[String]
    } yield AadToken(accessToken, idToken)
  }

  /**
   * This class downloads and manages the certificates and verifies the tokens
   */
  class OAuth2CodeVerify {
    private[this] val log = Logger.get(getClass.getPackage.getName)
    private[this] var certificates: Map[String, String] = Map.empty[String, String]

    private[this] def find(name: String): Option[String] =
      certificates.get(name)

    protected[this] def add(name: String, certificate: String): Unit =
      certificates = (this.certificates + ((name, certificate)))

    private[this] def decodeCertFromXml(xml: Elem): NodeSeq = {
      (xml \\ "_" filter (node =>
        node.attributes.exists(_.value.text == "fed:SecurityTokenServiceType"))) \\ "X509Certificate"
    }

    private[this] def downloadAadCerts(loginManager: OAuth2LoginManagerMixin, thumbprint: String): Future[String] = {
      //  Fetch the response
      loginManager.certificateEndpoint.send(
        Request(loginManager.certificateEndpoint.path.toString)).flatMap(res => res.status match {

        //  Parse for Tokens if Status.Ok
        case Status.Ok => {

          // Load xml
          val xml = Try(scala.xml.XML.loadString(res.contentString.replaceAll("[^\\x20-\\x7e]", ""))) match {
            case Success(v) => v
            case Failure(f) => throw BpCertificateError(f.getMessage)
          }

          // Parse xml for certificate tags and then add all certificates to cache
          decodeCertFromXml(xml).foreach(node => {
            val md = java.security.MessageDigest.getInstance("SHA-1")
            val dec = DatatypeConverter.parseBase64Binary(node.text)
            val thumb = DatatypeConverter.printBase64Binary(md.digest(dec)).replaceAll("=", "").replaceAll("/", "_")
            // Add it to the cache
            add(thumb, node.text)
            log.debug(s"Downloaded a certificate for thumbprint: " + thumb)
          })

          // Find again or throw exception
          find(thumbprint).getOrElse(throw BpCertificateError(
            s"Unable to find certificate for thumbprint: $thumbprint")).toFuture
        }

        case _ => Future.exception(BpCertificateError(
          s"Failed to download certificate from OAuth2 Server with: ${res.status}"))
      })
    }

    protected[this] def verifier(pk: PublicKey): JWSVerifier =
      pk match {
        case rsaPk: RSAPublicKey => new RSASSAVerifier(rsaPk)
        case ecPk: ECPublicKey => new ECDSAVerifier(ecPk)
        case _ => throw BpCertificateError(s"Unsupported PublicKey algorithm: ${pk.getAlgorithm}")
      }

    /**
     * Parse the signed token, download the certificate/public key if necessary and verify the signature
     *
     * @param tokenStr
     * @return
     */
    private[this] def getClaimsSet(req: BorderRequest, loginManager: OAuth2LoginManagerMixin, tokenStr: String):
      Future[JWTClaimsSet] = {
        for {
          signedJWT <- wrapFuture({ () => SignedJWT.parse(tokenStr) }, BpTokenParsingError.apply)
          thumbprint <- wrapFuture({() => signedJWT.getHeader.getX509CertThumbprint }, BpTokenParsingError.apply)
          certStr <- find(thumbprint.toString).fold(downloadAadCerts(
            loginManager, thumbprint.toString))(Future.value(_))
          cert <- wrapFuture({ () => X509CertUtils.parse(DatatypeConverter.parseBase64Binary(certStr)) },
            BpCertificateError.apply)
        } yield signedJWT.verify(verifier(cert.getPublicKey)) match {
          case true =>
            log.debug(s"Verified the signature on AccessToken, for a user with certificate thumbprint: ${thumbprint}, "+
              s"SessionId: ${req.sessionId.toLogIdString}, " +
              s"IPAddress: '${req.req.xForwardedFor.getOrElse("No IP Address")}'")
            signedJWT.getJWTClaimsSet
          case false => throw BpVerifyTokenError(s"for a user with certificate thumbprint: $thumbprint, " +
            s" SessionId: ${req.sessionId.toLogIdString}, " +
            s"IPAddress: '${req.req.xForwardedFor.getOrElse("No IP Address")}'")
      }
    }

    /**
     * Download the AAD tokens, have the Access Token verified and return it to callers
     *
     * @param req
     * @return
     */
    def codeToClaimsSet(req: BorderRequest, loginManager: OAuth2LoginManagerMixin):
      Future[(String, JWTClaimsSet, JWTClaimsSet)] = {
      for {
        aadToken <- loginManager.codeToToken(req).flatMap(res => res.status match {
          //  Parse for Tokens if Status.Ok
          case Status.Ok =>
            OAuth2.derive[AadToken](res.contentString).fold[Future[AadToken]](
              err => Future.exception(BpTokenParsingError(
                s"in the Access Token response from OAuth2 Server: '${loginManager.name}'")),
              t => Future.value(t)
            )
          case _ => Future.exception(BpTokenRetrievalError(
            s"Failed to receive the token from OAuth2 Server: '${loginManager.name}', with: ${res.status}, " +
              s"and SessionId: ${req.sessionId.toLogIdString}, " +
              s"IPAddress: '${req.req.xForwardedFor.getOrElse("No IP Address")}'"))
        })
        idClaimSet <- wrapFuture({() => PlainJWT.parse(aadToken.idToken).getJWTClaimsSet}, BpTokenParsingError.apply)
        accessClaimSet <- getClaimsSet(req, loginManager, aadToken.accessToken)
      } yield (aadToken.accessToken, accessClaimSet, idClaimSet)
    }
  }
}
