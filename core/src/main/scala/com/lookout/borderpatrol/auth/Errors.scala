package com.lookout.borderpatrol.auth

import com.lookout.borderpatrol.sessionx.SignedId
import com.twitter.finagle.http.Status


// scalastyle:off null
class BpAuthError(val message: String) extends Exception(s"BPAUTH: $message", null)

/**
 * Token Parsing error
 */
case class BpTokenParsingError(msg: String)
    extends BpAuthError(s"Failed to parse token with: $msg")

/**
 * Certificate processing error
 */
case class BpCertificateError(msg: String)
    extends BpAuthError(s"Failed to process Certificate with: $msg}")

/**
 * Certificate processing error
 */
case class BpVerifyTokenError(msg: String)
  extends BpAuthError(s"Failed to verify the signature on the token: $msg}")

/**
 * This exception stores the response code
 */
case class BpIdentityProviderError(status: Status, msg: String) extends BpAuthError(msg)

/**
 * This exception stores the response code
 */
case class BpAccessIssuerError(status: Status, msg: String) extends BpAuthError(msg)

/**
 * This exception stores the response code
 */
case class BpRedirectError(status: Status, location: String, sessionIdOpt: Option[SignedId], msg: String)
    extends BpAuthError(msg)

/**
 * This exception stores the response code
 */
case class BpLogoutError(status: Status, location: String, msg: String) extends BpAuthError(msg)
