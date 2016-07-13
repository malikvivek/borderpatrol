package com.lookout.borderpatrol.auth

import com.twitter.finagle.http.Status


// scalastyle:off null
class BpAuthError(val message: String) extends Exception(s"BPAUTH: $message", null)

/**
  * Server side error encountered during identity or access phase
  */
case class BpTokenParsingError(msg: String)
    extends BpAuthError(s"Failed to parse token with: $msg")

case class BpCertificateError(msg: String)
  extends BpAuthError(s"Failed to process Certificate with: $msg}")

case class BpIdentityProviderError(msg: String)
  extends BpAuthError(s"Failed in identity provisioning with: $msg}")

case class BpAccessIssuerError(msg: String)
  extends BpAuthError(s"Failed in access issuer with: $msg}")

case class BpForbiddenRequest(msg: String = "")
  extends BpAuthError(s"${Status.Forbidden.reason}: $msg")

/**
  * User initiated error(s) - encoutered during identity or access phase
  */
class BpUserError(val status: Status, message: String) extends BpAuthError(message)

case class BpTokenRetrievalError(msg: String)
  extends BpUserError(Status.BadRequest, s"Failed to retrieve token with: $msg")

case class BpTokenAccessError(msg: String)
  extends BpUserError(Status.BadRequest, s"Failure while using token with: $msg")

case class BpVerifyTokenError(msg: String)
  extends BpUserError(Status.BadRequest, s"Failed to verify the signature on the token: $msg}")

case class BpUnauthorizedRequest(msg: String = "")
  extends BpUserError(Status.Unauthorized, s"${Status.Unauthorized.reason}: $msg")

case class BpInvalidRequest(msg: String = "")
  extends BpUserError(Status.BadRequest, s"${Status.BadRequest.reason}: $msg")
