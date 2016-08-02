package com.lookout.borderpatrol.sessionx

// scalastyle:off null
class BpSessionError(val message: String) extends Exception(s"BPSESSION: $message", null)

case class BpSignedIdError(error: String)
    extends BpSessionError(s"An error occurred reading SignedId: $error")

case class BpSessionDataError(error: Throwable)
    extends BpSessionError(s"An error occurred reading Session data: ${error.getMessage}")

case class BpSessionStoreError(msg: String)
    extends BpSessionError(s"An error occurred interacting with the session store: $msg")

case class BpSecretDecodeError(msg: String)
    extends BpSessionError(s"An error decoding a Secret occurred: $msg")

case class BpSecretsDecodeError(msg: String)
  extends BpSessionError(s"An error decoding a Secrets occurred: $msg")

case class BpConsulError(msg: String)
  extends BpSessionError(s"An error occurred getting a value from Consul: $msg")

case class BpSessionCreateUnavailable(msg: String)
  extends BpSessionError(s"Session create failed: $msg")
