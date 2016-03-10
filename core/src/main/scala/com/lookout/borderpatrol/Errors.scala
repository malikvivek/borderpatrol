package com.lookout.borderpatrol

// scalastyle:off null
class BpCoreError(val message: String) extends Exception(s"BPCORE: $message", null)

case class BpCommunicationError(error: String)
  extends BpCoreError(s"An error occurred while talking to: $error")
