package com.lookout.borderpatrol

// scalastyle:off null
class BpBaseError(val message: String) extends Exception(s"BPBASE: $message", null)

case class BpCommunicationError(error: String)
  extends BpBaseError(s"An error occurred while talking to: $error")
