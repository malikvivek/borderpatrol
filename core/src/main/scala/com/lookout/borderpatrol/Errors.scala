package com.lookout.borderpatrol

import com.twitter.finagle.http.Status

// scalastyle:off null
class BpCoreError(val status: Status, val message: String) extends Exception(message, null)

case class BpCommunicationError(msg: String)
  extends BpCoreError(Status.InternalServerError, s"An error occurred while talking to: $msg")

case class BpNotFoundRequest(msg: String = "")
  extends BpCoreError(Status.NotFound, s"${Status.NotFound.reason}: $msg")

case class BpBadRequest(msg: String = "")
  extends BpCoreError(Status.BadRequest, s"${Status.BadRequest.reason}: $msg")

