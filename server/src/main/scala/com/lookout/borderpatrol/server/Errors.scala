package com.lookout.borderpatrol.server

// scalastyle:off null
case class BpConfigError(message: String)
  extends Exception(s"BPCONFIG: An error occurred while reading BorderPatrol Configuration: ${message}", null)

case class BpDuplicateConfigError(key: String, field: String)
  extends Exception("An error occurred while reading BorderPatrol Configuration: " +
    s"Duplicate entries for key(s) (${key}) - are found in the field: ${field}")

case class BpInvalidConfigError(message: String)
  extends Exception(message, null)
