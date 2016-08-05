package com.lookout.borderpatrol.test

import com.google.common.net.InternetDomainName
import com.lookout.borderpatrol.auth.DestinationValidator

/**
  * Created by rikesh.chouhan on 8/4/16.
  */
class DestinationValidatorSpec extends BorderPatrolSuite {

  val validDomains = Set("www.yahoo.com", "www.google.com", "localhost")
  val allowedDomains: Set[InternetDomainName] = validDomains map (InternetDomainName.from(_))
  val destinationValidator = DestinationValidator(allowedDomains)

  it should "Return the string as is when it is a valid URL" in {
    destinationValidator.matchesValidHosts("http://www.yahoo.com") should be (Some("http://www.yahoo.com"))
  }

  it should "Return None when the host is not a valid entry" in {
    destinationValidator.matchesValidHosts("http://www.cnn.com") should be (None)
  }

  it should "Return the string when it is a fragment or path instead of url" in {
    destinationValidator.matchesValidHosts("/dummy/path") should be (Some("/dummy/path"))
  }

  it should "Return the string when it is a plain string matching a host entry" in {
    destinationValidator.matchesValidHosts("localhost") should be (Some("localhost"))
  }

}
