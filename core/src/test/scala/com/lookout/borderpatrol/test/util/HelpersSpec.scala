package com.lookout.borderpatrol.test

import com.lookout.borderpatrol.util.Helpers._


class HelpersSpec extends BorderPatrolSuite {

  behavior of "scrubQueryParams"

  it should "scrub the special characters from the query params" in {
    /* Query encoded URLs */
    val req1 = "https://mtp.lookout.com/logout?destination=/abc%0d%0atest:abc%0d%0a&blah=/abc%0d%0atest2:abc2%0d%0a"
    scrubQueryParams(req1, "destination") should be(Some("/abc"))
    val req2 = "https://mtp.lookout.com/logout?destination=/abc%0d%0atest:abc%0d%0a"
    scrubQueryParams(req2, "destination") should be(Some("/abc"))
    val req3 = "https://mtp.lookout.com/logout?destination=/abc%0d%0a"
    scrubQueryParams(req3, "destination") should be(Some("/abc"))
    val req4 = "https://mtp.lookout.com/logout?destination=/%0d%0aabc%0d%0a"
    scrubQueryParams(req4, "destination") should be(Some("/"))

    /* URLs w/o encoding */
    val req11 = "https://mtp.lookout.com/logout?destination=/abc\n\rtest:abc\n\r&blah=/abc\n\rtest2:abc2\n\r"
    scrubQueryParams(req11, "destination") should be(Some("/abc"))
    val req12 = "https://mtp.lookout.com/logout?destination=/abc\n\rtest:abc\n\r"
    scrubQueryParams(req12, "destination") should be(Some("/abc"))
    val req13 = "https://mtp.lookout.com/logout?destination=/abc\n\r"
    scrubQueryParams(req13, "destination") should be(Some("/abc"))
    val req14 = "https://mtp.lookout.com/logout?destination=/\n\rabc\n\r"
    scrubQueryParams(req14, "destination") should be(Some("/"))
    val req15 = "https://mtp.lookout.com/logout?destination=/abc\r"
    scrubQueryParams(req15, "destination") should be(Some("/abc"))
    val req16 = "https://mtp.lookout.com/logout?destination=/abc\n\r"
    scrubQueryParams(req16, "destination") should be(Some("/abc"))
    val req17 = "https://mtp.lookout.com/logout?destination=/abc\n"
    scrubQueryParams(req17, "destination") should be(Some("/abc"))
    val req18 = "https://mtp.lookout.com/logout?destination=\n\r/abc"
    scrubQueryParams(req18, "destination") should be(Some("/abc"))

    /* Error conditions */
    scrubQueryParams(req1, "foo") should be(None)
    scrubQueryParams(null, "foo") should be(None)
    scrubQueryParams(req1, null) should be(None)
    val req21 = "https://mtp.lookout.com/logout?destination="
    scrubQueryParams(req21, "destination") should be(None)
    val req22 = "https://mtp.lookout.com/logout?destination=\n\r"
    scrubQueryParams(req22, "destination") should be(None)
  }
}
