package com.lookout.borderpatrol.test.util

import com.lookout.borderpatrol.test._
import com.lookout.borderpatrol.util.Combinators._
import com.lookout.borderpatrol.util.Helpers._
import com.twitter.finagle.http.{Method, Request}


class HelpersSpec extends BorderPatrolSuite {

  def toPostRequest(uri: String): Request =
    tap(Request(Method.Post, "/"))(req => {
      req.contentType = "application/x-www-form-urlencoded"
      req.contentString = uri
    })

  behavior of "scrubQueryParams"

  it should "scrub the special characters from the encoded query params of GET Request URI" in {
    /* Query encoded GET URLs */
    val req1 = Request("logout?destination=%20/abc%0d%0a%20test:abc%0d%0a&blah=/abc%0d%0atest2:abc2%0d%0a")
    scrubQueryParams(req1.params, "destination") should be(Some("/abc"))
    val req2 = Request("logout?destination=/abc%0d%0atest:abc%0d%0a")
    scrubQueryParams(req2.params, "destination") should be(Some("/abc"))
    val req3 = Request("logout?destination=/abc%0d%0a")
    scrubQueryParams(req3.params, "destination") should be(Some("/abc"))
    val req4 = Request("logout?destination=/%0d%0aabc%0d%0a")
    scrubQueryParams(req4.params, "destination") should be(Some("/"))

    /* Error conditions */
    scrubQueryParams(req1.params, "foo") should be(None)
    scrubQueryParams(req1.params, null) should be(None)
  }

  it should "scrub the special characters from the query params of GET Request URI" in {
    /* URLs w/o encoding */
    val req11 = Request("logout?destination=/abc\n\rtest:abc\n\r&blah=/abc\n\rtest2:abc2\n\r")
    scrubQueryParams(req11.params, "destination") should be(Some("/abc"))
    val req12 = Request("logout?destination=/abc\n\rtest:abc\n\r")
    scrubQueryParams(req12.params, "destination") should be(Some("/abc"))
    val req13 = Request("logout?destination=/abc\n\r")
    scrubQueryParams(req13.params, "destination") should be(Some("/abc"))
    val req14 = Request("logout?destination=/\n\rabc\n\r")
    scrubQueryParams(req14.params, "destination") should be(Some("/"))
    val req15 = Request("logout?destination=/abc\r")
    scrubQueryParams(req15.params, "destination") should be(Some("/abc"))
    val req16 = Request("logout?destination=/abc\n\r")
    scrubQueryParams(req16.params, "destination") should be(Some("/abc"))
    val req17 = Request("logout?destination=/abc\n")
    scrubQueryParams(req17.params, "destination") should be(Some("/abc"))
    val req18 = Request("logout?destination=\n\r/abc")
    scrubQueryParams(req18.params, "destination") should be(Some("/abc"))
    val req19 = Request("logout?destination=")
    scrubQueryParams(req19.params, "destination") should be(None)
    val req20 = Request("logout?destination=\n\r")
    scrubQueryParams(req20.params, "destination") should be(None)
  }

  it should "scrub the special characters from the encoded query params of POST Request URI" in {
    /* Query encoded POST URLs */
    val req30 = toPostRequest("destination=/abc")
    scrubQueryParams(req30.params, "destination") should be(Some("/abc"))
    val req31 = toPostRequest("destination=/abc%0d%0atest:abc%0d%0a&blah=/abc%0d%0atest2:abc2%0d%0a")
    scrubQueryParams(req31.params, "destination") should be(Some("/abc"))
    val req32 = toPostRequest("destination=/abc%0d%0atest:abc%0d%0a")
    scrubQueryParams(req32.params, "destination") should be(Some("/abc"))
    val req33 = toPostRequest("destination=/abc%0d%0a")
    scrubQueryParams(req33.params, "destination") should be(Some("/abc"))
    val req34 = toPostRequest("destination=/%0d%0aabc%0d%0a")
    scrubQueryParams(req34.params, "destination") should be(Some("/"))
  }

  it should "scrub the special characters from the query params of POST Request URI" in {
    /* URLs w/o POST encoding */
    val req41 = toPostRequest("destination=/abc\n\rtest:abc\n\r&blah=/abc\n\rtest2:abc2\n\r")
    scrubQueryParams(req41.params, "destination") should be(Some("/abc"))
    val req42 = toPostRequest("destination=/abc\n\rtest:abc\n\r")
    scrubQueryParams(req42.params, "destination") should be(Some("/abc"))
    val req43 = toPostRequest("destination=/abc\n\r")
    scrubQueryParams(req43.params, "destination") should be(Some("/abc"))
    val req44 = toPostRequest("destination=/\n\rabc\n\r")
    scrubQueryParams(req44.params, "destination") should be(Some("/"))
    val req45 = toPostRequest("destination=/abc\r")
    scrubQueryParams(req45.params, "destination") should be(Some("/abc"))
    val req46 = toPostRequest("destination=/abc\n\r")
    scrubQueryParams(req46.params, "destination") should be(Some("/abc"))
    val req47 = toPostRequest("destination=/abc\n")
    scrubQueryParams(req47.params, "destination") should be(Some("/abc"))
    val req48 = toPostRequest("destination=\n\r/abc")
    scrubQueryParams(req48.params, "destination") should be(Some("/abc"))
  }
}
