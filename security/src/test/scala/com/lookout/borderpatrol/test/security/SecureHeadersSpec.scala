package com.lookout.borderpatrol.test.security

import com.google.common.net.InternetDomainName
import com.lookout.borderpatrol.security.SecureHeaderFilter
import com.lookout.borderpatrol.security.SecureHeaders
import com.lookout.borderpatrol.test._
import com.twitter.finagle.Service
import com.twitter.finagle.http.{Response, Request, Status}
import com.twitter.util.Future

class SecureHeadersSpec extends BorderPatrolSuite {

  behavior of "SecureHeaderFilter"
  val requestDefaults = SecureHeaders.request
  val validDomains = Set("www.yahoo.com", "www.google.com", "localhost")
  val allowedDomains: Set[InternetDomainName] = validDomains map (InternetDomainName.from(_))
  val defaults = SecureHeaders.response(allowedDomains)
  val filter = SecureHeaderFilter(requestDefaults, allowedDomains)
  val service = filter andThen testService(r => true)

  it should "inject all of the headers" in {
    val request = Request("/")
    service(request).results.headerMap.sameElements(defaults) should be(true)
  }

  it should "append X-Forwarded-For to an existing list into request" in {
    val request = Request("/")
    request.xForwardedFor = "10.10.10.10"

    filter(request, testService(r =>
      r.xForwardedFor.getOrElse("").split(",").size > 1)
    ).results.status should be (Status.Ok)

    // empty xforwardedfor
    filter(Request("/"), testService(r =>
      r.xForwardedFor.getOrElse("").split(",").size == 1)
    ).results.status should be (Status.Ok)
  }

  it should "override existing headers" in {
    val request = Request("/")
    val response = Response(Status.Ok)
    response.headerMap.add("X-Download-Options", "arglebargle")
    val s = Service.mk[Request, Response](r => Future.value(response))
    filter(request, s).results.headerMap("X-Download-Options") should be(SecureHeaders.XDownloadOptions._2)
  }

  it should "Find CORS Header with domains specified" in {
    val request = Request("/")
    val response = Response(Status.Ok)
    val s = Service.mk[Request, Response](r => Future.value(response))
    filter(request, s).results.headerMap(SecureHeaders.allowOrigin) should be(validDomains.mkString(","))
  }

}
