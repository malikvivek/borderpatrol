package com.lookout.borderpatrol.test.security

import com.lookout.borderpatrol.auth.BpUserError
import com.lookout.borderpatrol.test._
import com.lookout.borderpatrol.security.HostHeaderFilter.HostChecker
import com.twitter.finagle.http.{Status, Request}
import com.twitter.util.Await

/**
  * Created by rikesh.chouhan on 7/19/16.
  */
class HostHeaderFilterSpec extends BorderPatrolSuite {

  behavior of "HostHeaderFilter"
  val validHosts = Set("example.com","aad.example.com", "getouttahere.com")
  val checker = HostChecker(validHosts)
  val service = testService(r => true)

  it should "allow empty domain request to pass through" in {
    val request = Request("/")
    val response = checker.apply(request, service)
    Await.result(response).status should be (Status.Ok)
  }

  it should "allow valid host entry request to pass through" in {
    val request = Request("/")
    request.host = validHosts.head
    val response = checker.apply(request, service)
    Await.result(response).status should be (Status.Ok)
  }

  it should "throw 404 error on unknown host entry" in {
    val request = Request("/")
    request.host = "dummy.com"
    val caught = the[BpUserError] thrownBy { checker.apply(request, service) }
    caught.status should be (Status.NotFound)
  }

}
