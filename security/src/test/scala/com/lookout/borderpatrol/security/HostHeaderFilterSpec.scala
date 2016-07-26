package com.lookout.borderpatrol.security

import com.google.common.net.InternetDomainName
import com.lookout.borderpatrol.BpNotFoundRequest
import com.lookout.borderpatrol.test._
import com.twitter.finagle.http.{Request, Status}
import com.twitter.util.Await

/**
  * Created by rikesh.chouhan on 7/19/16.
  */
class HostHeaderFilterSpec extends BorderPatrolSuite {

  behavior of "HostHeaderFilter"
  val validHostsString = Set("example.com","aad.example.com", "getouttahere.com")
  val validHosts = validHostsString map { host => InternetDomainName.from(host)}
  val checker = HostHeaderFilter(validHosts)
  val service = testService(r => true)

  it should "allow empty domain request to pass through" in {
    val request = Request("/")
    val response = checker.apply(request, service)
    Await.result(response).status should be (Status.Ok)
  }

  it should "allow valid host entry request to pass through" in {
    val request = Request("/")
    request.host = validHosts.head.toString
    val response = checker.apply(request, service)
    Await.result(response).status should be (Status.Ok)
  }

  it should "throw 404 error on unknown host entry" in {
    val request = Request("/")
    request.host = "dummy.com"
    val caught = the[BpNotFoundRequest] thrownBy { checker.apply(request, service) }
    caught.status should be (Status.NotFound)
  }

  it should "attempt to extract just the hostname from entries which can have port " +
    "and just return entry if there is no port" in {
    val someHostNames = Seq("hello.com", "yahoo.com:8080", "123456", ":dummy", " ", "localhost:8080")
    val filteredNames: Seq[String] = someHostNames.map( s => checker.extractHostName(s).getOrElse(""))
    filteredNames.contains(":dummy") should be (true)
    filteredNames.contains("hello.com") should be (true)
    filteredNames.contains("localhost") should be (true)
    filteredNames.contains("yahoo.com") should be (true)
    filteredNames.contains("123456") should be (true)
  }

  it should "allow a valid host name with port entry to pass through" in {
    val request = Request("/")
    request.host = validHosts.last.toString+":9000"
    val response = checker.apply(request, service)
    Await.result(response).status should be (Status.Ok)
  }

}
