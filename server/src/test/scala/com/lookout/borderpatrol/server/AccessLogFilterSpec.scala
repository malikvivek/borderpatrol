/**
  * Created by vivek.malik on 8/1/16.
  */
package com.lookout.borderpatrol.server

import java.util.{Calendar, Date, logging => javalog}

import com.lookout.borderpatrol.auth.{CustomerIdFilter, CustomerIdRequest, SessionIdFilter, SessionIdRequest}
//import com.lookout.borderpatrol.service.ServiceConfig._
//import com.lookout.borderpatrol.test.service.serviceTestHelpers._
import com.lookout.borderpatrol.test.{BorderPatrolSuite, coreTestHelpers}
import com.twitter.finagle.Service
import com.twitter.finagle.http.{Request, Response, Status}
import com.twitter.util.{Await, Future}

import scala.io.Source
import scala.reflect.io.File

class AccessLogFilterSpec extends BorderPatrolSuite {
  import coreTestHelpers._

  behavior of "AccessLogFilter"

  it should "successfully create a local file and log" in {

    val name = "localAccessLogger"
    val tempValidFile = File.makeTemp("TempAccessLogFile", ".tmp")
    val testFileSize: Long = 1*1024*1000
    val Request = req("enterprise", "/ent")

    //  test service
    val testService = Service.mk[Request, Response] {
      req => {
        Future.value(Response(Status.Ok))
      }
    }

    // Execute
    val output = (AccessLogFilter(name, tempValidFile.toCanonical.toString, testFileSize) andThen testService) (Request)

    // Validate
    Await.result(output).status should be(Status.Ok)
    Thread.sleep(5)
    Source.fromFile(tempValidFile.toCanonical.toString).mkString should include("AccessLogV1")
  }
}
