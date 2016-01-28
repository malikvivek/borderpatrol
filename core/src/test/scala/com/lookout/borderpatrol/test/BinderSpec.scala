package com.lookout.borderpatrol.test

import com.lookout.borderpatrol._
import com.lookout.borderpatrol.Binder._
import com.twitter.finagle.http.{Status, Response, Request}
import com.twitter.util.Await


class BinderSpec extends BorderPatrolSuite {
  import sessionx.helpers._

  override def afterEach(): Unit = {
    try {
      super.afterEach() // To be stackable, must call super.afterEach
    }
    finally {
      BinderBase.clear
    }
  }

  behavior of "ManagerBinder"

  it should "successfully connect to server and returns the response" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678", mkTestService[Request, Response]{_ => Response(Status.Found).toFuture })
    try {
      val bindReq = BindRequest[Manager](keymasterIdManager, Request(keymasterIdManager.path.toString))
      val output = ManagerBinder.apply(bindReq)
      Await.result(output).status should be(Status.Found)
      /* Make sure client is cached in the cache */
      BinderBase.get(keymasterIdManager.name) should not be None
    } finally {
      server.close()
    }
  }

  behavior of "ServiceIdentifierBinder"

  it should "successfully connect to server and returns the response" in {
    val server = com.twitter.finagle.Http.serve(
      "localhost:5678", mkTestService[Request, Response]{_ => Response(Status.NotAcceptable).toFuture })
    try {
      val bindReq = BindRequest[ServiceIdentifier](one, Request(one.path.toString))
      val output = ServiceIdentifierBinder(bindReq)
      Await.result(output).status should be(Status.NotAcceptable)
      /* Make sure client is cached in the cache */
      BinderBase.get(one.name) should not be None
    } finally {
      server.close()
    }
  }
}
