package com.lookout.borderpatrol.auth

import com.lookout.borderpatrol.LoginManager
import com.twitter.util.Future
import scala.util.{Failure, Success, Try}


package object tokenmaster {

  def wrapFuture[A](f: () => A, onFailure: String => Throwable): Future[A] =
    Try(f()) match {
      // scalastyle:off null
      case Success(v) if v != null => Future.value[A](v)
      case Success(v) => Future.exception[A](onFailure("Wrapping null input argument"))
      case Failure(e) => Future.exception[A](onFailure(e.getMessage))
    }

  def wrapOps[A](f: () => A, msg: String, onFailure: String => Throwable): A =
    Try(f()) match {
      // scalastyle:off null
      case Success(v) if v != null => v
      case Success(v) => throw onFailure(s"$msg: null argument")
      case Failure(e) => throw onFailure(s"$msg: ${e.getMessage}")
    }

  implicit class LoginManagerOps(val lm: LoginManager) extends AnyVal {
    def as[A <: LoginManager]: A =
      lm.asInstanceOf[A]
  }
}

