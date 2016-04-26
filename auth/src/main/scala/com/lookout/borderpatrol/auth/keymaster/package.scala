package com.lookout.borderpatrol.auth

import com.twitter.util.Future

import scala.util.{Failure, Success, Try}

/**
 * This provides the specification contracts for Keymaster auth.
 *
 * The composition of these filters should work, e.g.:
 *
 * val bpFilter = CustomerIdFilter andThen SessionIdFilter
 * val loginFilters = bpFilter andThen ...
 * val authFilters = bpFilter andThen IdentityFilter(???) andThen AccessFilter(???)
 */
package object keymaster {

  def wrapFuture[A](f: () => A, onFailure: String => Throwable): Future[A] =
    Try(f()) match {
      // scalastyle:off null
      case Success(v) if v != null => Future.value[A](v)
      case Success(v) => Future.exception[A](onFailure("Wrapping null input argument"))
      case Failure(e) => Future.exception[A](onFailure(e.getMessage))
    }
}

