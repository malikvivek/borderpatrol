package com.lookout.borderpatrol.security

import com.lookout.borderpatrol.auth.{BpUserError}
import com.lookout.borderpatrol.util.Combinators._
import com.twitter.finagle.{Service, SimpleFilter}
import com.twitter.finagle.http.{Response, Request, Status}
import com.twitter.util.Future

/**
  * Created by rikesh.chouhan on 7/18/16.
  */
object HostHeaderFilter {

  /**
    * Check that the request received contains a host entry [if present] that is present in the
    * validHosts set of names specified to this filter. If not then return an empty Future[Response]
    * or error
    *
    * @param validHosts
    */
  case class HostChecker(validHosts: Set[String]) extends SimpleFilter[Request, Response] {

    private[this] def checkHostEntry(request: Request): Request = {
      if (!validHosts.isEmpty && request.host.isDefined) {
        val host = request.host
        if (!validHosts(host.get))
          throw new BpUserError(Status.NotFound, s"Host Header: '${host.get}' not found")
      }
      request
    }

    /**
      * Requests get forwarded to service only for host entries that have been assigned to this filter
      */
    def apply(req: Request, service: Service[Request, Response]): Future[Response] =
      for {
        resp <- service(checkHostEntry(req))
      } yield resp
  }
}
