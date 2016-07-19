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

    private def checkHostEntry(request: Request): Request =
      tap(request) { re =>
        re.host match {
          case Some(s) if !s.isEmpty => if (!validHosts(s))
            throw new BpUserError(Status.NotFound, s"Host Header: $s not found")
          case _ => (re)
        }
    }


    /**
      * Requests get X-Forwarded-For and other request headers added before passing to the service
      * Responses get response headers added before returning to the client
      */
    def apply(req: Request, service: Service[Request, Response]): Future[Response] =
      for {
        resp <- service(checkHostEntry(req))
      } yield resp
  }
}
