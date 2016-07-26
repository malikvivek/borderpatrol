package com.lookout.borderpatrol.security

import com.google.common.net.InternetDomainName
import com.lookout.borderpatrol.BpNotFoundRequest
import com.twitter.finagle.util.InetSocketAddressUtil
import com.twitter.finagle.{Service, SimpleFilter}
import com.twitter.finagle.http.{Response, Request}
import com.twitter.util.Future
import scala.util.{Try,Success,Failure}

/**
  * Created by rikesh.chouhan on 7/18/16.
  * Check that the request received contains a host entry [if present] that is present in the
  * validHosts set of names specified to this filter. If not then return an empty Future[Response]
  * or error
  *
  * @param validHosts
  */
case class HostHeaderFilter(validHosts: Set[InternetDomainName]) extends SimpleFilter[Request, Response] {

  lazy val validHostStrings = validHosts.map( validHost => validHost.toString )

  /**
    * Strip out the port portion including the semicolon from the provided
    * host entry.
    *
    * @param host
    * @return
    */
  private[security] def extractHostName(host: String): Option[String] = {
    Try (InetSocketAddressUtil.parseHostPorts(host).seq.head._1) match {
      case Success(hostOnly) => Some(hostOnly)
      case Failure(f) => Some(host)
    }
  }

  private[security] def checkHostEntry(request: Request): Unit = {
    request.host.foreach( host => {
      extractHostName(host) match {
        case Some(hostName) if (!validHostStrings(hostName)) =>
          throw new BpNotFoundRequest(s"Host Header: '${hostName}' not found")
        case _ => ()
      }
    })
  }

  /**
    * Requests get forwarded to service only for host entries that have been assigned to this filter
    */
  def apply(req: Request, service: Service[Request, Response]): Future[Response] = {
    checkHostEntry(req)
    for {
      resp <- service(req)
    } yield resp
  }
}
