package com.lookout.borderpatrol.security

import java.net.InetAddress

import com.google.common.net.InternetDomainName
import com.lookout.borderpatrol.sessionx._
import com.lookout.borderpatrol.util.Combinators.tap
import com.twitter.finagle.{Service, SimpleFilter}
import com.twitter.finagle.http.{HeaderMap, Request, Response}
import com.twitter.util.Future

/**
  * Basic, default values for adding security mechanisms via headers
  */
object SecureHeaders {

  // response headers https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#Response_fields
  val StrictTransportSecurity = ("Strict-Transport-Security", "max-age=31557600")
  val XFrameOptions = ("X-Frame-Options", "DENY")
  val XXSSProtection = ("X-XSS-Protection", "1; mode=block")
  val XContentTypeOptions = ("X-ContentType-Options", "nosniff")
  val XDownloadOptions = ("X-Download-Options", "noopen")
  val XPermittedCrossDomainPolicies = ("X-Permitted-Cross-Domain-Policies", "none")
  /* CORS support headers */
  val allowOrigin = "Access-Control-Allow-Origin"
  val controlEnabled = "Access-Control-Allow-Credentials" -> "true"
  val exposeHeaders = "Access-Control-Expose-Headers" -> "ETag,Set-Cookie"
  val allowMethods = "Access-Control-Allow-Methods" -> "GET, POST, PATCH, PUT, DELETE, OPTIONS, HEAD"
  val allowHeaders =
    "Access-Control-Allow-Headers" -> "*,x-csrf-token,x-requested-with,Content-Type,If-Modified-Since,If-None-Match"
  val maxAge = "Access-Control-Max-Age" -> "86400"

  def response(allowedDomains: Set[InternetDomainName]): HeaderMap = {
    HeaderMap(StrictTransportSecurity, XFrameOptions, XXSSProtection,
      XContentTypeOptions, XDownloadOptions, XPermittedCrossDomainPolicies,
      allowMethods, allowHeaders, controlEnabled,exposeHeaders, maxAge,
      SecureHeaders.allowOrigin -> allowedDomains.mkString(","))
  }

  val request = HeaderMap()
}

/**
  * Inject and override specific headers in requests and responses for added security
  *
  * This filter is best added to the very beginning of the filter chain to ensure that
  * 4xx-5xx level responses get these headers added.
  *
  * By default it includes the following default headers and values:
  *
  *   Responses:
  *   Strict-Transport-Security: max-age=31557600
  *   X-Frame-Options: DENY
  *   X-XSS-Protection: 1; mode=block
  *   X-ContentType-Options: nosniff
  *   X-Download-Options: noopen
  *   X-Permitted-Cross-Domain-Policies: none
  *
  *   Requests:
  *   X-Forwarded-For: the ip of this host appended to any existing values
  *
  * @param requestHeaders
  */
case class SecureHeaderFilter(requestHeaders: HeaderMap = SecureHeaders.request,
                              allowedDomains: Set[InternetDomainName])
    extends SimpleFilter[Request, Response] {
  val localIp = InetAddress.getLocalHost.getHostAddress
  lazy val responseMap = SecureHeaders.response(allowedDomains)

  def injectRequestHeaders(req: Request): Request =
    tap(req) { re =>
      re.headerMap ++= requestHeaders
      re.xForwardedFor_=(re.xForwardedFor.fold(localIp)(s => s"$s, $localIp"))
    }

  private[this] def injectResponseHeaders(response: Response): Response =
    tap(response) { resp =>
      resp.headerMap ++= (responseMap)
    }

  /**
    * Requests get X-Forwarded-For and other request headers added before passing to the service
    * Responses get response headers added before returning to the client
    */
  def apply(req: Request, service: Service[Request, Response]): Future[Response] =
    for {
      resp <- service(injectRequestHeaders(req))
      _ <- (injectResponseHeaders(resp)).toFuture
    } yield resp
}
