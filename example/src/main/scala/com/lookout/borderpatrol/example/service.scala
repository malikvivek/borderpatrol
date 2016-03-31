/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Lookout, Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.lookout.borderpatrol.example

import com.lookout.borderpatrol.Binder.ServiceIdentifierBinder
import com.lookout.borderpatrol.{HealthCheckRegistry, ServiceMatcher}
import com.lookout.borderpatrol.auth._
import com.lookout.borderpatrol.auth.keymaster.Keymaster._
import com.lookout.borderpatrol.auth.keymaster._
import com.lookout.borderpatrol.auth.keymaster.Tokens._
import com.lookout.borderpatrol.server.{HealthCheckService, ServerConfig}
import com.lookout.borderpatrol.sessionx._
import com.lookout.borderpatrol.util.Combinators._
import com.twitter.finagle.stats.StatsReceiver
import com.twitter.io.Buf
import com.twitter.finagle.http.{Method, Request, Response, Status}
import com.twitter.finagle.http.service.RoutingService
import com.twitter.finagle.Service
import com.twitter.util.Future
import io.finch.response.ResponseBuilder


object service {
  /**
   * Get IdentityProvider map of name -> Service chain
   *
   * As of now, we only support `keymaster` as an Identity Provider
   */
  def identityProviderChainMap(sessionStore: SessionStore)(
    implicit store: SecretStoreApi, statsReceiver: StatsReceiver):
  Map[String, Service[BorderRequest, Response]] =
    Map("keymaster" -> keymasterIdentityProviderChain(sessionStore))

  /**
   * Get AccessIssuer map of name -> Service chain
   *
   * As of now, we only support `keymaster` as an Access Issuer
   */
  def accessIssuerChainMap(sessionStore: SessionStore)(
    implicit store: SecretStoreApi, statsReceiver: StatsReceiver):
  Map[String, Service[BorderRequest, Response]] =
    Map("keymaster" -> keymasterAccessIssuerChain(sessionStore))

  /**
   * The sole entry point for all service chains
   */
  def MainServiceChain(implicit config: ServerConfig, statsReceiver: StatsReceiver, registry: HealthCheckRegistry,
                       secretStore: SecretStoreApi):
      Service[Request, Response] = {
    val serviceMatcher = ServiceMatcher(config.customerIdentifiers, config.serviceIdentifiers)
    val notFoundService = Service.mk[SessionIdRequest, Response] { req => Response(Status.NotFound).toFuture }

    RoutingService.byPath {
      case "/health" =>
        HealthCheckService(registry, BpBuild.BuildInfo.version)

      case _ =>
        /* Convert exceptions to responses */
        ExceptionFilter() andThen
          /* Validate that its our service */
          CustomerIdFilter(serviceMatcher) andThen
          /* Get or allocate Session/SignedId */
          SessionIdFilter(serviceMatcher, config.sessionStore) andThen
          /* If unauthenticated, send it to Identity Provider or login page */
          SendToIdentityProvider(identityProviderChainMap(config.sessionStore), config.sessionStore) andThen
          /* If authenticated and protected service, send it via Access Issuer chain */
          SendToAccessIssuer(accessIssuerChainMap(config.sessionStore)) andThen
          /* Authenticated or not, send it to unprotected service, if its destined to that */
          SendToUnprotectedService(ServiceIdentifierBinder, config.sessionStore) andThen
          /* Not found */
          notFoundService
    }
  }

  //  Mock Keymaster identityManager
  val mockKeymasterIdentityService = new Service[Request, Response] {

    val userMap: Map[String, String] = Map(
      ("test1@example.com" -> "password1")
    )

    def apply(request: Request): Future[Response] = {
      val tokens = Tokens(MasterToken("masterT"), ServiceTokens())
      (for {
        email <- request.getParam("email").toFuture
        pass <- request.getParam("password").toFuture
        if userMap(email) == (pass)
      } yield tap(Response(Status.Ok))(res => {
          res.contentString = TokensEncoder(tokens).toString()
          res.contentType = "application/json"
        })) handle {
        case ex => Response(Status.Unauthorized)
      }
    }
  }

  //  Mock Keymaster AccessIssuer
  val mockKeymasterAccessIssuerService = new Service[Request, Response] {
    def apply(request: Request): Future[Response] = {
      val serviceName = request.getParam("services")
      val tokens = Tokens(MasterToken("masterT"), ServiceTokens().add(
        serviceName, ServiceToken(s"SomeServiceData:${serviceName}")))
      tap(Response(Status.Ok))(res => {
        res.contentString = TokensEncoder(tokens).toString()
        res.contentType = "application/json"
      }).toFuture
    }
  }

  //  Mock Login Service
  val mockCheckpointService = new Service[Request, Response] {
    val loginForm = Buf.Utf8(
      """<html><body>
        |<h1>Example Account Service Login</h1>
        |<form action="/a/login" method="post">
        |<label>username</label><input type="text" name="username" />
        |<label>password</label><input type="password" name="password" />
        |<input type="submit" name="login" value="login" />
        |</form>
        |</body></html>
      """.stripMargin
    )

    def apply(req: Request): Future[Response] =
      req.method match {
        case Method.Get => {
          val rb = ResponseBuilder(Status.Ok).withContentType(Some("text/html"))
          rb(loginForm).toFuture
        }
        case _ => Future.value(Response(Status.NotFound))
      }
  }

  //  Mock Upstream service
  val mockUpstreamService = new Service[Request, Response] {
    def apply(request: Request): Future[Response] =
      tap(Response(Status.Ok))(res => {
        res.contentString =
          s"""
             |<html><body>
             |<h1>Welcome to Service @(${request.path})</h1>
                                                        |</body></html>
          """.stripMargin
        res.contentType = "text/html"
      }).toFuture
  }

  // Mock Routing service
  def getMockRoutingService(implicit config: ServerConfig, statsReceiver: StatsReceiver):
  Service[Request, Response] = {
    val checkpoint = config.findServiceIdentifier("checkpoint")
    val keymasterIdManager = config.findIdentityManager("keymaster")
    val keymasterAccessManager = config.findAccessManager("keymaster")
    val logout = config.findServiceIdentifier("logout")
    implicit val secretStore = config.secretStore
    val serviceMatcher = ServiceMatcher(config.customerIdentifiers, config.serviceIdentifiers)

    RoutingService.byPathObject {
      case keymasterAccessManager.path => mockKeymasterAccessIssuerService
      case keymasterIdManager.path => mockKeymasterIdentityService
      case path if path.startsWith(checkpoint.path) => mockCheckpointService
      case path if path.startsWith(logout.rewritePath.getOrElse(path)) =>
        ExceptionFilter() andThen /* Convert exceptions to responses */
          CustomerIdFilter(serviceMatcher) andThen /* Validate that its our service */
          LogoutService(config.sessionStore)
      case _ => mockUpstreamService
    }
  }
}
