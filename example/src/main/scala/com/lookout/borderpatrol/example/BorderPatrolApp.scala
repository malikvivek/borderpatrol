package com.lookout.borderpatrol.example

import com.lookout.borderpatrol.HealthCheck.UrlHealthCheck
import com.lookout.borderpatrol.sessionx.SecretStores.{ConsulHealthCheck, ConsulSecretStore}
import com.lookout.borderpatrol.sessionx.SessionStores.{MemcachedHealthCheck, MemcachedStore}
import com.lookout.borderpatrol.HealthCheckRegistry
import com.lookout.borderpatrol.server._
import com.twitter.finagle.Http
import com.twitter.server.TwitterServer
import com.twitter.util.Await

import scala.util.{Failure, Success, Try}

object BorderPatrolApp extends TwitterServer with Config {
  import service._
  import Config._

  premain {
    implicit val bpStatsReceiver = statsReceiver
    implicit val serverConfig = readServerConfig(configFile())
    implicit val secretStore = serverConfig.secretStore

    /** Add health checks to registry */
    implicit val healthCheckRegistry = new HealthCheckRegistry()
    serverConfig.secretStore match {
      case consulStore: ConsulSecretStore =>
        val consulCheck = ConsulHealthCheck("consul", consulStore)
        healthCheckRegistry.register(consulCheck)
      case _ =>
    }
    serverConfig.sessionStore match {
      case memcachedStore: MemcachedStore =>
        val memcachedCheck = MemcachedHealthCheck("memcached", memcachedStore)
        healthCheckRegistry.register(memcachedCheck)
      case _ =>
    }
    serverConfig.healthCheckUrls.foreach { conf =>
      healthCheckRegistry.register(UrlHealthCheck(conf.name, conf.url))
    }

    // Create a StatsD exporter
    val statsdReporter = StatsdExporter(serverConfig.statsdExporterConfig)

    // Create a server
    val server1 = Http.serve(s":${serverConfig.listeningPort}", MainServiceChain)
    val server2 = Http.serve(s":${serverConfig.listeningPort+1}", getMockRoutingService)
    Await.all(server1, server2)
  }
}
