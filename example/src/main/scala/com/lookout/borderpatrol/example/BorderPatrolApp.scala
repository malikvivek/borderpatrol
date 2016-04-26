package com.lookout.borderpatrol.example

import com.lookout.borderpatrol.HealthCheck.UrlHealthCheck
import com.lookout.borderpatrol.sessionx.SecretStores.{ConsulHealthCheck, ConsulSecretStore}
import com.lookout.borderpatrol.sessionx.SessionStores.{MemcachedHealthCheck, MemcachedStore}
import com.lookout.borderpatrol.HealthCheckRegistry
import com.lookout.borderpatrol.server._
import com.twitter.finagle.Http
import com.twitter.server.TwitterServer
import com.twitter.util.Await


object BorderPatrolApp extends TwitterServer with ServerConfigMixin {
  import service._
  import ServerConfig._

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
    serverConfig.healthCheckEndpointsVal .foreach { endpoint =>
      healthCheckRegistry.register(UrlHealthCheck(endpoint.name, endpoint))
    }

    // Create a StatsD exporter
    val statsdReporter = new StatsdExporter(
      serverConfig.statsdExporterConfigVal.host,
      serverConfig.statsdExporterConfigVal.durationInSec,
      serverConfig.statsdExporterConfigVal.prefix)

    // Create a server
    val server1 = Http.serve(s":${serverConfig.listeningPortVal}", MainServiceChain)
    val server2 = Http.serve(s":${serverConfig.listeningPortVal+1}", getMockRoutingService)
    Await.all(server1, server2)
  }
}
