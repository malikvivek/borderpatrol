package com.lookout.borderpatrol.server

import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel

import com.lookout.borderpatrol.test.BorderPatrolSuite
import com.twitter.finagle.util.{HashedWheelTimer}
import com.twitter.io.Buf
import com.twitter.common.metrics.{AbstractGauge, Metrics}
import com.twitter.util.Duration


class StatsdExporterSpec extends BorderPatrolSuite {
  private[this] val port = 4444
  private[this] val addr = new InetSocketAddress(port)
  private[this] val server = DatagramChannel.open().bind(addr)
  server.configureBlocking(false)
  private[this] val host = s"localhost:$port"
  private[this] val durationInSec = 300
  private[this] val prefix = "prefix"

  private[this] def receiveStat: Option[String] = {
    val buf1 = ByteBuffer.allocateDirect(65536)
    server.receive(buf1)
    buf1.flip()
    val buf2 = Buf.ByteBuffer.Owned(buf1)
    Buf.Utf8.unapply(buf2)
  }

  private[this] def receiveAllStats(stats: Set[String]): Set[String] =
    receiveStat match {
      case Some(s) if s.nonEmpty => receiveAllStats(stats + s)
      case _ => stats
    }

  behavior of "StatsdExporter"

  it should "instantiate with StatsExporterConfig" in {
    val exporter = new StatsdExporter(host, durationInSec, prefix)
    exporter.report()
    exporter.timer.stop()
  }

  it should "report counter increment" in {
    val metrics1 = Metrics.createDetached()
    val exporter1 = StatsdExporter(metrics1, HashedWheelTimer(), "ut", Duration.fromSeconds(300), host)
    val c = metrics1.createCounter("counter1")
    c.increment()
    exporter1.report()
    val stats = receiveAllStats(Set.empty[String])
    try {
      stats.filter(repo => repo.contains("ut.counter1:1|c")).nonEmpty should be (true)
    } finally {
      exporter1.timer.stop()
    }
  }

  it should "report gauge increment" in {
    val metrics2 = Metrics.createDetached()
    val exporter2 = StatsdExporter(metrics2, HashedWheelTimer(), "ut", Duration.fromSeconds(300), host)
    var x = 0
    val g = new AbstractGauge[Number]("gauge1") {
      def read: Number = x
    }
    val gauge = metrics2.registerGauge(g)
    x = 10
    exporter2.report()
    Thread.sleep(100)
    val stats = receiveAllStats(Set.empty[String])
    try {
      stats.filter(repo => repo.contains("ut.gauge1:10|g")).nonEmpty should be (true)
    } finally {
      exporter2.timer.stop()
    }
  }

  it should "report historgram increment" in {
    val metrics3 = Metrics.createDetached()
    val exporter3 = StatsdExporter(metrics3, HashedWheelTimer(), "ut", Duration.fromSeconds(300), host)
    val r = new scala.util.Random(10000)
    val histo = metrics3.createHistogram("histo")
    exporter3.report()
    val stats = receiveAllStats(Set.empty[String])
    try {
      stats.filter(repo => repo.contains("ut.histo.count:0|g")).nonEmpty should be (true)
      stats.filter(repo => repo.contains("ut.histo.avg:0.00|t")).nonEmpty should be (true)
      stats.filter(repo => repo.contains("ut.histo.min:0|t")).nonEmpty should be (true)
      stats.filter(repo => repo.contains("ut.histo.max:0|t")).nonEmpty should be (true)
      stats.filter(repo => repo.contains("ut.histo.stddev:0.00|t")).nonEmpty should be (true)
      stats.filter(repo => repo.contains("ut.histo.p50:0|t")).nonEmpty should be (true)
      stats.filter(repo => repo.contains("ut.histo.p90:0|t")).nonEmpty should be (true)
      stats.filter(repo => repo.contains("ut.histo.p95:0|t")).nonEmpty should be (true)
      stats.filter(repo => repo.contains("ut.histo.p99:0|t")).nonEmpty should be (true)
      stats.filter(repo => repo.contains("ut.histo.p999:0|t")).nonEmpty should be (true)
      stats.filter(repo => repo.contains("ut.histo.p9999:0|t")).nonEmpty should be (true)
    } finally {
      exporter3.timer.stop()
    }
  }
}
