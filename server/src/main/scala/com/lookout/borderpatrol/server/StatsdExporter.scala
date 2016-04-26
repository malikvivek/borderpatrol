package com.lookout.borderpatrol.server

import java.io.ByteArrayOutputStream
import java.net.{StandardProtocolFamily, InetAddress}
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel

import com.twitter.common.metrics.Metrics
import com.twitter.finagle.stats._
import com.twitter.finagle.util.{HashedWheelTimer, InetSocketAddressUtil}
import com.twitter.logging.Logger
import com.twitter.util.{Duration, Timer, NonFatal}
import scala.collection.JavaConverters.mapAsScalaMapConverter
import scala.collection.Map
import scala.util.Try


case class StatsdExporter(registry: Metrics, timer: Timer, prefix: String = "", duration: Duration,
                          hostAndPort: String) {
  private[this] val log = Logger.get(getClass.getPackage.getName)
  private[this] val addr = InetSocketAddressUtil.parseHosts(hostAndPort).head
  private[this] val channel = DatagramChannel.open(StandardProtocolFamily.INET)
  private[this] val dataBuffer = new ByteArrayOutputStream()

  def this(hostname: String, durationInSec: Int, prefix: String) = this(MetricsStatsReceiver.defaultRegistry,
    HashedWheelTimer(),
    prefix.getOrDefault(Try(InetAddress.getLocalHost.getHostName).getOrDefault("localhost")),
    Duration.fromSeconds(durationInSec), hostname)

  // Schedule exporter
  timer.schedule(duration)(report)

  // Format helpers
  private[this] def format(names: Seq[String], value: String, term: String): String = {
    val n = names.filter(_.nonEmpty).mkString(".").replaceAll("/", ".").replaceAll(":", "_")
    s"${n}:$value|$term\n"
  }

  private[this] def format(n: Long): String = n.toString

  private[this] def format(v: Double): String = "%2.2f".format(v)

  private[this] def labelPercentile(d: Double): String =
    d.toString.replace("0.", "p") match {
      case "p5" => "p50"
      case "p9" => "p90"
      case p => p
    }

  private[this] def flush(): Unit = {
    if (dataBuffer.size() != 0) {
      Try(channel.send(ByteBuffer.wrap(dataBuffer.toByteArray), addr)).recover {
        case e => log.info(
          s"Failed to send stats to: $hostAndPort, size: ${dataBuffer.size()} with: ${e.getMessage}")
      }
      /* Whether we succeed or not, always reset the output buffer in the end */
      dataBuffer.reset()
    }
  }

  private[this] def send(str: String): Unit = {
    /** Flush if we have more than 4k worth of data */
    if (dataBuffer.size() > 4000) {
      flush()
    }
    dataBuffer.write(str.getBytes)
  }

  // Report
  def report(): Unit = {
    val gauges = try registry.sampleGauges().asScala catch {
      case NonFatal(e) =>
        // because gauges run arbitrary user code, we want to protect ourselves here.
        // while the underlying registry should protect against individual misbehaving
        // gauges, an extra level of belt-and-suspenders seemed worthwhile.
        //log.error(e, "exception while collecting gauges")
        Map.empty[String, Number]
    }
    val histos = registry.sampleHistograms().asScala

    val counters = registry.sampleCounters().asScala

    counters.foreach {
      case (name, value) => send(format(Seq(prefix, name), format(value.longValue()), "c"))
    }
    gauges.foreach {
      case (name, value) => send(format(Seq(prefix, name), format(value.longValue()), "g"))
    }

    histos.foreach { case (name, snapshot) =>
      send(format(Seq(prefix, name, "count"), format(snapshot.count), "g"))
      send(format(Seq(prefix, name, "avg"), format(snapshot.avg), "t"))
      send(format(Seq(prefix, name, "min"), format(snapshot.min), "t"))
      send(format(Seq(prefix, name, "max"), format(snapshot.max), "t"))
      send(format(Seq(prefix, name, "stddev"), format(snapshot.stddev), "t"))
      snapshot.percentiles.foreach(p =>
        send(format(Seq(prefix, name, labelPercentile(p.getQuantile)), format(p.getValue), "t")))
    }

    /** Flush the data buffer in the end */
    flush()
  }
}
