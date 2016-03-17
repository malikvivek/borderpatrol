package com.lookout.borderpatrol.server

import java.io.{Writer, BufferedWriter, OutputStreamWriter, ByteArrayOutputStream}
import java.net.{StandardProtocolFamily, SocketOption, StandardSocketOptions, InetAddress}
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel

import com.twitter.common.metrics.Metrics
import com.twitter.finagle.stats._
import com.twitter.finagle.util.{HashedWheelTimer, InetSocketAddressUtil, DefaultTimer}
import com.twitter.io.Buf
import com.twitter.logging.Logger
import com.twitter.util.{Time, Duration, Timer, NonFatal}
import scala.collection.JavaConverters.mapAsScalaMapConverter
import scala.collection.Map
import scala.util.Try


case class StatsdExporter(registry: Metrics, timer: Timer, prefix: String = "", duration: Duration,
                          hostAndPort: String) {
  private[this] val log = Logger.get(getClass.getPackage.getName)
  private[this] val addr = InetSocketAddressUtil.parseHosts(hostAndPort).head
  private[this] val channel = DatagramChannel.open(StandardProtocolFamily.INET)
    .setOption(StandardSocketOptions.SO_SNDBUF.asInstanceOf[SocketOption[Any]], 64000)
  private[this] val outputData = new ByteArrayOutputStream()

  // Schedule exporter
  timer.schedule(duration)(report)

  // Format helpers
  private[this] def format(writer: Writer, names: Seq[String], value: String, term: String): Unit = {
    val n = names.filter(_.nonEmpty).mkString(".").replaceAll("/", ".").replaceAll(":", "_")
    writer.write(s"${n}:$value|$term\n")
    writer.flush()
  }

  private[this] def format(n: Long): String = n.toString

  private[this] def format(v: Double): String = "%2.2f".format(v)

  private[this] def labelPercentile(d: Double): String =
    d.toString.replace("0.", "p") match {
      case "p5" => "p50"
      case "p9" => "p90"
      case p => p
    }

  // Send helpers
  private[this] def buf(utf8: String): Buf =
    Buf.Utf8(utf8)

  private[this] def byteBuf(buf: Buf): ByteBuffer =
    Buf.ByteBuffer.Owned.extract(buf)

  private[this] def send(str: String): Unit = {
    Try(channel.send(byteBuf(buf(str)), addr)).recover {
      case e => log.warning(s"Failed to send stats to: $hostAndPort, size: ${str.size} with: ${e.getMessage}")
    }
  }

  // Report
  def report(): Unit = {
    outputData.reset()
    val writer = new BufferedWriter(new OutputStreamWriter(outputData))
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
      case (name, value) => format(writer, Seq(prefix, name), format(value.longValue()), "c")
    }
    gauges.foreach {
      case (name, value) => format(writer, Seq(prefix, name), format(value.longValue()), "g")
    }

    histos.foreach { case (name, snapshot) =>
      format(writer, Seq(prefix, name, "count"), format(snapshot.count), "g")
      format(writer, Seq(prefix, name, "avg"), format(snapshot.avg), "t")
      format(writer, Seq(prefix, name, "min"), format(snapshot.min), "t")
      format(writer, Seq(prefix, name, "max"), format(snapshot.max), "t")
      format(writer, Seq(prefix, name, "stddev"), format(snapshot.stddev), "t")
      snapshot.percentiles.foreach(p =>
        format(writer, Seq(prefix, name, labelPercentile(p.getQuantile)), format(p.getValue), "t"))
    }

    writer.close()
    send(outputData.toString)
  }
}

object StatsdExporter {
  def apply(config: StatsdExporterConfig): StatsdExporter =
    StatsdExporter(MetricsStatsReceiver.defaultRegistry, HashedWheelTimer(),
      config.prefix.getOrDefault(Try(InetAddress.getLocalHost.getHostName).getOrDefault("localhost")),
      Duration.fromSeconds(config.durationInSec), config.host)
}
