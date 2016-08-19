package com.lookout.borderpatrol.server

import com.lookout.borderpatrol.util.Combinators.tap
import com.twitter.util._
import com.twitter.finagle.{Service, SimpleFilter}
import com.twitter.finagle.http.{Request, Response}
import com.twitter.logging.{Logger, _}
import com.twitter.util.Future
import com.twitter.conversions.storage._

/**
  * Filter to generate access logs. The logs generated
  *
  * @param output
  * @param fileSizeInMegaBytes
  * @param fileCount
  */

case class AccessLogFilter(output: String, fileSizeInMegaBytes: Long, fileCount: Int)
  extends SimpleFilter[Request, Response] {

  val accessLogLevel: Level = Level.ALL
  val loggerName = "BorderPatrol_Access_Logs"
  val accessLogHandler = {
    if (output == "/dev/stderr" || output == "/dev/stdout")
      ConsoleHandler(BareFormatter, Some(accessLogLevel))
    else {
      FileHandler(
        filename = output,
        rollPolicy = Policy.MaxSize(fileSizeInMegaBytes.megabytes),
        level = Some(accessLogLevel),
        rotateCount = fileCount,
        append = true,
        formatter = BareFormatter
      )
    }
  }.apply()

  val logger: Logger = {
    tap(Logger.get(loggerName)) { l =>
      l.clearHandlers()
      // This allows the AccessLog logger to be used as a separate logger, not under root logger.
      l.setUseParentHandlers(false)
      //Set Log level for this logger.
      l.setLevel(accessLogLevel)
      // Add handler to QueuingHandler.
      l.addHandler(new QueueingHandler(accessLogHandler))
    }
  }

  def apply(req: Request, service: Service[Request, Response]): Future[Response] = {
    val startTime = Time.now
    for {
      resp <- service(req)
      _<- Future(logger.log(accessLogLevel,
        /* IP Address */
        s"${req.xForwardedFor.getOrElse("-")}\t"+
          /* Start Time */
          s"${startTime.format("[yyyy/mm/dd:hh:mm:ss.sss]")}\t"+
          /* Reuest Method (GET/POST) */
          s"${req.method}\t" +
          /* Request Host */
          s"${req.host.getOrElse("-")}\t" +
          /* Request Path */
          s"${req.path.getOrDefault("-")}\t" +
          /* Last 8 bytes of borser_session cookie from request */
          s"${req.cookies.getValue("border_session").fold("-")(c => c.takeRight(8))}\t"+
          /* Response Status Code */
          s"${resp.statusCode}\t" +
          /* Request Content length (in bytes) */
          s"${req.contentLength.getOrElse("-")}\t" +
          /* Last 8 bytes of borser_session cookie from response */
          s"${resp.cookies.getValue("border_session").fold("-")(c => c.takeRight(8))}\t"+
          /* Response Content length (in bytes) */
          s"${resp.contentLength.getOrElse("-")}\t" +
          /* Latency (Time difference between request and response in milliSeconds) */
          s"${Time.now.since(startTime).inMilliseconds}\t" +
          /* Access Logs Version 1*/
          s"AccessLogV1"))
    } yield resp
  }
}
