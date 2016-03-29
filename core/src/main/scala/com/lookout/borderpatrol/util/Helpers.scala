package com.lookout.borderpatrol.util

import org.jboss.netty.handler.codec.http.QueryStringDecoder

import scala.collection.JavaConverters._
import scala.util.{Success, Try}

object Helpers {

  /** Parse uri into (path, params) */
  private[this] val specialCharRegEx = (for (i <- 0 to 20) yield f"\\x$i%02x").mkString("[", "", "]")

  def scrubQueryParams(uri: String, paramKey: String): Option[String] = {
    Try(new QueryStringDecoder(uri)) match {
      case Success(qsd) =>
        /* Convert to a scala parameter map (key, List<values>) */
        val params = qsd.getParameters.asScala.mapValues {
          _.asScala.toList
        }
        /* Lookup list of query param values for the given param key */
        params.get(paramKey).flatMap { l =>
          /* These param values could be malformed and may contain special characters. So lets scrub them out and
           * choose the first valid string for each row in the list
           */
          val listOfValues = l.flatMap { s =>
            s.split(specialCharRegEx).filterNot(_.isEmpty).headOption
          }
          if (listOfValues.isEmpty) None
          else Some(listOfValues.mkString("_"))
        }
      case _ => None
    }
  }

}
