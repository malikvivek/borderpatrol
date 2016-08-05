package com.lookout.borderpatrol.util

import com.twitter.finagle.http.ParamMap


object Helpers {

  /** Regular Expression for all special characters from ASCII 0 to 32 */
  private[this] val specialCharRegEx = (for (i <- 0 to 31) yield f"\\x$i%02x").mkString("[", "", "]")

  def scrubQueryParams(params: ParamMap, paramKey: String): Option[String] = {
    /* Lookup query param value for the given param key */
    params.get(paramKey).flatMap { l =>
      /* These param values could be malformed and may contain special characters. So lets scrub them out and
       * choose the first valid string as param
       */
      scrubAString(l)
    }
  }

  def scrubAString(toScrub: String): Option[String] = {
    toScrub.split(specialCharRegEx).filterNot(_.isEmpty).headOption.map(_.trim)
  }
}
