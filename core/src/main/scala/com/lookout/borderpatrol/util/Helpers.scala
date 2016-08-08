package com.lookout.borderpatrol.util

import com.twitter.finagle.http.ParamMap


object Helpers {

  /** Regular Expression for all special characters from ASCII 0 to 32 */
  private[this] val specialCharRegEx = (for (i <- 0 to 31) yield f"\\x$i%02x").mkString("[", "", "]")

  /**
    * Lookup query param value for the given param key.
    * These param values could be malformed and may contain special characters. So lets scrub them out and
    * choose the first valid string as param
    * @param params - the map
    * @param paramKey - specific key to get look for and get first valid value
    * @return scrubbed value
    */
  def scrubQueryParams(params: ParamMap, paramKey: String): Option[String] = {
    params.get(paramKey).flatMap { l =>
      scrubAString(l)
    }
  }

  /**
    * The value could be malformed and may contain special characters. So lets scrub it and return the value
    * if anything was found
    * @param toScrub
    * @return
    */
  def scrubAString(toScrub: String): Option[String] = {
    toScrub.split(specialCharRegEx).filterNot(_.isEmpty).headOption.map(_.trim)
  }
}
