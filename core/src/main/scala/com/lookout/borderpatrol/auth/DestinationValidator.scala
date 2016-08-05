package com.lookout.borderpatrol.auth

import java.net.URL

import com.google.common.net.InternetDomainName

import scala.util.{Success, Try}

/**
  * Created by rikesh.chouhan on 8/4/16.
  */
/**
  * Placeholder for valid hosts name entries.
  * It can determine whether or not an entry passed to it is contained in the valid hosts set.
  *
  * @param hostEntries
  */
case class DestinationValidator(hostEntries: Set[InternetDomainName]) {
  lazy val validHosts: Set[String] = hostEntries.map(m => m.toString)

  /**
    * Attempt to check whether this is a valid host entry.
    * If yes - return it wrapped as Option
    * If no -
    *   Is this a URL
    *   Yes - Attempt to get host and find if it is a valid host entry
    *   No - (could be relative path) return the fragment as is
    *
    * @param location (could be a URL - if yes attempt to extract host from entry and use that for match)
    * @return
    */
  def matchesValidHosts(location: String): Option[String] =
    Try(new URL(location)) match {
      case Success(s) if (!validHosts.contains(s.getHost)) => None
      case _ => Some(location)
    }

}
