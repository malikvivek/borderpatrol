import sbtunidoc.Plugin.UnidocKeys._
import scoverage.ScoverageSbtPlugin.ScoverageKeys.coverageExcludedPackages

lazy val Version = "0.2.17-SNAPSHOT"

lazy val buildSettings = Seq(
  organization := "com.lookout",
  version := Version,
  scalaVersion := "2.11.8",
  crossScalaVersions := Seq("2.10.5", "2.11.8")
)

lazy val compilerOptions = Seq(
  "-deprecation",
  "-encoding", "UTF-8",
  "-feature",
  "-language:existentials",
  "-language:higherKinds",
  "-language:implicitConversions",
  "-unchecked",
  "-Yno-adapted-args",
  "-Ywarn-dead-code",
  "-Ywarn-numeric-widen",
  "-Xfuture",
  "-Xlint"
)

lazy val finagleVersion = "6.35.0"
lazy val circeVersion = "0.4.0"
lazy val twitterServerVersion = "1.20.0"
lazy val nimbusVersion = "4.7"

val testDependencies = Seq(
  "org.scalacheck" %% "scalacheck" % "1.13.0",
  "org.scalatest" %% "scalatest" % "2.2.6",
  "org.mockito" % "mockito-core" % "1.10.19"
)

val baseSettings = Seq(
  resolvers += "twitter-repo" at "http://maven.twttr.com",
  libraryDependencies ++= Seq(
    "com.twitter" %% "finagle-http" % finagleVersion,
    "com.twitter" %% "finagle-memcached" % finagleVersion,
    "org.scala-lang" % "scala-reflect" % scalaVersion.value,
    "com.twitter" %% "bijection-core" % "0.9.2",
    "com.twitter" %% "bijection-util" % "0.9.2",
    "org.bouncycastle" % "bcprov-jdk15on" % "1.54",
    compilerPlugin("org.scalamacros" % "paradise" % "2.1.0" cross CrossVersion.full)
  ) ++ testDependencies.map(_ % "test"),
  scalacOptions ++= compilerOptions ++ (
      CrossVersion.partialVersion(scalaVersion.value) match {
        case Some((2, 11)) => Seq("-Ywarn-unused-import")
        case _ => Seq.empty
      }
  ),
  scalacOptions in (Compile, console) := compilerOptions :+ "-Yrepl-class-based",
  wartremoverWarnings in (Compile, compile) ++= Warts.allBut(Wart.FinalCaseClass, Wart.NoNeedForMonad, Wart.Throw,
    Wart.Null, Wart.Nothing, Wart.DefaultArguments)
)

/**
 * Automatic deployments to JFrog OSS and Bintray/jCenter/Maven Central via Travis CI from SBT
 * http://szimano.org/automatic-deployments-to-jfrog-oss-and-bintrayjcentermaven-central-via-travis-ci-from-sbt/
 */
lazy val publishSettings =
  if (Version.endsWith("-SNAPSHOT"))
    Seq(
      licenses := Seq("MIT" -> url("http://opensource.org/licenses/MIT")),
      publishTo := Some("Artifactory Realm" at "http://oss.jfrog.org/artifactory/oss-snapshot-local"),
      bintrayReleaseOnPublish := false,
      publishArtifact in Test := true,
      // Only setting the credentials file if it exists (#52)
      credentials := List(Path.userHome / ".bintray" / ".artifactory").filter(_.exists).map(Credentials(_))
    )
  else
    Seq(
      licenses := Seq("MIT" -> url("http://opensource.org/licenses/MIT")),
      homepage := Some(url("https://github.com/lookout/borderpatrol")),
      scmInfo := Some(
        ScmInfo(
          url("https://github.com/lookout/borderpatrol"),
          "scm:git:git@github.com:lookout/borderpatrol.git"
        )
      ),
      /**
       * there’s some weird resolver added – this is apparently some recent Bintray bug described here:
       * http://stackoverflow.com/questions/31704818/releasing-and-publishing-from-sbt-bintray
       */
      publishMavenStyle := true,
      publishArtifact in Test := true,
      resolvers += Resolver.bintrayRepo("maheshkelkar", "maven")
    )

lazy val noPublish = Seq(
  publish := {},
  publishLocal := {}
)

lazy val assembleSettings =
  assemblyMergeStrategy in assembly := {
    case PathList("com", "twitter", "common", xs @ _*) => MergeStrategy.first
    case PathList("org", "objectweb", xs @ _*) => MergeStrategy.first
    case PathList("org", "slf4j", xs @ _*) => MergeStrategy.last
    case PathList("META-INF", "MANIFEST.MF") => MergeStrategy.discard
    case x =>
      val oldStrategy = (assemblyMergeStrategy in assembly).value
      oldStrategy(x)
  }

lazy val allSettings = baseSettings ++ buildSettings ++ publishSettings ++ assembleSettings

lazy val docSettings = site.settings ++ ghpages.settings ++ unidocSettings ++ Seq(
  site.addMappingsToSiteDir(mappings in (ScalaUnidoc, packageDoc), "docs"),
  git.remoteRepo := s"git@github.com:lookout/borderpatrol.git",
  unidocProjectFilter in (ScalaUnidoc, unidoc) := inAnyProject,
  tutSourceDirectory := baseDirectory.value / "docs" / "src" / "main" / "tut"
)

lazy val root = project.in(file("."))
  .settings(moduleName := "borderpatrol")
  .settings(allSettings)
  .settings(tutSettings)
  .settings(docSettings)
  .settings(noPublish)
  .settings(
    initialCommands in console :=
      """
        |import com.lookout.borderpatrol._
        |import com.lookout.borderpatrol.sessionx._
        |import com.lookout.borderpatrol.server._
        |import com.lookout.borderpatrol.auth._
      """.stripMargin
    )
  .aggregate(core, example, security, auth, server, test)
  .dependsOn(core, auth, server)

lazy val core = project
  .settings(moduleName := "borderpatrol-core")
  .settings(allSettings)
  .settings(
    libraryDependencies ++= Seq(
      "io.circe" %% "circe-core" % circeVersion,
      "io.circe" %% "circe-generic" % circeVersion,
      "io.circe" %% "circe-jawn" % circeVersion,
      "com.nimbusds" % "nimbus-jose-jwt" % nimbusVersion
    )
  )

lazy val test = project
  .settings(moduleName := "borderpatrol-test")
  .settings(allSettings)
  .settings(libraryDependencies ++= testDependencies)
  .dependsOn(core, auth)

lazy val example = project
  .settings(resolvers += Resolver.sonatypeRepo("snapshots"))
  .settings(moduleName := "borderpatrol-example")
  .settings(allSettings)
  .settings(coverageExcludedPackages := "com\\.lookout\\.borderpatrol\\.example\\..*")
  .settings(noPublish)
  .settings(
    libraryDependencies ++= Seq(
      "com.twitter" %% "twitter-server" % twitterServerVersion
    )
  )
  .settings(assemblyJarName in assembly := s"borderpatrol-example-all-${version.value}.jar")
  .disablePlugins(JmhPlugin)
  .dependsOn(core, auth, server, security, test % "test")
  .enablePlugins(BuildInfoPlugin).
    settings(
      buildInfoKeys := Seq[BuildInfoKey](name, version, scalaVersion, sbtVersion),
      buildInfoPackage := "BpBuild"
    )

lazy val security = project
  .settings(moduleName := "borderpatrol-security")
  .settings(allSettings)
  .dependsOn(core % "test->test;compile->compile")

lazy val auth = project
  .settings(moduleName := "borderpatrol-auth")
  .settings(allSettings)
  .dependsOn(core % "test->test;compile->compile")

lazy val server = project
  .settings(moduleName := "borderpatrol-server")
  .settings(allSettings)
  .settings(
    libraryDependencies ++= Seq(
      "com.twitter" %% "finagle-stats" % finagleVersion
    )
  )
  .dependsOn(core % "test->test;compile->compile", auth % "test->test;compile->compile")
