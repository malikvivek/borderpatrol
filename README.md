# BorderPatrol

Border Patrol is a type-safe, immutable, functional Scala library built on top of [Finagle](https://finagle.github.io/)
that provides modular components useful for session management and authentication. This library is used at
[Lookout](http://lookout.com) for single sign on with support for multiple authentication backends.

![Overview Diagram](images/BpBlockDiagram.png)

The original version (as a server) can be found here (nginx+lua): [ngx_borderpatrol](https://www.github.com/lookout/ngx_borderpatrol)

Badges
------

[![Join the chat at https://gitter.im/lookout/borderpatrol](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/lookout/borderpatrol?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Build Status](https://travis-ci.org/lookout/borderpatrol.png)](https://travis-ci.org/lookout/borderpatrol)
[![Coverage Status](https://img.shields.io/codecov/c/github/lookout/borderpatrol/master.svg)](https://codecov.io/github/lookout/borderpatrol)

Border Patrol Concepts
----------------------

 * The Border Patrol fronts all services (configured using `ServiceIdentifier`) in a Cloud.
 * The Cloud is identified by one or more subdomains (configured using `CustomerIdentifier`)
 * The Cloud, typically, has an identity `endpoint` (for authentication) and access `endpoint` (for authorization).
 * The identity endpoint, access endpoint, subdomains and default service forms the policy, which is defined using
`LoginManager`.
 * When a HTTP request with URL `<http[s]>://<subdomain>:[port]/<path-prefix>` hits BorderPatrol:
   * It can check whether or not a host specified is supported by this instance of BorderPatrol.
   * It looks up the CustomerIdentifier using subdomain prefix. It returns 404, if no match is found.
   * It looks up the ServiceIdentifier using path prefix. In the absence of any path (i.e. Root), the request is
redirected to the default service.

Border Patrol Components:
-------------------------

 * Service Identifier:
   * A service can be configured as protected (default) or unprotected.
   * Once authenticated, the user has access to all the protected services in the Cloud
   * The user (authenticated or not) has access to all the unprotected services in the Cloud
   * A service identifier is comprised of a "unique" `/path` located on an upstream `[hosts]` in the Cloud.
   * The Service path is mapped onto the subdomain that Border Patrol represents.
 * Endpoint:
   * An endpoint is represented by set of URLs and a unique path.
   * Border Patrol connects to these remote REST endpoints fetches information or execute operations such as
identity provisioning (i.e. identity endpoint), access issuing (i.e. access endpoint), authorization (external
endpoint that does identity provisioning), token issuing (i.e. issues token for oauth2 code), etc.
 * Identity Endpoint:
   * If external authentication (e.g. OAuth2) is used, then identity endpoint provisions the user in Cloud.
   * Currently, there are 2 identity provider service chains available for `tokenmaster.basic` and `tokenmaster.oauth2`.
   * The `tokenmaster.basic` chain simply sends the user credentials to an identity endpoint in the Cloud.
   * The `tokenmaster.oauth2` chain redirects the user to authorization endpoint, with instructions to return the oauth2
code after authentication. The user authenticates with oauth2 server and oauth2 server returns oauth2 code (via browser
redirect) to Border Patrol. The BorderPatrol user token endpoint to convert oauth2 code into access token. The Border
Patrol fetches certificate from certificate endpoint and verifies the access token. The Border Patrol uses triple of
subject, login manager name and subdomain to authenticate the user to identity endpoint.
   * The identity endpoint responds with a Master Token. The Master Token is cached in the Session.
   * The implementation is modular and new service chains can easily be added
 * Access Endpoint:
   * `tokenmaster.basic` and `tokenmaster.oauth2` use the same access service chain. It sends service name and
Master Token to the access endpoint in the Cloud. That responds with a Service Token.
   * The Service Token is cached in the Session.
   * The implementation is modular and new service chains can easily be added
   * It relays Request w/ Service Token to the upstream endpoints, so that it can validate it.
 * Session Store:
   * A store is used to cache information about a Session.
   * A SessionId (a signed id with an expiry) acts a key to the session. The SessionId is sent to the user as a cookie
in the HTTP response.
   * For unauthenticated user, the Session contains original Request
   * For authenticate user, the Session contains Master Token and one or more Service Token(s)
 * Secret Store:
   * A store is used to cache secret used to sign the session id(s)
 * Host Checker:
   * A filter that blocks any request with a host entry that is not present in the `allowedDomains` entry.
If request does not contain host header, this filter is a noop.
This filter is applied by default and the config will throw an exception if there is *no entry/0* entries for this field.
The code should be updated if you don't intend on using it.

Configuration
-------------

 * `secretStore`: Secret Store. It can be configured using `type` as `InMemorySecretStore` or `ConsulSecretStore`.
   * `InMemorySecretStore`: Typically used for single host setup as Secrets are meant to be shared across all the BorderPatrol nodes.

     ```json
     "secretStore" : {
       "type" : "InMemorySecretStore",
     }
     ```

   * `ConsulSecretStore`: Setting up Consul is outside of the scope.
     * `hosts`: A list of consul URLs (Format: `[<http[s]>://<host>:[port]]+`)
     * `key`: BorderPatrol uses the key-value store for storing the secret. The `key` is configurable.

     ```json
     "secretStore" : {
       "type" : "ConsulSecretStore",
       "hosts": ["http://localhost:8500"],
       "key": "BpSecrets"
     }
     ```

 * `sessionStore`: Session Store. It can be configured using `type` as `InMemoryStore` or `MemcachedStore`.
   * `InMemoryStore`: Typically used for single host setup as Sessions are meant to be shared across all the BorderPatrol nodes.

     ```json
     "sessionStore" : {
       "type" : "InMemoryStore",
     }
     ```

   * `MemcachedStore`: Setting up Memcached is outside of the scope. BorderPatrol uses it to store Sessions.
     * `hosts`: A comma separated list of of memcached host and port (Format: `<host>:[port],<host>:[port]`)

     ```json
     "sessionStore" : {
       "type" : "MemcachedStore",
       "hosts" : "localhost:123,localhost:234"
     }
     ```

 * `endpoints`: A list of `endpoint`s.
 * `endpoint`:
   * `hosts`: A list of endpoint URLs (Format: `[<http[s]>://<host>:[port]]+`)
   * `path`: A path serviced by the endpoint.
   * `name`: A unique name that identifies this endpoint
 * `loginManagers`: A list of LOGIN `Manager`s
 * `loginManager`: It defines policy items such as authentication backend, identity endpoint, access endpoint, etc used
for the given CustomerIdentifier.
   * `name`:  unique name that identifies this Login Manager
   * `guid`: the global UID for the login manager
   * `identityEndpoint`: Identity endpoint name used by this Login Manager
   * `accessEndpoint`: Access endpoint used by this Login Manager
   * `loginConfirm`: The path at which `Internal` login form or external authenticator posts the login
credentials
   * `type`: The type of proto used. Currently supported types are `tokenmaster.basic` and `tokenmaster.oauth2`
     * `tokenmaster.basic` specific config:
       * `authorizePath`: A path to request login form
     * `tokenmaster.oauth2` specific config:
       * `authorizeEndpoint`: An endpoint to request an authorization code for access to a resource
       * `tokenEndpoint`: An endpoint to request access token using authorization code
       * `certificateEndpoint`: An endpoint to fetch certificate to verify token signature
       * `clientId`: Client id of the OAuth2 server application
       * `clientSecret`: Client secret of the OAuth2 server application
 * `serviceIdentifiers`: A list of services in the cloud.
 * `serviceIdentifier`: A service.
   * `hosts`: A list of service URLs (Format: `[<http[s]>://<host>:[port]]+`)
   * `name`: A unique name that identifies this Service. For protected services, the access issuer must be aware of
this service
   * `path`: A path serviced by the service, which is mapped on the subdomain.
   * `rewritePath`: If configured, this path replaces the `path` in the incoming Request
   * `protected`: If the service is NOT protected, then it bypasses access issuer. The default is `true`.
 * `customerIdentifiers`: A list of customer identifiers.
 * `customerIdentifier`:
   * `loginManager`: Login Manager or policy used by this customer identifier
   * `guid`: the global UID for the subdomain
   * `subdomain`: A subdomain represented by this identifier
   * `defaultServiceIdentifier`: The default "protected" service for this customer identifier
 * `statdReporter`: The statsd reporter configuration
   * `host`: Upstream statsd endpoint
   * `durationInSec`: Reporting frequency in Seconds.
   * `prefix`: Prefix attached to each reported stat
 * `listeningPort`: Border Patrol listens to new requests on this port.
 * `healthCheckEndpoints`: A set of endpoints that impact the Border Patrol Health Status
 * `allowedDomains`: Border Patrol checks whether incoming request has a host header value present
in this set. 

     ```json
     "allowedDomains" : [ "api.localhost", "ent.localhost"],
     ```
    * If the domain name is "example.com"
    
    ```json
     "allowedDomains" : [ "api.example.com", "ent.example.com"],
     ```

Modules
-------

Border Patrol uses a multi-project structure and contains the following _modules_:

* [`core`](core) - the core classes/functions
* [`auth`](auth) - different authentication plugins for core auth
* [`security`](security) - different security plugins, e.g. CSRF protection
* [`server`](server) - a server composing these modules that can be configured
* [`example`](example) - the demo app showing sessions and authentication for multiple
services. It mocks the authentication (aka identity provider), authorization (aka access issuer) and upstream
endpoints.

Installation
------------

Every stable Border Patrol module is published at Bintray. The SNAPSHOT builds are published to JFrog.

* _stable_ release:

```scala
libraryDependencies ++= Seq(
  "com.lookout.borderpatrol" %% "[borderpatrol-module]" % "0.2.0"
)
```

* `SNAPSHOT` release:

```scala
libraryDependencies ++= Seq(
  "com.lookout.borderpatrol" %% "[borderpatrol-module]" % "0.2.10-SNAPSHOT"
)
```

Building Border Patrol
----------------------

To build Border Patrol you should have [sbt](http://www.scala-sbt.org/0.13/tutorial/Setup.html)
installed (prefer v0.13.8+). Run `sbt`, and then use any of the following commands:

 * `compile`: compile the code
 * `project [project]`: to switch projects, e.g. "project example"
 * `console`: launch a REPL
 * `test`: run the tests
 * `unidoc`: generate the documentation
 * `scalastyle`: run the style-checker on the code
 * `validate`: run tests, style-checker, and doc generation

Running the example
-------------------

* To test and work with subdomain routing locally, ensure to update your /etc/hosts file to include subdomains to
  localhost. For example:
  ```text
  127.0.0.1 ent.localhost
  ```

* Run
  ```text
  $ sbt
  > project example
  > run
  ```

Documentation
-------------

* Scaladoc is available at [http://lookout.github.io/borderpatrol/docs](http://hackers.lookout.com/borderpatrol/docs/#com.lookout.borderpatrol.package)
* Markdown documents are available [here](https://github.com/lookout/borderpatrol/tree/master/docs/src/main/tut).  The code examples are fully runnable in a Scala REPL verified with [tut](https://github.com/tpolecat/tut).  Use `sbt tut` to compile example code in markdown (`docs/src/main/tut`) which outputs to `target/scala-N.NN/tut`

Contributing
------------

We would love to make this better, so please help us!

* [Submit a PR](CONTRIBUTING.md) including an issue label ["easy"](https://github.com/lookout/borderpatrol/issues?q=is%3Aopen+is%3Aissue+label%3Aeasy)
* Write ScalaDoc comments
* Write tutorials and examples
* Improve tests
* Help with code review
* Give it a star
* Join us on IRC `#borderpatrol` on [Freenode](http://freenode.net)

License
-------

We use the MIT License [License](LICENSE)
