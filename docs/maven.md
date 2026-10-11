# Maven

flint serves Java and other JVM artifacts in the Maven 2 repository layout, which Maven, Gradle, sbt, and other build tools use, from three kinds of Maven repository:

- **Hosted** repositories hold first-party artifacts, which you deploy with `mvn deploy` or Gradle's `maven-publish` plugin.
- **Proxy** repositories cache an upstream repository, such as Maven Central, and keep serving what they cached when it is down.
- **Virtual** repositories merge hosted and proxy repositories behind one URL, so a build needs a single repository, with dependency-confusion protection on by default.

[Configuration](configuration.md#repositories) describes how to declare them.
A typical setup deploys releases and snapshots to two hosted repositories and builds from a virtual repository over them and a Maven Central proxy:

```json
"repositories": [
  {"name": "maven-releases", "format": "maven", "type": "hosted"},
  {"name": "maven-snapshots", "format": "maven", "type": "hosted", "maven": {"versionPolicy": "snapshot"}},
  {"name": "central", "format": "maven", "type": "proxy",
   "proxy": {"url": "https://repo.maven.apache.org/maven2"}},
  {"name": "maven", "format": "maven", "type": "virtual", "anonymousPull": true,
   "virtual": {"members": ["maven-releases", "maven-snapshots",
                           {"name": "central", "exclude": ["com.acme.*"]}]}}
]
```

## URLs

Each repository is served under `/maven/<repository>/`, the URL to give Maven and Gradle, in the Maven 2 layout:

| URL | Serves |
| --- | --- |
| `/maven/<repository>/<group path>/<artifactId>/<version>/<artifactId>-<version>[-<classifier>].<extension>` | An artifact file, such as `/maven/maven/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.jar`. The group's dots become slashes. |
| `/maven/<repository>/<group path>/<artifactId>/maven-metadata.xml` | An artifact's versions, with its `latest` and `release` versions. |
| `/maven/<repository>/<group path>/<artifactId>/<version>-SNAPSHOT/maven-metadata.xml` | A snapshot version's timestamped files. |
| `/maven/<repository>/<group path>/maven-metadata.xml` | A group's plugin prefixes, which Maven uses to find a plugin by its prefix, as in `mvn acme:check`. |
| `<any of the above>.md5`, `.sha1`, `.sha256`, `.sha512` | The file's checksum. |

Artifact files are served with their checksums in `X-Checksum-MD5`, `X-Checksum-SHA1`, `X-Checksum-SHA256`, and `X-Checksum-SHA512` headers, which Maven reads instead of fetching the checksum files.
Directory listings are not served.

## Configuring clients

The examples use `https://registry.example` for flint, and the repositories above.

### Credentials

Maven and Gradle authenticate with HTTP basic credentials: a user name and its password, or a user name and one of the user's [API tokens](auth.md#api-tokens), which is better for builds.
Gradle can also send a token as `Authorization: Bearer <token>`.
A repository with `anonymousPull` needs no credentials to build from.
Building needs the `read` role, deploying `write`, and deleting `delete` ([permissions](auth.md#permissions)).

Neither Maven nor Gradle sends credentials for downloads until a server asks for them, so a request without credentials that needs them gets `401` with `WWW-Authenticate: Basic realm="flint"`, never `404`, and the client then sends them.
Maven sends credentials with uploads right away.

Create a token for a CI job that deploys with the [admin API](auth.md#tokens):

```sh
curl -u alice https://registry.example/api/v1/tokens -d '{
  "name": "ci-deploy",
  "scopes": [{"repositories": ["maven-releases", "maven-snapshots"], "role": "write"}]
}'
```

### Maven

Point every repository Maven uses at the virtual repository with a mirror, and give it credentials in `~/.m2/settings.xml`:

```xml
<settings>
  <mirrors>
    <mirror>
      <id>flint</id>
      <mirrorOf>*</mirrorOf>
      <url>https://registry.example/maven/maven/</url>
    </mirror>
  </mirrors>
  <!-- Resolve snapshots too: Maven's built-in central repository, which
       the mirror stands in for, has them turned off. -->
  <profiles>
    <profile>
      <id>flint</id>
      <repositories>
        <repository>
          <id>central</id>
          <url>http://central</url>
          <snapshots><enabled>true</enabled></snapshots>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>central</id>
          <url>http://central</url>
          <snapshots><enabled>true</enabled></snapshots>
        </pluginRepository>
      </pluginRepositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>flint</activeProfile>
  </activeProfiles>
  <servers>
    <!-- Only needed if the virtual repository has no anonymousPull. -->
    <server>
      <id>flint</id>
      <username>ci-bot</username>
      <password>flint_...</password>
    </server>
  </servers>
</settings>
```

The `<server>`'s `id` matches the mirror's, or a repository's, to give it credentials.
`mirrorOf` `*` sends Maven Central and every repository a project names to flint, plugins included; list the repositories the virtual repository serves instead, as in `central,!internal`, to leave others alone.
A mirror keeps the policy of the repository it stands in for, and Maven's built-in `central` repository does not resolve snapshots, so the profile redefines `central` with snapshots enabled; its URL is never used, since the mirror replaces it.
Without the profile, releases resolve through flint, but snapshot dependencies are not found.

To deploy, name the hosted repositories in the project's `pom.xml`, with servers of the same ids in `settings.xml`:

```xml
<distributionManagement>
  <repository>
    <id>flint-releases</id>
    <url>https://registry.example/maven/maven-releases/</url>
  </repository>
  <snapshotRepository>
    <id>flint-snapshots</id>
    <url>https://registry.example/maven/maven-snapshots/</url>
  </snapshotRepository>
</distributionManagement>
```

```xml
<servers>
  <server><id>flint-releases</id><username>ci-bot</username><password>flint_...</password></server>
  <server><id>flint-snapshots</id><username>ci-bot</username><password>flint_...</password></server>
</servers>
```

and run `mvn deploy`.
A virtual repository with `publishTo` also takes deploys, so `distributionManagement` can name the same URL as the mirror.
`mvn deploy -DaltDeploymentRepository=flint-releases::https://registry.example/maven/maven-releases/` deploys without changing the POM.

Maven refuses plain `http://` repositories other than `localhost` by default (its `maven-default-http-blocker` mirror); serve flint over HTTPS, or for a test instance on another host, override that mirror in `settings.xml`.

### Gradle

Declare the virtual repository in `settings.gradle.kts`, for plugins as well as dependencies:

```kotlin
pluginManagement {
    repositories {
        maven("https://registry.example/maven/maven/")
    }
}
dependencyResolutionManagement {
    repositories {
        maven("https://registry.example/maven/maven/")
    }
}
```

For a repository that needs credentials, add them, from `~/.gradle/gradle.properties` rather than the build:

```kotlin
maven("https://registry.example/maven/maven/") {
    name = "flint"
    credentials(PasswordCredentials::class) // reads flintUsername and flintPassword
}
```

```properties
flintUsername=ci-bot
flintPassword=flint_...
```

Or send an API token as a bearer token:

```kotlin
maven("https://registry.example/maven/maven/") {
    credentials(HttpHeaderCredentials::class) {
        name = "Authorization"
        value = "Bearer ${providers.gradleProperty("flintToken").get()}"
    }
    authentication { create<HttpHeaderAuthentication>("header") }
}
```

Gradle sends basic credentials only after a `401`, which flint gives, unless the repository declares `authentication { create<BasicAuthentication>("basic") }` to send them right away.

To deploy with the `maven-publish` plugin:

```kotlin
plugins {
    `java-library`
    `maven-publish`
}

publishing {
    publications {
        create<MavenPublication>("lib") { from(components["java"]) }
    }
    repositories {
        maven {
            name = "flint"
            val releases = "https://registry.example/maven/maven-releases/"
            val snapshots = "https://registry.example/maven/maven-snapshots/"
            url = uri(if (version.toString().endsWith("SNAPSHOT")) snapshots else releases)
            credentials(PasswordCredentials::class)
        }
    }
}
```

and run `gradle publish`.
Gradle publishes its module metadata (`.module` files), and `.sha256` and `.sha512` checksums besides `.md5` and `.sha1`; flint stores the module files as artifact files and checks every checksum.
Gradle refuses plain `http://` repositories unless the repository sets `isAllowInsecureProtocol = true`.

### Other build tools

sbt, Leiningen, Bazel's `rules_jvm_external`, and other tools that read the Maven 2 layout use the same repository URL and basic credentials.

## Hosted repositories

Deploying uploads each file with its own `PUT`, as Maven and Gradle do: the artifact files, their checksum files, and `maven-metadata.xml`.

- **Version policy.** A hosted repository accepts release versions only, by default; with `"maven": {"versionPolicy": "snapshot"}`, only snapshot versions (those ending in `-SNAPSHOT`); with `"mixed"`, both. A file whose version the policy refuses gets `400`.
- **Layout.** A file must be in the Maven 2 layout: its name starts with its directory's artifactId and version, as in `com/acme/lib/1.0/lib-1.0-sources.jar`. Other paths get `400`.
- **Release files never change.** Deploying different content under the name of a deployed file fails with `409 Conflict`. Deploying the same content again succeeds without a change, so a retried deploy is harmless. A deleted file's name is never usable again, not even with the same content, because a file that came back with other bytes would break every build that had it.
- **Snapshots** are deployed under unique timestamped names, such as `lib-1.0-20261011.120000-3.jar` in `1.0-SNAPSHOT/`, as Maven 3 and Gradle do; each such file never changes either. Non-unique snapshot files, named with `SNAPSHOT` itself, which only Maven 2 deployed, are refused with `400`. Old snapshots are kept until you delete them.
- **flint writes `maven-metadata.xml`.** It generates every artifact's and snapshot version's metadata from what is deployed: versions in Maven's version order, `latest` (the highest version) and `release` (the highest that is not a snapshot), `lastUpdated`, and a snapshot's latest timestamp, build number, and files. The copies clients upload after a deploy are accepted and discarded, so concurrent deploys of different versions never overwrite each other's. The plugin prefixes Maven uploads in a group's metadata when it deploys a plugin are kept.
- **Checksums.** flint computes the MD5, SHA-1, SHA-256, and SHA-512 of every file as it is uploaded, and serves checksum files from those. An uploaded checksum file is checked against the file it belongs to, and refused with `400` if it does not match; it is not otherwise stored.

### Deleting

Deleting needs the `delete` role on the repository:

```sh
curl -u alice -X DELETE https://registry.example/maven/maven-releases/com/acme/lib/1.0/lib-1.0-sources.jar
curl -u alice -X DELETE https://registry.example/maven/maven-releases/com/acme/lib/1.0/
```

The first deletes one file; the second, a version's directory, deletes every file of the version.
Each answers `204`, or `404` if there was nothing to delete.
A deleted file disappears at once, and a version disappears from the metadata once none of its files is left; [garbage collection](garbage-collection.md) later reclaims the disk space.
The deleted names stay used forever, and the repository keeps owning the artifact, for [dependency-confusion protection](#virtual-repositories).

## Proxy repositories

A proxy repository caches one upstream Maven repository, given by its base URL, such as:

- Maven Central, `https://repo.maven.apache.org/maven2`;
- the Gradle Plugin Portal, `https://plugins.gradle.org/m2`, for Gradle plugins;
- Google's Maven repository, `https://maven.google.com`, for Android.

How it serves:

- **Artifact files** (jars, POMs, Gradle module files, signatures, and timestamped snapshot files) never change, so once cached they are served forever without asking the upstream. Each is verified before it is cached, and before a client receives its last byte: against the SHA-1 the upstream announces in its `X-Checksum-SHA1` header, as Maven Central does, or else against the strongest checksum file it serves, `.sha512`, `.sha256`, `.sha1`, or `.md5`. A file that does not match is refused with `502`, or cut off before its last byte if part of it was already sent, and never enters the cache. A file the upstream offers no checksum for is passed through without being cached. Concurrent requests for the same file share one upstream fetch.
- **Checksum files** of a cached file are served from the digests flint computed when it cached the file; for a file not cached, they come from the upstream.
- **`maven-metadata.xml`** changes as versions are published, so a cached copy is served for `revalidateAfter` (default 5 minutes) after the upstream last confirmed it; after that, flint asks the upstream again with the copy's `ETag` and `Last-Modified`, so an unchanged document costs a `304`. A document flint cannot read never replaces the cached one. Its checksum files are computed from the copy flint serves.
- **Not-found answers** are remembered for a minute, because builds ask every repository for files that do not exist, such as sources and Gradle module files of artifacts that have none.
- **When the upstream is unreachable**, cached files and metadata keep being served, and flint treats the upstream as offline for 30 seconds; a file that was never cached is answered with `503`. **When the upstream answers that something is not found or denied**, flint answers `404`.
- **Non-unique snapshot files** and paths outside the layout, such as `archetype-catalog.xml`, are passed through from the upstream without being cached.
- **Disk space and size limits** work as for [OCI proxy repositories](configuration.md#proxy-repositories): under `proxyCache.minFreeSpace`, new files are passed through, still verified, without being cached; with `proxy.sizeLimit`, the least recently downloaded files are evicted to stay within the limit. Metadata does not count against the limit.
- **Fetch policy.** flint fetches only from the host of `proxy.url`, the hosts its well-known upstreams redirect files to (`plugins-artifacts.gradle.org` for `plugins.gradle.org`, `dl.google.com` for `maven.google.com`), and the hosts in `proxy.allowHosts`; see [the fetch policy](configuration.md#upstream-fetch-policy).
- **Credentials.** With `proxy.username` and `proxy.passwordFile`, flint sends basic credentials to the upstream's own host, never to another.
- **Read-only.** Deploys and deletes are refused with `405`.

## Virtual repositories

A virtual repository serves one repository over an ordered list of hosted and proxy members, and resolves every request by the artifact it belongs to, `groupId:artifactId`:

- **Metadata merges.** An artifact's `maven-metadata.xml` lists the versions of every member that has the artifact, and its `latest` and `release` are computed from the merged list. A group's plugin prefixes merge by plugin, the first member's winning.
- **Files come from the member that has their version.** A hosted member that lists the version serves all of its files; otherwise the first proxy member that has the file serves it. A snapshot version's metadata comes from the first member that has the version.
- **Filters.** A member with `include` or `exclude` patterns is consulted only for the artifacts they admit, matched against `groupId:artifactId`, with `:` and `.` as one separator, so `com.acme.*` matches every artifact of group `com.acme`, such as `com.acme:lib`, and of its subgroups, such as `com.acme.tools:cli`. Exclude your internal groups from proxy members, as in `{"name": "central", "exclude": ["com.acme.*"]}`: dependency-confusion protection covers an artifact only once a hosted member owns it, and the filter also covers internal artifacts not deployed yet.
- **Dependency-confusion protection**, on by default: once a hosted member owns an artifact, its upstream versions are never served through the virtual repository, not even versions the hosted member lacks, and the proxy members are not even asked about it. A hosted repository owns an artifact from the first deploy of a file of it, and keeps it after every file is deleted. So an artifact someone publishes upstream under your group and artifact name can never be resolved in place of yours. Set `virtual.dependencyConfusionProtection` to `false` to merge every member for every artifact.
- A member that fails, such as a proxy whose upstream is unreachable with nothing cached, is left out with a warning in the log, counted in `flint_virtual_member_skips_total`. The request fails only if no member could answer.
- **Deploys** go to the hosted member that `virtual.publishTo` names, and need the permissions a deploy to it needs; an artifact that member's filters do not admit is refused with `403`. Without `publishTo`, deploys are refused with `405`, naming the hosted members to deploy to instead.

Building through a virtual repository needs the `read` role on the virtual repository, or its `anonymousPull`; the members' own permissions are not consulted.

## Not supported

- The Maven 1 layout.
- WebDAV (`PROPFIND`, `MKCOL`), which only Maven's old WebDAV wagon uses.
- Non-unique snapshots.
- Directory listings and search; the UI covers browsing.
- Server-side archetype catalogs.
