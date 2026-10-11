# Configuration

flint reads one JSON file, given with `flint serve -config <file>` (default `/etc/flint/config.json`).
The [Helm chart](helm.md#configuration) renders it from YAML values; outside Kubernetes you write it by hand.

The file is decoded strictly.
An unknown field, a value of the wrong type, or anything after the top-level object is an error, so a misspelled field never falls back to a default silently.
Every problem found is reported at startup, each with its JSON path, for example `repositories[1].name: "Docker" is not a valid repository name: ...`.
flint does not start with an invalid configuration.
`flint config check <file>` checks a file the same way without starting the server, and prints `<file>: ok` or the problems it found.

Users and API tokens are runtime data kept in the metadata store, not configuration; see [authentication](auth.md).
Repositories and permission grants declared here are read-only through the API.

## Example

[`flint.example.json`](flint.example.json), which the tests keep valid:

```json
{
  "listen": ":8443",
  "dataDir": "/var/lib/flint",
  "publicURL": "https://flint.example.com",
  "tls": {
    "certFile": "/etc/flint/tls/tls.crt",
    "keyFile": "/etc/flint/tls/tls.key"
  },
  "trustedProxies": ["10.42.0.0/16", "192.168.1.10"],
  "shutdownTimeout": "25s",
  "log": {
    "level": "info"
  },
  "repositories": [
    {
      "name": "docker-local",
      "format": "oci",
      "type": "hosted"
    },
    {
      "name": "releases",
      "format": "oci",
      "type": "hosted",
      "immutableTags": true,
      "anonymousPull": true,
      "helmIndex": true
    },
    {
      "name": "dockerhub",
      "format": "oci",
      "type": "proxy",
      "proxy": {
        "url": "https://registry-1.docker.io",
        "username": "flint-mirror",
        "passwordFile": "/etc/flint/upstream/dockerhub/password",
        "revalidateAfter": "5m"
      }
    },
    {
      "name": "ghcr",
      "format": "oci",
      "type": "proxy",
      "proxy": {
        "url": "https://ghcr.io",
        "sizeLimit": "200GiB"
      }
    },
    {
      "name": "pypi-local",
      "format": "pypi",
      "type": "hosted"
    },
    {
      "name": "pypi",
      "format": "pypi",
      "type": "proxy",
      "proxy": {
        "url": "https://pypi.org/simple/",
        "revalidateAfter": "10m"
      }
    },
    {
      "name": "pypi-all",
      "format": "pypi",
      "type": "virtual",
      "anonymousPull": true,
      "virtual": {
        "members": [
          "pypi-local",
          {"name": "pypi", "exclude": ["acme-*"]}
        ],
        "publishTo": "pypi-local"
      }
    },
    {
      "name": "files",
      "format": "generic",
      "type": "hosted"
    },
    {
      "name": "tool-releases",
      "format": "generic",
      "type": "proxy",
      "generic": {
        "immutable": true
      },
      "proxy": {
        "url": "https://github.com/acme/tool/releases/download/",
        "allowHosts": ["release-assets.githubusercontent.com", "objects.githubusercontent.com"]
      }
    },
    {
      "name": "cargo-local",
      "format": "cargo",
      "type": "hosted"
    },
    {
      "name": "crates-io",
      "format": "cargo",
      "type": "proxy",
      "proxy": {
        "url": "sparse+https://index.crates.io/"
      }
    },
    {
      "name": "cargo-all",
      "format": "cargo",
      "type": "virtual",
      "virtual": {
        "members": [
          "cargo-local",
          {"name": "crates-io", "exclude": ["acme-*"]}
        ],
        "publishTo": "cargo-local"
      }
    },
    {
      "name": "npm-local",
      "format": "npm",
      "type": "hosted"
    },
    {
      "name": "goproxy",
      "format": "go",
      "type": "proxy",
      "proxy": {
        "url": "https://proxy.golang.org"
      }
    },
    {
      "name": "go-corp",
      "format": "go",
      "type": "proxy",
      "proxy": {
        "url": "https://goproxy.corp.example.com",
        "username": "flint",
        "passwordFile": "/etc/flint/upstream/go-corp/password"
      },
      "go": {
        "noSumCheck": ["corp.example.com/*"]
      }
    },
    {
      "name": "go-all",
      "format": "go",
      "type": "virtual",
      "virtual": {
        "members": [
          {"name": "go-corp", "include": ["corp.example.com/*"]},
          {"name": "goproxy", "exclude": ["corp.example.com/*"]}
        ]
      }
    },
    {
      "name": "docker",
      "format": "oci",
      "type": "virtual",
      "virtual": {
        "members": ["docker-local", "dockerhub", "ghcr"],
        "publishTo": "docker-local"
      }
    }
  ],
  "proxyCache": {
    "minFreeSpace": "5%"
  },
  "backup": {
    "directory": "/var/backups/flint"
  },
  "gc": {
    "gracePeriod": "24h",
    "interval": "24h"
  },
  "audit": {
    "retention": {
      "maxAge": "17520h"
    }
  },
  "auth": {
    "bootstrapAdmin": {
      "username": "admin",
      "passwordFile": "/etc/flint/admin/password"
    },
    "permissions": [
      {
        "repositories": ["docker-local", "releases", "pypi-local", "files", "cargo-local", "npm-local"],
        "role": "write",
        "groups": ["ci"]
      },
      {
        "repositories": ["dockerhub", "ghcr", "docker", "pypi", "crates-io", "cargo-all", "go-all"],
        "role": "read",
        "groups": ["ci"]
      },
      {
        "repositories": ["team-a-*"],
        "role": "admin",
        "users": ["alice"]
      }
    ]
  }
}
```

The smallest valid file is `{"dataDir": "/var/lib/flint"}`: plain HTTP on port 5000, no repositories.

## Fields

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `listen` | string | `":5000"` | TCP address to listen on, `host:port`. An empty host listens on every interface. |
| `dataDir` | string | required | Absolute path of the data directory. It is created if missing, and locked (`<dataDir>/LOCK`) so a second flint process on it refuses to start. |
| `tls` | object | none | Serve HTTPS from certificate files. Without it flint serves plain HTTP, for example behind a TLS-terminating proxy. |
| `tls.certFile` | string | required with `tls` | PEM certificate chain, leaf first. |
| `tls.keyFile` | string | required with `tls` | PEM private key for the certificate. |
| `trustedProxies` | array of strings | `[]` | IP addresses or CIDR prefixes of proxies whose forwarded headers are believed. |
| `publicURL` | string | none | The URL clients reach flint at, such as `"https://flint.example.com"`; see [public URL](#public-url). |
| `shutdownTimeout` | duration string | `"25s"` | How long a graceful shutdown waits for in-flight requests before closing their connections. Must be positive. |
| `log.level` | string | `"info"` | Minimum log level: `debug`, `info`, `warn`, or `error`. |
| `repositories` | array | `[]` | Repositories declared in configuration; see below. |
| `auth.permissions` | array | `[]` | Permission grants; see below. |
| `auth.bootstrapAdmin` | object | none | Create the first administrator at startup if none exists; see below. |
| `auth.loginTokenTTL` | duration string | `"2160h"` | How long an API token minted by a package client's login command stays valid (90 days by default); see [authentication](auth.md#tokens-from-client-login-commands). Must be positive. |
| `backup.directory` | string | none | Absolute path of the [backup](backup.md) directory, outside the data directory and not containing it. Without it, backups are disabled. |
| `proxyCache.minFreeSpace` | string | `"5%"` | Free space on the data directory's filesystem below which [proxy repositories](#proxy-repositories) stop caching new content: a percentage of the filesystem's size, such as `"5%"`, or a size, such as `"20GiB"`. |
| `gc.gracePeriod` | duration string | `"24h"` | How long [garbage collection](#garbage-collection) keeps a blob that nothing references after the blob was stored, and a blob link that no manifest references after it was last written or read with a blob `HEAD` or `GET`, or after flint started; so also how long a push may take between uploading or checking its blobs and pushing its manifest. At least `"1h"`. |
| `gc.interval` | duration string | none | Run garbage collection on a schedule, this long after the previous run started. Without it, garbage collection runs only when an administrator starts it. |
| `audit.retention.maxAge` | duration string | none | Delete [audit log](operations.md#retention) records once they are older than this, such as `"8760h"`, a file at a time, within about half of this after they pass it. Without it, records are kept forever. |
| `audit.retention.maxSize` | string or number | none | Delete the oldest audit log records, a file at a time, while the audit log is larger than this size, such as `"10GiB"`, keeping it within about a quarter of this of the limit. Without it, there is no limit. |

Durations are Go duration strings: a number and a unit, such as `"30s"`, `"2m"`, or `"1m30s"`.
Sizes are a number of bytes, or a number and a unit: `kB`, `MB`, `GB`, `TB`, and `PB` count in powers of 1000, and `KiB`, `MiB`, `GiB`, `TiB`, and `PiB` in powers of 1024, with or without the final `B` (`Gi`), such as `"500MiB"` or `"1.5TB"`.

### TLS

flint checks the certificate and key files every 10 seconds and loads them when their contents change, without a restart or dropped connections.
This works with Kubernetes secrets mounted into a pod, which the kubelet updates by swapping a symlink.
If the new files do not load, for example because the certificate was replaced before its key, flint keeps serving the previous certificate, logs the error once, and loads the files as soon as they form a valid pair.
At startup the files must load, or flint exits.
HTTPS serves HTTP/1.1 and HTTP/2, with TLS 1.2 as the minimum version.

### Trusted proxies

flint believes `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` only on connections from an address in `trustedProxies`; from anyone else they are ignored.
The client address is found by reading `X-Forwarded-For` from right to left and skipping trusted proxies: the first untrusted address is the client.
`X-Forwarded-Proto` (`http` or `https`) and `X-Forwarded-Host` use their first value.
A bare IP address means that one address; IPv4-mapped IPv6 addresses match IPv4 entries.

### Public URL

Some package protocols put absolute URLs into the metadata clients store, such as the URLs in PyPI's JSON API, which tools record, the download and API URLs in a Cargo index's `config.json`, and npm tarball URLs, which lockfiles record.
`publicURL` is the base of every absolute URL flint writes into served metadata, so those URLs stay the same however a client reached flint: through an ingress, a port forward, or an internal service name.
It is an `http` or `https` URL without credentials, a query, or a fragment; it may have a path, when a reverse proxy serves flint under one and strips it before forwarding.
Without it, absolute URLs are built from the scheme and host of each request, as seen through [trusted proxies](#trusted-proxies).
It is also the base of the login URLs flint gives clients, such as Cargo's `login_url`.
The Docker token realm, the token endpoint named in a registry's `401` challenge, does not use it and always follows the host the client used, so a client that reached flint by an internal name gets its token from that same host.
Where a protocol allows relative URLs, such as PyPI's project pages and the classic Helm index, flint writes relative ones and `publicURL` does not matter.
Cached upstream content is stored as the upstream sent it and rewritten when served, so changing `publicURL` takes effect at once.

### Repositories

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | required | The repository's name, which clients address it by: the path prefix of its images, as in `host/docker-local/team/app`, of its index, as in `host/pypi/pypi-local/simple/` or `host/cargo/cargo-local/`, of its npm registry URL, as in `host/npm/npm-local/`, of its Go module proxy, as in `host/go/go-all/`, of its files, as in `host/generic/files/tools/app.tar.gz`, or of its Maven repository, as in `host/maven/maven-releases/`. 1 to 64 lowercase letters and digits, with single `.`, `_`, or `-` separators between them. Unique across formats. |
| `format` | string | required | Package format: `oci` for container images and OCI artifacts, `pypi` for Python packages, `generic` for arbitrary files addressed by path, `cargo` for Rust crates, `npm` for npm packages, `maven` for Java and other JVM artifacts, or `go` for Go modules. |
| `type` | string | required | Repository type: `hosted`, which clients publish to, for every format but `go`; `proxy`, a read-only cache of an upstream registry, index, repository, or module proxy; or, for `oci`, `pypi`, `generic`, `cargo`, `maven`, and `go`, `virtual`, one view merged from other repositories of its format. `npm` repositories are hosted. A repository of format `<format>` is served under `/<format>/<name>/`, except OCI's, which are under `/v2/`; another format's path does not find it. |
| `immutableTags` | bool | `false` | Hosted OCI repositories only. Make a pushed tag permanent: pushing another manifest under it, deleting it, or deleting a manifest it points to is refused with `409 DENIED`. Pushing the same manifest again is allowed. |
| `anonymousPull` | bool | `false` | Let unauthenticated clients pull. |
| `helmIndex` | bool | `false` | Hosted OCI repositories only. Also serve the Helm charts pushed to the repository as a classic Helm chart repository at `/helm/<name>/`; see [Helm chart repositories](#helm-chart-repositories). |
| `proxy` | object | required for `proxy` | The upstream of a proxy repository; see below. Not allowed for other types. |
| `virtual` | object | required for `virtual` | The members of a virtual repository; see below. Not allowed for other types. |
| `generic` | object | none | Settings of a `generic` repository; see [generic files settings](#generic-files-settings). Not allowed for other formats. |
| `maven` | object | none | Maven repositories only: the format's settings, below. |
| `maven.versionPolicy` | string | `"release"` | Hosted Maven repositories only. The versions the repository accepts: `release` for release versions only, `snapshot` for snapshot versions (ending in `SNAPSHOT`) only, or `mixed` for both; see [Maven](maven.md#hosted-repositories). |
| `go` | object | none | Go proxy repositories only. The checksum database modules are verified against; see [Go repository settings](#go-repository-settings). |

### Proxy repository settings

A proxy repository caches one upstream: a registry such as Docker Hub, ghcr.io, or quay.io, a Python package index such as pypi.org, a Cargo sparse index such as crates.io's, a Maven repository such as Maven Central, a Go module proxy such as proxy.golang.org, or, for generic files, any web server. [Proxy repositories](#proxy-repositories) describes how an OCI proxy serves pulls, and [PyPI](pypi.md#proxy-repositories), [generic files](generic.md#proxy-repositories), [Cargo](cargo.md#proxy-repositories), [Maven](maven.md#proxy-repositories), and [Go modules](go.md#proxy-repositories) how theirs do.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `proxy.url` | string | required | For `oci`, the upstream registry's base URL, without a path, such as `"https://registry-1.docker.io"` or `"https://ghcr.io"`; for Docker Hub (`registry-1.docker.io`), a single-component image name gets the `library/` prefix, as Docker clients add it: `dockerhub/nginx` pulls `library/nginx`. For `pypi`, the upstream's simple index URL, the one you would give pip as `--index-url`, such as `"https://pypi.org/simple/"` or `"https://download.pytorch.org/whl/cpu"`; a URL without a path gets `/simple/`, so `"https://pypi.org"` works too. For `generic`, any base URL, such as `"https://github.com/acme/tool/releases/download/"`: a request for `<path>` fetches `<url>/<path>`. For `cargo`, the upstream's sparse index URL, as you would give Cargo, such as `"sparse+https://index.crates.io/"`; the `sparse+` prefix is optional. For `maven`, the upstream repository's base URL, such as `"https://repo.maven.apache.org/maven2"` for Maven Central. For `go`, the upstream module proxy's URL, as `GOPROXY` would name it, such as `"https://proxy.golang.org"`; it may have a path. |
| `proxy.username` | string | none | User name for the upstream, such as a Docker Hub account for its higher pull limits. Requires `passwordFile`. A Cargo registry that challenges for a token gets the password file's token alone, as Cargo sends it; set any user name. See the warning below. |
| `proxy.passwordFile` | string | none | Absolute path of a file holding the upstream password or access token, such as a mounted Kubernetes Secret. One trailing newline is ignored. flint reads it at startup, failing to start if it cannot, and again whenever it authenticates to the upstream, so a rotated secret takes effect without a restart. It is never logged. Requires `username`. |
| `proxy.revalidateAfter` | duration | `"5m"` | How long a cached tag, tag listing, referrers listing, or document, such as a PyPI project page, a generic file without `generic.immutable`, a Cargo index file, a `maven-metadata.xml`, or a Go module's version list, is served before the upstream is asked again. Must be positive. |
| `proxy.sizeLimit` | size | none | Cap the content cached in this repository. Over the cap, the least recently pulled content is evicted. Without it, everything is cached forever. For `generic`, only with `generic.immutable`, since only files cached forever count against it. |
| `proxy.maxConcurrent` | integer | `64` | Requests the repository may have in flight to its upstream at once, each from when it is sent until its response has been read; further requests wait, and the wait does not count against their timeouts or mark the upstream unavailable. Keeps a burst of client requests, such as a large install, from turning into a rate-limit ban. |
| `proxy.allowHosts` | array of strings | none | Hosts besides the upstream's own that the repository may fetch from when upstream content or a redirect points at them: a host name or IP address, optionally with a port (`"cdn.example.com"`, `"10.0.0.7:9000"`), or `"*.example.com"` for every subdomain of `example.com`. See [the fetch policy](#upstream-fetch-policy). |

> **Warning: upstream credentials are shared with everyone who can pull.**
> flint sends every upstream request of a proxy repository with its configured account, so anyone allowed to pull from that repository, including anonymous clients with `anonymousPull`, can read whatever that account can read upstream, including its private repositories.
> Use a dedicated account that has no private content, or an access token limited to public, read-only access, such as a Docker Hub personal access token with the *Public Repo Read-only* scope.

### Go repository settings

A Go proxy repository checks every module version against the Go checksum database before it caches the version's `go.mod` file and module zip, and also serves the database to clients; [Go modules](go.md#verification-against-the-checksum-database) describes both. The optional `go` object chooses the database, and the modules it does not check.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `go.sumdb.key` | string | sum.golang.org's key | The checksum database's public key, as `GOSUMDB` names one: `<name>+<hash>+<key>`, such as `"sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"`. Its name is the one clients use for the database, as in `/go/<repository>/sumdb/<name>/`. |
| `go.sumdb.url` | string | `"https://<name>"` | Where flint fetches the database from, such as a mirror of it; an `http` or `https` URL, which may have a path. |
| `go.noSumCheck` | array of strings | none | Module paths, or patterns in which `*` matches any run of characters, whose modules are cached without being checked, such as `["corp.example.com/*"]`: the private modules of a private upstream, which a public checksum database does not know. Clients name them in `GONOSUMDB` too. |

### Upstream fetch policy

A proxy repository fetches only from its upstream's host and the hosts its format allows for that upstream:

- **OCI** registries may redirect blob downloads to, and name their token service on, any host, as the distribution protocol allows, so every public host is allowed.
- **PyPI** indexes link their files: the index's own host, `files.pythonhosted.org` for `pypi.org`, and `test-files.pythonhosted.org` for `test.pypi.org`.
- **Generic** proxies fetch only from the upstream's own host. A download site that redirects to another host, as GitHub release downloads redirect to `release-assets.githubusercontent.com` (and, for older releases, `objects.githubusercontent.com`), needs that host in `proxy.allowHosts`.
- **Cargo** indexes name where their crates are downloaded and their web API in `config.json`: the index's own host, and `static.crates.io` and `crates.io` for `index.crates.io`.
- **Maven** repositories redirect some downloads: the repository's own host, `plugins-artifacts.gradle.org` for `plugins.gradle.org`, and `dl.google.com` for `maven.google.com`.
- **Go** module proxies serve everything from their own host; a Go proxy repository also fetches its checksum database from the host of `go.sumdb.url` (default `sum.golang.org`), which may resolve to an internal address since the configuration names it, and which never gets the upstream credentials.
- `proxy.allowHosts` adds further hosts.

Redirects are followed only to allowed hosts. flint refuses to connect to loopback, link-local, private, shared (`100.64.0.0/10`), and unspecified (`0.0.0.0/8`) addresses, and to IPv6 addresses that embed one (NAT64 `64:ff9b::/96`, 6to4 `2002::/16`), except for the host of `proxy.url` and the hosts in `proxy.allowHosts`, which the configuration names: the check runs on the address a name resolves to when flint connects, so upstream content, a redirect, or a token challenge can never steer flint at a service inside its network. A refused fetch is answered `502`. Credentials are only ever sent to the host of `proxy.url`. The `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` environment variables apply to upstream requests; with a proxy configured, flint connects to the proxy, which then decides where requests go.

### Virtual repository settings

A virtual repository serves one view merged from an ordered list of hosted and proxy repositories of its format, so clients need a single URL. `oci`, `pypi`, `generic`, `cargo`, `maven`, and `go` have virtual repositories; [OCI virtual repositories](#oci-virtual-repositories), [PyPI](pypi.md#virtual-repositories), [Cargo](cargo.md#virtual-repositories), [Maven](maven.md#virtual-repositories), and [Go modules](go.md#virtual-repositories) describe how they merge, and [generic files](generic.md#virtual-repositories) how a generic one serves each path from the first member that has it.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `virtual.members` | array | required | The member repositories, in order of precedence: hosted or proxy repositories of the same format, each named once. Where several members have the same version or file of a package, the first one's is served. Each member is a repository name, or an object with `name` and the filters below, such as `{"name": "pypi", "exclude": ["acme-*"]}`. |
| `virtual.members[].name` | string | required | The member repository. |
| `virtual.members[].include` | array of strings | all names | Package names, or patterns in which `*` matches any run of characters, that the member is consulted for. Without it, the member is consulted for every name. |
| `virtual.members[].exclude` | array of strings | none | Package names or patterns the member is never consulted for, even if `include` matches them. |
| `virtual.publishTo` | string | none | A hosted member that receives what clients publish to the virtual repository, so one URL serves both installing and publishing; for `oci`, pushes and deletes. A publish of a package whose name the member's `include` and `exclude` filters do not admit is refused with `403`, naming the member and the filter, since the virtual repository would not serve it. Without it, the virtual repository refuses uploads. |
| `virtual.dependencyConfusionProtection` | bool | `true` | Once a hosted member owns a package name, never serve that name from a proxy member, so a package published upstream under the same name can never replace or mix with the first-party one. A hosted repository owns a name from the first upload of a file of it, or the first publish of a crate, also after everything is deleted; a hosted OCI repository owns an image name while it holds a tag of it or a manifest of it without a `subject`, other than the signature tag schema's `sha256-<digest>.sig`, `.att`, and `.sbom` tags and the manifests only they point to, so a signature or attestation pushed for an upstream image does not hide the image. Only a hosted member whose filters admit a name can own it. |

Filters are compared with package names after the format's normalization, as clients may spell a name several ways: for PyPI, case and runs of `-`, `_`, and `.` do not matter, so `Acme_*` and `acme-*` are the same filter; for Cargo, case does not matter and `-` and `_` are equal; Go module paths are compared exactly, so `corp.example.com/*` covers every module below `corp.example.com/`. For OCI, a package name is the image name below the repository, such as `team/app` or `library/nginx`, and is compared exactly. For generic files, a filter matches a file's path, exactly, such as `"internal/*"`. For Maven, the name is `groupId:artifactId`, with `:` and `.` as one separator, so `com.acme.*` matches every artifact of group `com.acme` and its subgroups. A pattern is 1 to 256 printable characters other than space.

> **Recommendation: exclude your internal names from proxy members.**
> Dependency-confusion protection covers a name only once a hosted member owns it. Until your first upload of a new internal package, or while the hosted member that has it is left out by its filters, a public package of the same name would be served from a proxy member. An `exclude` pattern for every internal prefix or scope on each proxy member, such as `"exclude": ["acme-*"]`, keeps those names out of the upstream for good.

A member that fails, such as a proxy whose upstream cannot be reached and that has nothing cached for a package, is left out of the response, which is built from the other members; flint logs a warning and counts it in `flint_virtual_member_skips_total`. The request fails only if no member could answer.

Pulling through a virtual repository needs the `read` role on the virtual repository itself, or its `anonymousPull`; the members' own permissions are not consulted. Publishing through it needs the role publishing to its `publishTo` member directly needs.

### Generic files settings

A `generic` repository may have a `generic` object; [generic files](generic.md) describes the repositories.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `generic.allowOverwrite` | bool | `false` | Hosted repositories only. Let a client with `write` replace a file with different content, and one with `delete` delete a file without leaving a tombstone, so its path can be used again: for scratch areas and "latest build" directories. Without it, files are immutable: uploading different content to a file's path is refused with `409`, and a deleted file's path can never be used again. |
| `generic.immutable` | bool | `false` | Proxy repositories only. Cache files fetched from the upstream forever and never revalidate them, as suits release download sites whose files never change. Without it, a cached file is revalidated with a conditional request after `proxy.revalidateAfter`, since flint cannot know whether a path of an arbitrary upstream changes. |

### Permissions

Each grant gives one role on matching repositories to users and groups.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `repositories` | array of strings | required | Repository names, or patterns in which `*` matches any run of characters, such as `team-a-*`. |
| `role` | string | required | `read`, `write`, `delete`, or `admin`. |
| `users` | array of strings | `[]` | Users who receive the role. |
| `groups` | array of strings | `[]` | Groups whose members receive the role. At least one user or group is required. |

User and group names are 1 to 64 lowercase letters, digits, `.`, `_`, `-`, or `@`, starting with a letter or digit.
A user's role on a repository is the highest one any matching grant gives; [authentication](auth.md#permissions) describes what each role allows.

### Bootstrap administrator

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `username` | string | `"admin"` | Name of the first administrator. |
| `passwordFile` | string | required | File holding the administrator's password, such as a mounted Kubernetes Secret. One trailing newline is ignored. |

The file is read only while no administrator exists, so it can be removed after the first start, and changing it later does not reset the password.

### Garbage collection

Deleting an image or a blob hides it at once; garbage collection later deletes the blobs nothing references any more.
Administrators run it with `flint gc` or the admin API, and `gc.interval` runs it on a schedule.
The scheduled time counts from the start of the previous run, which survives restarts, so a server restarted more often than the interval still collects; a scheduled run never starts within a minute of startup.
The grace period protects content a push stored a moment ago, and the blob links of a push whose manifest has not arrived yet, whether the push wrote them or found them with a `HEAD`: a push that takes longer than the grace period between uploading or checking a blob and pushing its manifest may find the blob's link removed, and its manifest push fails with `MANIFEST_BLOB_UNKNOWN` until it pushes the blob again. It cannot be set below an hour.
[Garbage collection](garbage-collection.md) describes what is reclaimed, how to run it, and how to monitor it.

## Endpoints

### OCI registry API

OCI repositories are served at `/v2/` following the OCI Distribution Spec v1.1: blob pulls with range requests, monolithic, chunked, and streamed uploads, cross-repository mounts, manifests (OCI image manifests and indexes, Docker schema 2 manifests and manifest lists), the referrers API, paginated tag and catalog listings, and deletes.
An image is addressed as `<host>/<repository>/<name>`, for example `registry.example.com/docker-local/team/app:1.0`, where `<repository>` is a configured OCI repository and `<name>` is one or more path components.
Blobs and manifests are visible only in the repository name they were pushed or mounted to.

A manifest is accepted only when every blob and child manifest it references is already in the same repository name, with the size its descriptor gives; a manifest's `subject` may name a manifest not pushed yet.
Docker image manifest schema 1 is refused.
Deleting a tag removes only the tag; deleting a manifest by digest also removes the tags that point to it.
Deletes hide content at once; the disk space is reclaimed later by [garbage collection](#garbage-collection).

An upload session expires 24 hours after it starts; flint checks for expired sessions hourly and removes their staged data.

Every request is authenticated and authorized as [authentication](auth.md) describes.

### OCI virtual repositories

An OCI virtual repository puts a hosted repository and proxies of several registries behind one path: `registry.example.com/docker/team/app` and `registry.example.com/docker/library/nginx` pull from whichever member has the image, and pushes go to its `publishTo` member. With the [example](#example)'s `docker` repository, whose members are `docker-local`, `dockerhub`, and `ghcr`:

```sh
docker pull registry.example.com/docker/library/nginx:1.27     # from Docker Hub, through dockerhub
docker pull registry.example.com/docker/terrabyteian/flint:v0.3.0  # from ghcr.io, which Docker Hub does not have
docker push registry.example.com/docker/team/app:1.0           # to docker-local
```

- **Which member serves a pull.** The members whose filters admit the image name are asked in order, and the first that has what the request asks for serves it, as a pull from that member would. A tag is the first member's that has it. With `dependencyConfusionProtection`, once `docker-local` holds a tag of a name or a manifest of it without a `subject`, other than the signatures described under **Referrers** below, Docker Hub and ghcr.io are never asked about it, so an upstream image never shadows a first-party one; a name nobody pushed yet is not protected, which `exclude` filters on the proxy members cover. A proxy member that answers that it does not have a tag or manifest is not asked about it again for its `revalidateAfter`, so pulling a ghcr.io image through the example asks Docker Hub about it once per window, not on every pull; member filters keep a member from being asked at all, such as `"exclude": ["acme/*"]` on `dockerhub` for an organization's images on ghcr.io.
- **Blobs and manifests by digest** are served only by a member that holds them under the image name: one that has them linked there or, for a proxy, whose upstream serves them under that name. A digest held under another name is not enough. Members that already hold the content are asked first, so cached content is served without asking an upstream.
- **Tag listings** merge the members' tags, sorted, and paginate them as a hosted repository does. **Referrers** merge those of the members that hold the subject manifest or referrers of it, the first member's winning on a duplicate digest. A signature or attestation pushed through the virtual repository for an image Docker Hub serves, such as with `cosign sign` or `oras attach` using the referrers API, lands in `docker-local` without making `docker-local` own the name: the image is still pulled from Docker Hub, and the referrers API lists the signature with Docker Hub's referrers. The same holds for the signature tag schema that cosign uses by default: a tag `sha256-<64 lowercase hex>.sig`, `.att`, or `.sbom`, and a manifest without a `subject` that only such tags point to, do not make `docker-local` own the name, while any other tag, or a manifest without a `subject` that no such tag points to, does.
- **Failing members.** A member that fails, such as a proxy whose upstream cannot be reached with nothing cached, is skipped as for any virtual repository, so an outage of one registry does not stop pulls from the others or of cached content.
- **Pushes and deletes** go to `publishTo`: the image lands in `docker-local/team/app`, and is pulled as `docker/team/app` or `docker-local/team/app`. Without a `publishTo` they are refused with `405 UNSUPPORTED`, and a name its filters do not admit with `403 DENIED`. A blob's `HEAD`, which push clients send to learn whether to upload it, never asks an upstream, and a pushed manifest may use blobs and platform manifests another member holds under the same name, such as those of a base image pulled through the virtual repository, even once `docker-local` owns the name. So `crane copy docker.io/library/nginx:1.27 registry.example.com/docker/library/nginx:1.27`, `crane tag`, or `docker buildx imagetools create` can push a multi-platform image whose platform images were pulled through the virtual repository: they are linked into `docker-local` with their blobs. A platform image Docker Hub's proxy has not cached with its blobs is not, and the push reports it missing.
- **containerd mirrors.** A request with containerd's `ns` query parameter, which containerd adds to the requests it sends to a registry mirror, is answered only by the proxy members of the registry `ns` names, so one virtual repository can be the mirror of Docker Hub, ghcr.io, and quay.io at once; [containerd mirrors](containerd.md#one-mirror-for-several-registries) shows the setup.

Pulling through a virtual repository needs the `read` role on it, or its `anonymousPull`; the members' own permissions are not consulted, so a client can pull `docker/library/nginx` without any role on `dockerhub`. Pushing needs `write` on the same name in `publishTo`, and `read` on the virtual repository (or its `anonymousPull`) for the pulls a push makes; deleting needs `delete` on the same name in `publishTo`. Docker clients get their token for the name they push, `docker/team/app`, and flint grants it for the role on `docker-local/team/app`.

### PyPI repositories

PyPI repositories are served under `/pypi/<repository>/`: the simple index at `/pypi/<repository>/simple/`, the upload URL at `/pypi/<repository>/legacy/`, and the JSON API at `/pypi/<repository>/pypi/<project>/json`.
[PyPI](pypi.md) describes the URL layout, configuring pip, uv, and twine, and how hosted, proxy, and virtual repositories behave.

### Generic files repositories

Generic files repositories are served under `/generic/<repository>/`: a file at `/generic/<repository>/<path>`, uploaded with `PUT` and downloaded with `GET`, and a listing of a directory at a path ending in `/`.
[Generic files](generic.md) describes the URL layout, configuring curl and wget, and how hosted, proxy, and virtual repositories behave.

### Cargo repositories

Cargo repositories are served under `/cargo/<repository>/` over Cargo's sparse registry protocol: the index URL to give Cargo is `sparse+https://<host>/cargo/<repository>/`, and the web API, for publishing, yanking, downloading, and search, is under `/cargo/<repository>/api/v1/`.
[Cargo](cargo.md) describes the URL layout, configuring Cargo, and how hosted, proxy, and virtual repositories behave.

### npm repositories

An npm repository's registry URL, the one to give npm, pnpm, Yarn, and Bun, is `/npm/<repository>/`; packuments, tarballs, dist-tags, and the rest of the npm registry API are below it.
[npm](npm.md) describes configuring each client, publishing, dist-tags, deprecating, unpublishing, and `npm login`.
Tarball URLs in packuments are absolute and use [`publicURL`](#public-url), since lockfiles record them.

### Maven repositories

Maven repositories are served under `/maven/<repository>/` in the Maven 2 repository layout, the URL to give Maven and Gradle.
[Maven](maven.md) describes the layout, configuring Maven and Gradle, and how hosted, proxy, and virtual repositories behave.

### Go repositories

Go repositories are served under `/go/<repository>/`, the URL to give the go command as `GOPROXY`, with the GOPROXY protocol's endpoints below it and the checksum database's below `/go/<repository>/sumdb/<name>/`.
[Go modules](go.md) describes the URL layout, configuring the go command, and how proxy and virtual repositories behave.

### Proxy repositories

This section describes OCI proxy repositories; [PyPI](pypi.md#proxy-repositories), [Cargo](cargo.md#proxy-repositories), [Maven](maven.md#proxy-repositories), and [Go modules](go.md#proxy-repositories) describe theirs, which follow the same rules for caching, outages, disk space, and size limits.

A proxy repository serves pulls of its upstream's images, such as `registry.example.com/dockerhub/library/nginx:1.27` for Docker Hub's `nginx:1.27`, and caches what it serves in the same content-addressed store as hosted repositories, so each blob is stored once however many repositories use it.

- **Content addressed by digest** (blobs, and manifests pulled by digest) never changes, so once cached it is served forever without asking the upstream.
- **Tags** are served from the cache for `revalidateAfter` after the upstream last confirmed them. After that, flint asks the upstream for the tag's current digest with a `HEAD` request, which Docker Hub does not count against its pull rate limit, and fetches the manifest again only if the tag moved.
- **Tag listings and the referrers API** come from the upstream and are kept in memory for `revalidateAfter`. An upstream without the referrers API is answered with the referrers of the manifests cached so far.
- **When the upstream is unreachable**, because of network errors, timeouts, `5xx` errors, or `429` rate limiting, cached content keeps being served: tags as last confirmed, and listings as last fetched or, failing that, from the cached tags. After such a failure flint treats the upstream as offline for 30 seconds and serves cached copies without waiting on it. Content that was never cached cannot be served, and is answered with `503 UNAVAILABLE`.
- **When the upstream answers that a tag or tag listing is not found or denied** (`404`, or `401` or `403` once flint has authenticated), for example because the tag was deleted or the image made private, flint answers `404` too, even if it has the tag cached. Content addressed by digest stays cached and served.
- **When flint cannot authenticate to the upstream**, because the upstream or its token service refuses the configured credentials (an expired access token, say) or its authentication challenge is unusable, cached content keeps being served as if the upstream were unreachable, flint logs a warning naming the authentication failure, and it treats the upstream as offline for 30 seconds, so it does not ask the token service again on every pull.
- **Fetching.** A blob that is not cached streams to the client while flint writes it to the store, and concurrent pulls of the same blob share one upstream request. Every blob and manifest is checked against its digest: a mismatched manifest is refused with `502`, and a mismatched blob is cut off before its last byte, so a client never receives it whole and it never enters the cache. Transient upstream failures (network errors, `429`, and `5xx`) are retried with backoff, and at most `proxy.maxConcurrent` upstream requests run at once. Redirects and token services follow [the fetch policy](#upstream-fetch-policy).
- **Disk space.** When the free space on the data directory's filesystem would fall below `proxyCache.minFreeSpace`, new content is passed through from the upstream without being cached, cached content keeps being served, flint logs a warning, and `flint_proxy_disk_pressure` is 1. flint never deletes cached content to make room.
- **Size limit.** With `proxy.sizeLimit`, when the repository's cached content (each blob and manifest, counted once per image name) exceeds the limit, the least recently pulled items are evicted until it fits: a blob's link, or a manifest with the tags pointing to it. Content larger than the limit is passed through. Pull times are kept in memory and saved every minute, so a restart forgets at most the last minute's pulls. Eviction hides content at once; the disk space is reclaimed later by [garbage collection](#garbage-collection).
- **Read-only.** Pushes and deletes are refused with `405 UNSUPPORTED`.

Proxy repositories use the same permissions as hosted ones: pulling needs the `read` role or `anonymousPull`. With `anonymousPull`, clients pull without credentials or a token, which is how a containerd registry mirror reaches flint; [containerd mirrors](containerd.md) shows the setup.

### Helm chart repositories

A hosted OCI repository with `helmIndex` also serves the Helm charts pushed to it with `helm push` as a classic Helm chart repository at `/helm/<repository>/`.
[Helm chart repositories](helm-repository.md) describes the view, its access rules, and client setup.

### Built-in endpoints

These endpoints are always served, without authentication:

| Endpoint | Meaning |
| --- | --- |
| `GET /healthz` | Liveness: 200 while the process serves HTTP. |
| `GET /readyz` | Readiness: 200 when ready; 503 while shutting down or when a readiness check fails. A metadata store that rejects writes after a failed fsync stays ready, because it still serves reads; the fault shows in `flint_meta_store_poisoned` and the logs. |
| `GET /metrics` | Prometheus metrics in the text exposition format. |

These authenticate themselves, as [authentication](auth.md) describes:

| Endpoint | Meaning |
| --- | --- |
| `GET, POST /auth/token` | The Docker token endpoint: issues short-lived bearer tokens for registry requests. |
| `/api/v1/...` | The admin API: users, groups, API tokens, [backups](backup.md), the [audit log](operations.md#audit-log), yanking and deleting PyPI files, and deleting crate versions. |
| `PUT /npm/<repository>/-/user/org.couchdb.user:<user>` | npm's legacy login, which mints an API token for a user name and password; see [npm](npm.md#logging-in-with-npm-login). |

## Signals and shutdown

On `SIGTERM` or `SIGINT`, flint fails readiness, stops accepting connections, and waits up to `shutdownTimeout` for in-flight requests, then writes the audit log's last records, closes the metadata store, and exits 0.
A second signal during shutdown exits at once.
In Kubernetes, keep `terminationGracePeriodSeconds` longer than `shutdownTimeout`.

## Logs

flint writes structured JSON logs to standard error.
Each request produces one line with the request ID (also returned in the `X-Request-Id` response header), method, path without the query string, route, status, response bytes, duration, client address, protocol, user agent, and, for an authenticated client, the user and any API token ID.
Requests to `/healthz`, `/readyz`, and `/metrics` log at `debug` level, so probes and scrapes do not flood the log.
Requests to the OCI API carry the repository name in a `repository` attribute, and their route is one of `oci.base`, `oci.catalog`, `oci.blob`, `oci.upload`, `oci.manifest`, `oci.tags`, `oci.referrers`, or `oci.unknown`.
Requests to PyPI repositories carry it too, with the route `pypi.index`, `pypi.project`, `pypi.file`, `pypi.metadata`, `pypi.upload`, `pypi.json`, or `pypi.unknown`; the admin API's PyPI endpoints use `api.pypi.yank`, `api.pypi.unyank`, and `api.pypi.delete`.
Requests to generic files repositories carry it as well, with the route `generic.file`, `generic.list`, `generic.upload`, `generic.delete`, or `generic.unknown`.
Requests to Cargo repositories carry it too, with the route `cargo.config`, `cargo.index`, `cargo.download`, `cargo.publish`, `cargo.yank`, `cargo.unyank`, `cargo.search`, `cargo.owners`, or `cargo.unknown`; the admin API's Cargo endpoint uses `api.cargo.delete`.
Requests to npm repositories carry it as well, and the package name in `package`, with the route `npm.root`, `npm.packument`, `npm.version`, `npm.tarball`, `npm.publish`, `npm.edit` (deprecating or unpublishing versions), `npm.unpublish`, `npm.dist-tags`, `npm.login`, `npm.whoami`, `npm.ping`, `npm.search`, `npm.audit`, `npm.keys`, `npm.attestations`, or `npm.unknown`.
Requests to Maven repositories carry it too, with the route `maven.file`, `maven.metadata`, `maven.checksum`, `maven.other` (paths outside the layout, and version directories), or `maven.unknown`.
Requests to Go repositories carry it too, with the route `go.list`, `go.info`, `go.mod`, `go.zip`, `go.latest`, `go.sumdb`, or `go.unknown`.

## Metrics

Besides the HTTP, metadata store, [audit log](operations.md#metrics), Go runtime, and [backup](backup.md#metrics) metrics, the OCI API and the package formats export the metrics below. The `flint_proxy_*` metrics cover proxy repositories of every format, and `flint_virtual_member_skips_total` virtual repositories of every format.

| Metric | Meaning |
| --- | --- |
| `flint_oci_upload_bytes_total{repository}` | Blob bytes received in uploads. |
| `flint_oci_manifest_pushes_total{repository}` | Manifests pushed. |
| `flint_oci_link_retries_total` | Link batches retried because a concurrent change, such as a garbage-collection sweep starting, failed their precondition. |
| `flint_pypi_uploads_total{repository}` | Distribution files uploaded to hosted PyPI repositories. |
| `flint_pypi_upload_bytes_total{repository}` | Bytes of distribution files uploaded to hosted PyPI repositories. |
| `flint_cargo_publishes_total{repository}` | Crate versions published to hosted Cargo repositories. |
| `flint_cargo_publish_bytes_total{repository}` | Bytes of `.crate` files published to hosted Cargo repositories. |
| `flint_npm_publishes_total{repository}` | Package versions published to hosted npm repositories. |
| `flint_npm_publish_bytes_total{repository}` | Bytes of package tarballs published to hosted npm repositories. |
| `flint_maven_deploys_total{repository}` | Files deployed to hosted Maven repositories; identical re-uploads are not counted. |
| `flint_maven_deploy_bytes_total{repository}` | Bytes of files deployed to hosted Maven repositories. |
| `flint_virtual_member_skips_total{repository,member}` | Members of virtual repositories left out of a response because they failed, such as a proxy whose upstream could not be reached with nothing cached. |
| `flint_proxy_requests_total{repository,result}` | Pulls from proxy repositories, by result: `hit` (served from the cache), `revalidated` (served after the upstream confirmed a tag, listing, project page, generic file, index file, or `maven-metadata.xml`), `fetched` (fetched from the upstream and cached), `passthrough` (fetched without caching, under disk pressure, over the size limit, or for a PyPI file whose index entry has no sha256 digest or a Maven file without a checksum, and Cargo searches), and `stale` (served from the cache because the upstream failed). |
| `flint_proxy_upstream_errors_total{repository}` | Upstream requests that failed: unreachable, server errors, denied access, failed authentication, or content that did not match its digest. A blob fetch shared by several clients counts once. |
| `flint_proxy_upstream_bytes_total{repository}` | Bytes fetched from upstream registries, indexes, and web servers. |
| `flint_proxy_fetches_in_flight` | Blobs and files being fetched from upstreams. |
| `flint_proxy_disk_pressure` | 1 while the free space is below `proxyCache.minFreeSpace` and new content is passed through without caching, else 0. Alert on it. |
| `flint_data_free_bytes` | Free bytes on the data directory's filesystem, as last measured. |
| `flint_proxy_cached_bytes{repository}` | Bytes cached by proxy repositories with a size limit. |
| `flint_proxy_evictions_total{repository}` | Items evicted to keep proxy repositories within their size limits. |

Garbage collection exports `flint_gc_runs_total{mode,result}`, `flint_gc_duration_seconds{mode}`, `flint_gc_reclaimed_blobs_total`, `flint_gc_reclaimed_bytes_total`, `flint_gc_last_success_timestamp_seconds`, and `flint_gc_running`; [garbage collection](garbage-collection.md#monitoring) describes them.

The disk-pressure gauge is the alert for a nearly full disk, for example as a Prometheus alerting rule:

```yaml
- alert: FlintProxyDiskPressure
  expr: flint_proxy_disk_pressure == 1
  for: 10m
  annotations:
    summary: flint's data volume is nearly full; proxy repositories no longer cache new content.
```
