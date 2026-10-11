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
        "members": ["pypi-local", "pypi"]
      }
    }
  ],
  "proxyCache": {
    "minFreeSpace": "5%"
  },
  "backup": {
    "directory": "/var/backups/flint"
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
        "repositories": ["docker-local", "releases", "pypi-local"],
        "role": "write",
        "groups": ["ci"]
      },
      {
        "repositories": ["dockerhub", "ghcr", "pypi"],
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
| `shutdownTimeout` | duration string | `"25s"` | How long a graceful shutdown waits for in-flight requests before closing their connections. Must be positive. |
| `log.level` | string | `"info"` | Minimum log level: `debug`, `info`, `warn`, or `error`. |
| `repositories` | array | `[]` | Repositories declared in configuration; see below. |
| `auth.permissions` | array | `[]` | Permission grants; see below. |
| `auth.bootstrapAdmin` | object | none | Create the first administrator at startup if none exists; see below. |
| `auth.loginTokenTTL` | duration string | `"2160h"` | How long an API token minted by a package client's login command stays valid (90 days by default); see [authentication](auth.md#tokens-from-client-login-commands). Must be positive. |
| `backup.directory` | string | none | Absolute path of the [backup](backup.md) directory, outside the data directory and not containing it. Without it, backups are disabled. |
| `proxyCache.minFreeSpace` | string | `"5%"` | Free space on the data directory's filesystem below which [proxy repositories](#proxy-repositories) stop caching new content: a percentage of the filesystem's size, such as `"5%"`, or a size, such as `"20GiB"`. |
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

### Repositories

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | required | The repository's name, which clients address it by: the path prefix of its images, as in `host/docker-local/team/app`, or of its PyPI index, as in `host/pypi/pypi-local/simple/`. 1 to 64 lowercase letters and digits, with single `.`, `_`, or `-` separators between them. Unique across formats. |
| `format` | string | required | Package format: `oci` for container images and OCI artifacts, or `pypi` for Python packages. |
| `type` | string | required | Repository type: `hosted`, which clients publish to; `proxy`, a read-only cache of an upstream registry or index; or, for `pypi`, `virtual`, one index merged from other repositories. |
| `immutableTags` | bool | `false` | Hosted OCI repositories only. Make a pushed tag permanent: pushing another manifest under it, deleting it, or deleting a manifest it points to is refused with `409 DENIED`. Pushing the same manifest again is allowed. |
| `anonymousPull` | bool | `false` | Let unauthenticated clients pull. |
| `helmIndex` | bool | `false` | Hosted OCI repositories only. Also serve the Helm charts pushed to the repository as a classic Helm chart repository at `/helm/<name>/`; see [Helm chart repositories](#helm-chart-repositories). |
| `proxy` | object | required for `proxy` | The upstream of a proxy repository; see below. Not allowed for other types. |
| `virtual` | object | required for `virtual` | The members of a virtual repository; see below. Not allowed for other types. |

### Proxy repository settings

A proxy repository caches one upstream: a registry such as Docker Hub, ghcr.io, or quay.io, or a Python package index such as pypi.org. [Proxy repositories](#proxy-repositories) describes how an OCI proxy serves pulls, and [PyPI](pypi.md#proxy-repositories) how a PyPI proxy does.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `proxy.url` | string | required | For `oci`, the upstream registry's base URL, without a path, such as `"https://registry-1.docker.io"` or `"https://ghcr.io"`; for Docker Hub (`registry-1.docker.io`), a single-component image name gets the `library/` prefix, as Docker clients add it: `dockerhub/nginx` pulls `library/nginx`. For `pypi`, the upstream's simple index URL, the one you would give pip as `--index-url`, such as `"https://pypi.org/simple/"` or `"https://download.pytorch.org/whl/cpu"`; a URL without a path gets `/simple/`, so `"https://pypi.org"` works too. |
| `proxy.username` | string | none | User name for the upstream, such as a Docker Hub account for its higher pull limits. Requires `passwordFile`. See the warning below. |
| `proxy.passwordFile` | string | none | Absolute path of a file holding the upstream password or access token, such as a mounted Kubernetes Secret. One trailing newline is ignored. flint reads it at startup, failing to start if it cannot, and again whenever it authenticates to the upstream, so a rotated secret takes effect without a restart. It is never logged. Requires `username`. |
| `proxy.revalidateAfter` | duration | `"5m"` | How long a cached tag, tag listing, referrers listing, or document, such as a PyPI project page, is served before the upstream is asked again. Must be positive. |
| `proxy.sizeLimit` | size | none | Cap the content cached in this repository. Over the cap, the least recently pulled content is evicted. Without it, everything is cached forever. |
| `proxy.maxConcurrent` | integer | `64` | Requests the repository may have in flight to its upstream at once, each from when it is sent until its response has been read; further requests wait. Keeps a burst of client requests, such as a large install, from turning into a rate-limit ban. |
| `proxy.allowHosts` | array of strings | none | Hosts besides the upstream's own that the repository may fetch from when upstream content or a redirect points at them: a host name or IP address, optionally with a port (`"cdn.example.com"`, `"10.0.0.7:9000"`), or `"*.example.com"` for every subdomain of `example.com`. See [the fetch policy](#upstream-fetch-policy). |

> **Warning: upstream credentials are shared with everyone who can pull.**
> flint sends every upstream request of a proxy repository with its configured account, so anyone allowed to pull from that repository, including anonymous clients with `anonymousPull`, can read whatever that account can read upstream, including its private repositories.
> Use a dedicated account that has no private content, or an access token limited to public, read-only access, such as a Docker Hub personal access token with the *Public Repo Read-only* scope.

### Upstream fetch policy

A proxy repository fetches only from its upstream's host and the hosts its format allows for that upstream:

- **OCI** registries may redirect blob downloads to, and name their token service on, any host, as the distribution protocol allows, so every public host is allowed.
- **PyPI** indexes link their files: the index's own host, `files.pythonhosted.org` for `pypi.org`, and `test-files.pythonhosted.org` for `test.pypi.org`.
- `proxy.allowHosts` adds further hosts.

Redirects are followed only to allowed hosts. flint refuses to connect to loopback, link-local, private, shared (`100.64.0.0/10`), and unspecified (`0.0.0.0/8`) addresses, and to IPv6 addresses that embed one (NAT64 `64:ff9b::/96`, 6to4 `2002::/16`), except for the host of `proxy.url` and the hosts in `proxy.allowHosts`, which the configuration names: the check runs on the address a name resolves to when flint connects, so upstream content, a redirect, or a token challenge can never steer flint at a service inside its network. A refused fetch is answered `502`. Credentials are only ever sent to the host of `proxy.url`. The `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` environment variables apply to upstream requests; with a proxy configured, flint connects to the proxy, which then decides where requests go.

### Virtual repository settings

A virtual repository serves one index merged from an ordered list of hosted and proxy repositories of its format, so clients need a single URL. Only `pypi` has virtual repositories; [PyPI](pypi.md#virtual-repositories) describes how they merge.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `virtual.members` | array of strings | required | The member repositories, in order of precedence: hosted or proxy repositories of the same format, each named once. Where several members have a file of the same name, the first one's is served. |
| `virtual.dependencyConfusionProtection` | bool | `true` | Once a hosted member owns a package name, never serve that name from a proxy member, so a package published upstream under the same name can never replace or mix with the first-party one. A hosted repository owns a name from the first upload of a file of it, also after every file is deleted. |

Pulling through a virtual repository needs the `read` role on the virtual repository itself, or its `anonymousPull`; the members' own permissions are not consulted. Publishing goes to a hosted member directly: a virtual repository refuses uploads.

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

## Endpoints

### OCI registry API

OCI repositories are served at `/v2/` following the OCI Distribution Spec v1.1: blob pulls with range requests, monolithic, chunked, and streamed uploads, cross-repository mounts, manifests (OCI image manifests and indexes, Docker schema 2 manifests and manifest lists), the referrers API, paginated tag and catalog listings, and deletes.
An image is addressed as `<host>/<repository>/<name>`, for example `registry.example.com/docker-local/team/app:1.0`, where `<repository>` is a configured OCI repository and `<name>` is one or more path components.
Blobs and manifests are visible only in the repository name they were pushed or mounted to.

A manifest is accepted only when every blob and child manifest it references is already in the same repository name, with the size its descriptor gives; a manifest's `subject` may name a manifest not pushed yet.
Docker image manifest schema 1 is refused.
Deleting a tag removes only the tag; deleting a manifest by digest also removes the tags that point to it.
Deletes hide content at once; the disk space is reclaimed by garbage collection, which arrives with milestone M4.

An upload session expires 24 hours after it starts; flint checks for expired sessions hourly and removes their staged data.

Every request is authenticated and authorized as [authentication](auth.md) describes.

### PyPI repositories

PyPI repositories are served under `/pypi/<repository>/`: the simple index at `/pypi/<repository>/simple/`, the upload URL at `/pypi/<repository>/legacy/`, and the JSON API at `/pypi/<repository>/pypi/<project>/json`.
[PyPI](pypi.md) describes the URL layout, configuring pip, uv, and twine, and how hosted, proxy, and virtual repositories behave.

### Proxy repositories

This section describes OCI proxy repositories; [PyPI](pypi.md#proxy-repositories) describes PyPI ones, which follow the same rules for caching, outages, disk space, and size limits.

A proxy repository serves pulls of its upstream's images, such as `registry.example.com/dockerhub/library/nginx:1.27` for Docker Hub's `nginx:1.27`, and caches what it serves in the same content-addressed store as hosted repositories, so each blob is stored once however many repositories use it.

- **Content addressed by digest** (blobs, and manifests pulled by digest) never changes, so once cached it is served forever without asking the upstream.
- **Tags** are served from the cache for `revalidateAfter` after the upstream last confirmed them. After that, flint asks the upstream for the tag's current digest with a `HEAD` request, which Docker Hub does not count against its pull rate limit, and fetches the manifest again only if the tag moved.
- **Tag listings and the referrers API** come from the upstream and are kept in memory for `revalidateAfter`. An upstream without the referrers API is answered with the referrers of the manifests cached so far.
- **When the upstream is unreachable**, because of network errors, timeouts, `5xx` errors, or `429` rate limiting, cached content keeps being served: tags as last confirmed, and listings as last fetched or, failing that, from the cached tags. After such a failure flint treats the upstream as offline for 30 seconds and serves cached copies without waiting on it. Content that was never cached cannot be served, and is answered with `503 UNAVAILABLE`.
- **When the upstream answers that a tag or tag listing is not found or denied** (`404`, or `401` or `403` once flint has authenticated), for example because the tag was deleted or the image made private, flint answers `404` too, even if it has the tag cached. Content addressed by digest stays cached and served.
- **When flint cannot authenticate to the upstream**, because the upstream or its token service refuses the configured credentials (an expired access token, say) or its authentication challenge is unusable, cached content keeps being served as if the upstream were unreachable, flint logs a warning naming the authentication failure, and it treats the upstream as offline for 30 seconds, so it does not ask the token service again on every pull.
- **Fetching.** A blob that is not cached streams to the client while flint writes it to the store, and concurrent pulls of the same blob share one upstream request. Every blob and manifest is checked against its digest: a mismatched manifest is refused with `502`, and a mismatched blob is cut off before its last byte, so a client never receives it whole and it never enters the cache. Transient upstream failures (network errors, `429`, and `5xx`) are retried with backoff, and at most `proxy.maxConcurrent` upstream requests run at once. Redirects and token services follow [the fetch policy](#upstream-fetch-policy).
- **Disk space.** When the free space on the data directory's filesystem would fall below `proxyCache.minFreeSpace`, new content is passed through from the upstream without being cached, cached content keeps being served, flint logs a warning, and `flint_proxy_disk_pressure` is 1. flint never deletes cached content to make room.
- **Size limit.** With `proxy.sizeLimit`, when the repository's cached content (each blob and manifest, counted once per image name) exceeds the limit, the least recently pulled items are evicted until it fits: a blob's link, or a manifest with the tags pointing to it. Content larger than the limit is passed through. Pull times are kept in memory and saved every minute, so a restart forgets at most the last minute's pulls. Eviction hides content at once; the disk space is reclaimed by garbage collection, which arrives with milestone M4.
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
| `/api/v1/...` | The admin API: users, groups, API tokens, [backups](backup.md), the [audit log](operations.md#audit-log), and yanking and deleting PyPI files. |

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

## Metrics

Besides the HTTP, metadata store, [audit log](operations.md#metrics), Go runtime, and [backup](backup.md#metrics) metrics, the OCI API and PyPI repositories export the metrics below. The `flint_proxy_*` metrics cover proxy repositories of both formats.

| Metric | Meaning |
| --- | --- |
| `flint_oci_upload_bytes_total{repository}` | Blob bytes received in uploads. |
| `flint_oci_manifest_pushes_total{repository}` | Manifests pushed. |
| `flint_oci_link_retries_total` | Link batches retried because a concurrent change, such as a garbage-collection sweep starting, failed their precondition. |
| `flint_pypi_uploads_total{repository}` | Distribution files uploaded to hosted PyPI repositories. |
| `flint_pypi_upload_bytes_total{repository}` | Bytes of distribution files uploaded to hosted PyPI repositories. |
| `flint_proxy_requests_total{repository,result}` | Pulls from proxy repositories, by result: `hit` (served from the cache), `revalidated` (served after the upstream confirmed a tag, listing, or project page), `fetched` (fetched from the upstream and cached), `passthrough` (fetched without caching, under disk pressure, over the size limit, or for a PyPI file whose index entry has no sha256 digest), and `stale` (served from the cache because the upstream failed). |
| `flint_proxy_upstream_errors_total{repository}` | Upstream requests that failed: unreachable, server errors, denied access, failed authentication, or content that did not match its digest. A blob fetch shared by several clients counts once. |
| `flint_proxy_upstream_bytes_total{repository}` | Bytes fetched from upstream registries and indexes. |
| `flint_proxy_fetches_in_flight` | Blobs and files being fetched from upstreams. |
| `flint_proxy_disk_pressure` | 1 while the free space is below `proxyCache.minFreeSpace` and new content is passed through without caching, else 0. Alert on it. |
| `flint_data_free_bytes` | Free bytes on the data directory's filesystem, as last measured. |
| `flint_proxy_cached_bytes{repository}` | Bytes cached by proxy repositories with a size limit. |
| `flint_proxy_evictions_total{repository}` | Items evicted to keep proxy repositories within their size limits. |

The disk-pressure gauge is the alert for a nearly full disk, for example as a Prometheus alerting rule:

```yaml
- alert: FlintProxyDiskPressure
  expr: flint_proxy_disk_pressure == 1
  for: 10m
  annotations:
    summary: flint's data volume is nearly full; proxy repositories no longer cache new content.
```
