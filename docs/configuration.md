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
      "anonymousPull": true
    }
  ],
  "auth": {
    "bootstrapAdmin": {
      "username": "admin",
      "passwordFile": "/etc/flint/admin/password"
    },
    "tokenTTL": "5m",
    "permissions": [
      {
        "repositories": ["docker-local", "releases"],
        "role": "write",
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
| `auth.tokenTTL` | duration string | `"5m"` | Lifetime of the bearer tokens the Docker token endpoint issues, from `30s` to `1h`. |

Durations are Go duration strings: a number and a unit, such as `"30s"`, `"2m"`, or `"1m30s"`.

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
| `name` | string | required | The repository's path prefix, as in `host/docker-local/team/app`: clients address images below it, never the repository itself. 1 to 64 lowercase letters and digits, with single `.`, `_`, or `-` separators between them. Unique. |
| `format` | string | required | Package format. Only `oci` is supported so far; `pypi` arrives with milestone M3. |
| `type` | string | required | Repository type. Only `hosted` is supported so far; `proxy` and `virtual` arrive with later milestones. |
| `immutableTags` | bool | `false` | Make a pushed tag permanent: pushing another manifest under it, deleting it, or deleting a manifest it points to is refused with `409 DENIED`. Pushing the same manifest again is allowed. |
| `anonymousPull` | bool | `false` | Let unauthenticated clients pull. |

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

Hosted OCI repositories are served at `/v2/` following the OCI Distribution Spec v1.1: blob pulls with range requests, monolithic, chunked, and streamed uploads, cross-repository mounts, manifests (OCI image manifests and indexes, Docker schema 2 manifests and manifest lists), the referrers API, paginated tag and catalog listings, and deletes.
An image is addressed as `<host>/<repository>/<name>`, for example `registry.example.com/docker-local/team/app:1.0`, where `<repository>` is a configured hosted OCI repository and `<name>` is one or more path components.
Blobs and manifests are visible only in the repository name they were pushed or mounted to.

A manifest is accepted only when every blob and child manifest it references is already in the same repository name, with the size its descriptor gives; a manifest's `subject` may name a manifest not pushed yet.
Docker image manifest schema 1 is refused.
Deleting a tag removes only the tag; deleting a manifest by digest also removes the tags that point to it.
Deletes hide content at once; the disk space is reclaimed by garbage collection, which arrives with milestone M4.

An upload session expires 24 hours after it starts; flint checks for expired sessions hourly and removes their staged data.

Authentication arrives later in milestone M1.
Until then every request is allowed, so expose flint only to clients you trust.

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
| `/api/v1/...` | The admin API: users, groups, and API tokens. |

## Signals and shutdown

On `SIGTERM` or `SIGINT`, flint fails readiness, stops accepting connections, and waits up to `shutdownTimeout` for in-flight requests, then closes the metadata store and exits 0.
A second signal during shutdown exits at once.
In Kubernetes, keep `terminationGracePeriodSeconds` longer than `shutdownTimeout`.

## Logs

flint writes structured JSON logs to standard error.
Each request produces one line with the request ID (also returned in the `X-Request-Id` response header), method, path without the query string, route, status, response bytes, duration, client address, protocol, user agent, and, for an authenticated client, the user and any API token ID.
Requests to `/healthz`, `/readyz`, and `/metrics` log at `debug` level, so probes and scrapes do not flood the log.
Requests to the OCI API carry the repository name in a `repository` attribute, and their route is one of `oci.base`, `oci.catalog`, `oci.blob`, `oci.upload`, `oci.manifest`, `oci.tags`, `oci.referrers`, or `oci.unknown`.

## Metrics

Besides the HTTP, metadata store, and Go runtime metrics, the OCI API exports:

| Metric | Meaning |
| --- | --- |
| `flint_oci_upload_bytes_total{repository}` | Blob bytes received in uploads. |
| `flint_oci_manifest_pushes_total{repository}` | Manifests pushed. |
| `flint_oci_link_retries_total` | Link batches retried because a concurrent change, such as a garbage-collection sweep starting, failed their precondition. |
