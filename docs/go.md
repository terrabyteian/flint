# Go modules

flint serves Go modules to the go command, as its module proxy (`GOPROXY`), from two kinds of Go repository:

- **Proxy** repositories cache an upstream module proxy, such as proxy.golang.org, verify every module against the Go checksum database before caching it, and keep serving what they cached when the upstream is down. They also proxy the checksum database itself, so clients that cannot reach sum.golang.org still verify what they download.
- **Virtual** repositories merge proxy repositories behind one URL, with filters that keep internal module paths away from public upstreams.

Hosted Go repositories, which modules are published to, are not supported: the go command has no publish, and private modules are usually fetched from version control or a private upstream proxy.

[Configuration](configuration.md#repositories) describes how to declare them.
A typical setup caches proxy.golang.org, and an internal module proxy for the company's private modules, behind one virtual repository:

```json
"repositories": [
  {"name": "goproxy", "format": "go", "type": "proxy", "proxy": {"url": "https://proxy.golang.org"}},
  {"name": "go-corp", "format": "go", "type": "proxy",
   "proxy": {"url": "https://goproxy.corp.example.com", "username": "flint", "passwordFile": "/etc/flint/upstream/go-corp/password"},
   "go": {"noSumCheck": ["corp.example.com/*"]}},
  {"name": "go-all", "format": "go", "type": "virtual",
   "virtual": {"members": [
     {"name": "go-corp", "include": ["corp.example.com/*"]},
     {"name": "goproxy", "exclude": ["corp.example.com/*"]}
   ]}}
]
```

## URLs

Each repository is served under `/go/<repository>/`, which is the URL to give the go command as `GOPROXY`.
Below it are the endpoints of the GOPROXY protocol, and the checksum database's below `sumdb/<name>/`:

| URL | Serves |
| --- | --- |
| `/go/<repository>/<module>/@v/list` | The module's known versions, one per line. |
| `/go/<repository>/<module>/@v/<version>.info` | A version's metadata, as JSON; for a query that is not a version, such as a branch name or a commit, the version it resolves to. |
| `/go/<repository>/<module>/@v/<version>.mod` | A version's `go.mod` file. |
| `/go/<repository>/<module>/@v/<version>.zip` | A version's module zip. |
| `/go/<repository>/<module>/@latest` | The latest version's metadata, for a module without tagged versions. |
| `/go/<repository>/sumdb/<name>/supported` | `200`: the repository proxies checksum database `<name>`, such as `sum.golang.org`. |
| `/go/<repository>/sumdb/<name>/latest` | The checksum database's latest signed tree head. |
| `/go/<repository>/sumdb/<name>/lookup/<module>@<version>` | The checksum database's record of a module version. |
| `/go/<repository>/sumdb/<name>/tile/...` | The checksum database's tiles, which prove its records. |

Module paths and versions are case-encoded, as the protocol requires: each uppercase letter is written as `!` and the lowercase letter, so `github.com/Azure/azure-sdk-for-go` is `github.com/!azure/azure-sdk-for-go`.
The go command does this itself.
Go repositories are read-only: any method but `GET` and `HEAD` is refused with `405`.

## Configuring the go command

The examples use `https://registry.example` for flint, and the repositories above.

```sh
go env -w GOPROXY=https://registry.example/go/go-all
```

or `GOPROXY=https://registry.example/go/go-all` in the environment, as CI systems set it.
The go command then fetches every module through flint, and, because the repository answers `200` for `sumdb/sum.golang.org/supported`, it also fetches the checksum database through flint: it never needs to reach proxy.golang.org or sum.golang.org itself.
It still verifies everything it downloads against the checksum database, and checks the database's proofs, as it does without flint.

**Falling back.** With `GOPROXY=https://registry.example/go/go-all,direct`, the go command fetches a module directly from its version control repository when flint answers `404` or `410`, which flint passes on from the upstream.
After a comma, the go command does not fall back on other errors, such as `503` for a module flint has not cached while its upstream is down; after a `|`, as in `https://registry.example/go/go-all|direct`, it falls back on any error.

**Private modules.** The public checksum database cannot know private modules, so tell the go command not to look them up there, as for any module proxy:

```sh
go env -w GONOSUMDB=corp.example.com
```

`GOPRIVATE=corp.example.com` does that too, but also makes the go command fetch those modules directly, not through flint.
On the flint side, a proxy repository's [`go.noSumCheck`](#verification-against-the-checksum-database) patterns let it cache those modules without the checksum database.

### Credentials

The go command sends credentials only over HTTPS, so a Go repository that needs them must be served with [TLS](configuration.md#tls), or behind a TLS-terminating proxy.
A repository with `anonymousPull` needs no credentials, and also works over plain HTTP.
Downloading needs the `read` role ([permissions](auth.md#permissions)); a request without credentials that needs them gets `401` with `WWW-Authenticate: Basic realm="flint"`.

The go command reads credentials from `~/.netrc`, or the file `NETRC` names, with an [API token](auth.md#api-tokens) as the password and the user name `__token__`, or a user name and its password or token:

```
machine registry.example
login __token__
password flint_...
```

On a port other than 443, Go 1.24 and later look the credentials up by host and port, as `machine registry.example:8443`, and earlier releases by host alone, as `machine registry.example`; list both to cover every release.

From Go 1.24 on, a `GOAUTH` command can supply them instead, such as an API token as a bearer token. The command prints the URL prefix the credentials are for, a blank line, the headers, and a blank line:

```sh
#!/bin/sh
printf 'https://registry.example/go/\n\nAuthorization: Bearer %s\n\n' "$FLINT_TOKEN"
```

```sh
go env -w GOAUTH=/usr/local/bin/flint-goauth
```

## Proxy repositories

A proxy repository caches one upstream module proxy, given by the URL you would give the go command as `GOPROXY`, such as `https://proxy.golang.org`, or the URL of another module proxy, which may have a path.

- **A version's files** (its `.info`, `.mod`, and `.zip`) never change, as the GOPROXY protocol requires of a proxy, so once cached they are served forever without asking the upstream. They are fetched once however many clients ask at the same time, and checked before they are cached or sent, as the next section says. A `.info` must name the version it was asked for.
- **Version lists, `@latest`, and queries**, such as a branch name or a commit hash, are documents: stored in the cache as the upstream sent them, served for `revalidateAfter` (default 5 minutes) after the upstream last confirmed them, then asked for again with their `ETag` and `Last-Modified`, so an unchanged one costs a `304`, also after a restart. An answer to `@latest` or a query that flint cannot read never replaces the cached one. An answer that names a version is also cached as that version's `.info`, so a build that resolved a branch while the upstream was reachable finds the version's `.info` when it is not.
- **When the upstream answers not found** (`404` or `410`), flint passes the answer on as it is, and remembers it for a minute, so the go command's probes of the module path's parents cost the upstream one request each per minute. Content flint cached for the module stays cached.
- **When the upstream is unreachable**, because of network errors, timeouts, `5xx` errors, or `429` rate limiting, cached content keeps being served: a version's files as cached, and documents as last fetched. flint then treats the upstream as offline for 30 seconds. Content never cached is answered with `503`.
- **Disk space and size limits** work as for [OCI proxy repositories](configuration.md#proxy-repositories): under `proxyCache.minFreeSpace`, new content is passed through without being cached, still checked; with `proxy.sizeLimit`, the least recently downloaded files are evicted to stay within the limit. Documents do not count against it.
- **Credentials.** With `proxy.username` and `proxy.passwordFile`, flint answers the upstream's Basic or Bearer challenges, for a private upstream proxy. They are sent only to the host of `proxy.url`, never to the checksum database.
- **Fetch policy.** flint fetches modules only from the host of `proxy.url`, and the checksum database only from the host of `go.sumdb.url`, plus, for both, the hosts in `proxy.allowHosts`; see [the fetch policy](configuration.md#upstream-fetch-policy).

### Verification against the checksum database

Before a `.mod` or `.zip` is cached, and before a client receives any of it, flint checks it against the Go checksum database, as the go command checks what it downloads:

1. It looks up the module version's record, through the repository's own cache of the checksum database.
2. It proves the record, as the go command does: it verifies the signature of the tree head the record comes with, with the database's public key (Ed25519); it reads the database's tiles, and checks that they prove the record is in that tree; and it checks, with the tiles, that the tree is consistent with the latest tree head the repository has seen since flint started, so the database cannot show it two different logs.
3. It computes the `h1:` hash of the fetched `go.mod` file, or of the files in the module zip, and compares it with the record's.

Content that does not match is refused with `502`, and never enters the cache, so an upstream proxy, or someone between it and flint, cannot plant a module that every later build would download from flint.
A module version the checksum database has no record of, or whose record the database's tiles do not prove, is refused the same way, with a message naming it and the database, and nothing is cached; that holds for a mirror given as `go.sumdb.url` too, which cannot pair a made-up record with a genuine signed tree head.

The checksum database is sum.golang.org, fetched from `https://sum.golang.org`, unless the repository's `go.sumdb` names another, by its public key as `GOSUMDB` names one, and optionally the URL to fetch it from, such as a mirror:

```json
"go": {"sumdb": {"key": "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
                 "url": "https://sumdb-mirror.example.com/sumdb/sum.golang.org"}}
```

Modules matching one of the repository's `go.noSumCheck` patterns are cached without being checked: the private modules of a private upstream proxy, which no public checksum database knows. A pattern is a module path, or a pattern in which `*` matches any run of characters, so `corp.example.com/*` covers every module below `corp.example.com/`.

### The checksum database proxy

Every proxy repository also serves its checksum database to clients, under `sumdb/<name>/`, where `<name>` is the database's name, such as `sum.golang.org`:

- `supported` answers `200`, which is how the go command finds out that it can fetch the database through the repository.
- Lookups and tiles never change, so once cached they are served forever. A lookup is cached only once it is proven, as the previous section says. Of the tiles flint reads to prove records, it caches the full tiles the proof authenticates, and never the partial tiles at the edge of a tree, which the database replaces as the log grows; the tiles clients ask for are cached as fetched, since the go command proves them itself.
- The latest signed tree head is a document served for a minute after the database last confirmed it, and as last fetched while the database is unreachable. One whose signature does not verify, or that the tiles do not prove consistent with the latest tree head seen, never replaces the cached one.

## Virtual repositories

A virtual repository serves one module proxy over an ordered list of Go proxy repositories:

- **Version lists** are the union of the members' lists.
- **A version's files** come from the first member that has the version: the first whose `.info` of the version answers. A member's `.info` files are cached forever, and its upstream's not-found answers remembered for a minute, so finding the member is cheap after the first request.
- **`@latest` and queries** come from the first member that answers them.
- **Filters.** A member with `include` or `exclude` patterns is consulted only for the module paths they admit, compared exactly, with `*` matching any run of characters. Give the member serving your private modules `"include": ["corp.example.com/*"]`, and exclude the same patterns from the public members, as in `{"name": "goproxy", "exclude": ["corp.example.com/*"]}`: then a module someone publishes upstream under one of your module paths is never served, and the public upstream never learns your module paths. This is the server-side counterpart of `GOPRIVATE`.
- **A member that fails**, such as a proxy whose upstream is unreachable with nothing cached, is left out with a warning in the log, counted in `flint_virtual_member_skips_total`, so one unreachable upstream does not take the virtual repository down. The request fails only if no member could answer.
- **The checksum database** is served through the first member that proxies the database the request names.

Pulling through a virtual repository needs the `read` role on the virtual repository, or its `anonymousPull`; the members' own permissions are not consulted.

## Not supported

- Hosted Go modules: the go command has no publish.
- Fetching modules directly from version control: flint never runs git. Put `direct` after flint in `GOPROXY` for modules that no upstream proxy serves.
- Serving a checksum database of private modules: use `GONOSUMDB` or `GOPRIVATE` for them.
