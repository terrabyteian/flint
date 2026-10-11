# Generic files

flint stores and serves arbitrary files by path, for curl, wget, and scripts, from three kinds of generic files repository:

- **Hosted** repositories hold files you upload with `PUT`, such as build outputs, installers, and tarballs. Files are immutable by default.
- **Proxy** repositories cache files from any web server, such as a project's release downloads, and keep serving what they cached when it is down.
- **Virtual** repositories serve each path from the first of their hosted and proxy members that has it, so scripts need a single base URL.

[Configuration](configuration.md#repositories) describes how to declare them.
A typical setup uploads to a hosted repository, mirrors a release download site, and downloads both through a virtual repository:

```json
"repositories": [
  {"name": "files", "format": "generic", "type": "hosted"},
  {"name": "tool-releases", "format": "generic", "type": "proxy", "generic": {"immutable": true},
   "proxy": {"url": "https://github.com/acme/tool/releases/download/",
             "allowHosts": ["release-assets.githubusercontent.com", "objects.githubusercontent.com"]}},
  {"name": "files-all", "format": "generic", "type": "virtual",
   "virtual": {"members": ["files", "tool-releases"], "publishTo": "files"}}
]
```

## URLs

Each repository is served under `/generic/<repository>/`:

| Request | Does |
| --- | --- |
| `GET`, `HEAD /generic/<repository>/<path>` | Downloads a file, with `Range` and conditional requests. |
| `PUT /generic/<repository>/<path>` | Uploads a file. Hosted repositories, and virtual repositories with `publishTo`. |
| `DELETE /generic/<repository>/<path>` | Deletes a file. Hosted repositories. |
| `GET`, `HEAD /generic/<repository>/<dir>/` | Lists the files and directories directly below `<dir>`; `/generic/<repository>/` lists the top. |

A path is one or more segments separated by `/`, such as `tools/1.4.2/tool-linux-amd64.tar.gz`: at most 1024 bytes of UTF-8 without control characters, and no segment empty, `.`, or `..`.
Escape what a URL needs escaped, such as `%20` for a space; a path is compared exactly, so `Tool.tgz` and `tool.tgz` are different files.
There are no directories of their own: a directory exists while a file is below it.

Downloads carry:

- `Content-Type`: the type given at upload, or the one the file's extension implies, or `application/octet-stream`. A proxied file has the upstream's type.
- `ETag`: `"sha256:<hex>"`, the file's sha256 digest, with which a client revalidates a copy it has.
- For hosted files, `Last-Modified` (the upload time, so `wget -N` skips files it has), `X-Checksum-Sha256`, and `Repr-Digest` (RFC 9530).
- `Content-Security-Policy: sandbox` and `X-Content-Type-Options: nosniff`, so an uploaded HTML page or script opened in a browser never runs as part of flint's site.

### Listings

A `GET` of a path ending in `/` lists what is directly below it, as JSON with `Accept: application/json`, and as an HTML page of links otherwise, which browsers show and `wget -r` follows:

```json
{
  "repository": "files",
  "path": "tools/",
  "entries": [
    {"name": "1.4.2/", "type": "directory"},
    {"name": "README.md", "type": "file", "size": 1024, "sha256": "…", "contentType": "text/markdown; charset=utf-8",
     "uploaded": "2026-10-11T12:00:00Z"}
  ]
}
```

Entries are sorted by name.
A directory with nothing below it is `404`, and deleted files are not listed.

## Configuring clients

The examples use `https://registry.example` for flint, and the repositories above.

### Credentials

curl and wget authenticate with HTTP basic credentials: a user name and its password or an [API token](auth.md#api-tokens).
Scripts may instead send an API token as `Authorization: Bearer <token>`.
A repository with `anonymousPull` needs no credentials to download from.
A request without credentials that needs them gets `401` with `WWW-Authenticate: Basic realm="flint"`; one whose credentials lack the permission gets `403`.
Downloading and listing need the `read` role, uploading `write`, and deleting `delete` ([permissions](auth.md#permissions)).

Create a token for uploads with the [admin API](auth.md#tokens):

```sh
curl -u alice https://registry.example/api/v1/tokens -d '{
  "name": "ci uploads",
  "scopes": [{"repositories": ["files"], "role": "write"}]
}'
```

To keep credentials off the command line, put them in `~/.netrc`, which both curl (with `-n`) and wget read:

```
machine registry.example login ci-bot password flint_...
```

### curl

```sh
# Upload; -f fails on an error status.
curl -fsS -u "ci-bot:$TOKEN" -T dist/tool.tar.gz https://registry.example/generic/files/tools/1.4.2/tool.tar.gz

# Upload, verified against the digest you computed.
curl -fsS -u "ci-bot:$TOKEN" -T dist/tool.tar.gz \
  -H "X-Checksum-Sha256: $(sha256sum dist/tool.tar.gz | cut -d' ' -f1)" \
  https://registry.example/generic/files/tools/1.4.2/tool.tar.gz

# Download, with a token as a bearer token, or from ~/.netrc.
curl -fsSLO -H "Authorization: Bearer $TOKEN" https://registry.example/generic/files/tools/1.4.2/tool.tar.gz
curl -fsSLOn https://registry.example/generic/files/tools/1.4.2/tool.tar.gz

# Resume an interrupted download.
curl -fsSLn -C - -O https://registry.example/generic/files/tools/1.4.2/tool.tar.gz

# List a directory.
curl -fsSn -H 'Accept: application/json' https://registry.example/generic/files/tools/

# Delete.
curl -fsSn -X DELETE https://registry.example/generic/files/tools/1.4.2/tool.tar.gz
```

An upload answers `201 Created` with the file's path, sha256 digest, size, and content type as JSON, or `200 OK` when the very same file was there already.

### wget

```sh
# Download; wget waits for the Basic challenge before it sends credentials.
wget --user=ci-bot --password="$TOKEN" https://registry.example/generic/files/tools/1.4.2/tool.tar.gz

# Upload, with a token as a bearer token.
wget --method=PUT --body-file=dist/tool.tar.gz --header="Authorization: Bearer $TOKEN" \
  https://registry.example/generic/files/tools/1.4.2/tool.tar.gz

# Mirror a directory, following the HTML listings.
wget -r -np -nH --cut-dirs=2 -R 'index.html*' --user=ci-bot --password="$TOKEN" \
  https://registry.example/generic/files/tools/
```

wget sends uploads as `application/x-www-form-urlencoded` unless told otherwise; flint takes that, and `multipart/form-data`, to mean no type was given, and stores the type the file's extension implies.
To store another type, send it: `--header="Content-Type: application/zstd"`.

## Hosted repositories

- **Uploads.** `PUT` stores the request body as the file at its path, streamed into the blob store; flint stores each distinct content once however many paths and repositories have it. An upload may name the content's sha256 digest in `Content-Digest: sha-256=:<base64>:` (RFC 9530) or `X-Checksum-Sha256: <hex>`; content that does not match is refused with `400`, and nothing is stored. Other `Content-Digest` algorithms are ignored.
- **Content type.** The upload's `Content-Type`, unless it is absent or a form type, in which case the type the file's extension implies, or `application/octet-stream`.
- **Immutable files.** By default a file never changes once uploaded:
  - Uploading the very same content to its path again succeeds without a change, so a retried upload is harmless.
  - Uploading different content is refused with `409`; when the request names a digest that differs, before the body is read.
  - Deleting a file leaves a tombstone: the path is gone, and can never be used again, not even for the same content, because a path that comes back with other bytes breaks every script that pinned the old ones. Upload to a new path, such as one with a new version in it.
  - Of concurrent uploads to one path, all with the same content succeed, and of different content exactly one does.
- **`generic.allowOverwrite`.** For scratch areas and "latest build" directories: an upload with `write` replaces the file, and a delete removes it without a tombstone, so its path can be used again. Downloads are then marked `Cache-Control: no-cache` rather than cacheable for a year.
- **Deletes** need `delete`, hide the file at once, and leave reclaiming its bytes to [garbage collection](garbage-collection.md).

## Proxy repositories

A proxy repository caches files from one upstream base URL, `proxy.url`: a request for `/generic/<repository>/<path>` fetches `<proxy.url>/<path>`.

- **Revalidated by default.** flint cannot know whether a path of an arbitrary web server changes, so a cached file is served for `revalidateAfter` (default 5 minutes) after the upstream last confirmed it; after that, flint asks the upstream again, sending the file's `ETag` and `Last-Modified`, so an unchanged file costs a `304`, also on the first request after a restart. A file that changed is fetched again and replaces the cached one.
- **`generic.immutable`.** For release download sites, whose files never change: a file is fetched once and cached forever, never revalidated, and concurrent requests for it share one upstream fetch, which streams to every waiting client as it arrives.
- **Redirects** are followed only to hosts the [fetch policy](configuration.md#upstream-fetch-policy) allows: the upstream's own host and `proxy.allowHosts`. GitHub release downloads redirect to `release-assets.githubusercontent.com` (and, for older releases, `objects.githubusercontent.com`), which must be allowed, as in the example above; a redirect anywhere else is answered with `502`.
- **When the upstream is unreachable**, because of network errors, timeouts, `5xx` errors, or `429` rate limiting, cached files keep being served, revalidated or not, and flint treats the upstream as offline for 30 seconds. A file that was never cached is answered with `503`.
- **When the upstream answers that a file is not found or denied**, flint answers `404` too, also for a cached file it was revalidating, and remembers the answer for a minute, so scripts probing for files that do not exist cost one upstream request a minute.
- **Query strings** are refused with `400`, so a file's path alone is its name in the cache.
- **Directory listings** are not proxied: a path ending in `/` is `404`.
- **Disk space and size limits** work as for [OCI proxy repositories](configuration.md#proxy-repositories): under `proxyCache.minFreeSpace`, new files are passed through without being cached; without `generic.immutable`, only files up to 64 MiB, and a larger file that is not cached is answered with `503`. `proxy.sizeLimit` needs `generic.immutable`, since only files cached forever count against it; over it, the least recently downloaded files are evicted.
- **Credentials.** With `proxy.username` and `proxy.passwordFile`, flint answers the upstream's Basic or Bearer authentication challenges, and sends the credentials only to the host of `proxy.url`, never to a host it is redirected to.
- **Read-only.** Uploads and deletes are refused with `405`.

## Virtual repositories

A virtual repository serves each path from the first of its members, in order, that has the file:

- **Filters.** A member with `include` or `exclude` patterns is consulted only for the paths they admit, such as `{"name": "tool-releases", "include": ["v*"]}`; a pattern matches a whole path, with `*` matching any run of characters, `/` included.
- **Dependency-confusion protection**, on by default: once a hosted member has a file at a path, or a tombstone of one, the proxy members are never consulted for that path, so a file an upstream serves can never stand in for a first-party one, even after the first-party file is deleted. Set `virtual.dependencyConfusionProtection` to `false` to consult every member in order.
- A member that fails, such as a proxy whose upstream is unreachable and has the file uncached, is skipped with a warning in the log, counted in `flint_virtual_member_skips_total`, and the next member is consulted. The request fails with the first failure only if no member has the file.
- **Listings** merge the listings of the hosted members, filtered by their filters, the first member's entry winning where several have the same name. Proxy members' directories are not listed.
- **Uploads** go to the hosted member that `virtual.publishTo` names, and need the permission an upload to it directly needs. An upload to a path that member's filters do not admit is refused with `403`, naming the member and the filter, and nothing is stored. Without `publishTo`, uploads are refused with `405`, naming the hosted members to upload to instead. Deletes go to the hosted repository directly.

Downloading through a virtual repository needs the `read` role on the virtual repository, or its `anonymousPull`; the members' own permissions are not consulted.

## Not supported

- WebDAV, and multipart form uploads.
- Extracting archives, or bundling files into one.
- Directory listings of proxy repositories.
