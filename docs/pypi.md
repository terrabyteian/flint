# PyPI

flint serves Python packages from three kinds of PyPI repository:

- **Hosted** repositories hold first-party packages, which you publish with `twine upload` or `uv publish`.
- **Proxy** repositories cache an upstream index, such as pypi.org, and keep serving what they cached when it is down.
- **Virtual** repositories merge hosted and proxy repositories into one index, so pip and uv need a single index URL, with dependency-confusion protection on by default.

[Configuration](configuration.md#repositories) describes how to declare them.
A typical setup publishes to a hosted repository and installs from a virtual repository over it and a pypi.org proxy:

```json
"repositories": [
  {"name": "pypi-local", "format": "pypi", "type": "hosted"},
  {"name": "pypi", "format": "pypi", "type": "proxy", "proxy": {"url": "https://pypi.org/simple/"}},
  {"name": "pypi-all", "format": "pypi", "type": "virtual", "anonymousPull": true,
   "virtual": {"members": ["pypi-local", "pypi"]}}
]
```

## URLs

Each repository is served under `/pypi/<repository>/`:

| URL | Serves |
| --- | --- |
| `/pypi/<repository>/simple/` | The index: the URL to give pip and uv. Its root lists the repository's projects. |
| `/pypi/<repository>/simple/<project>/` | A project's page: its files, with their hashes and metadata. |
| `/pypi/<repository>/files/<project>/<filename>` | A distribution file. |
| `/pypi/<repository>/files/<project>/<filename>.metadata` | A file's core metadata (PEP 658), where available. |
| `/pypi/<repository>/legacy/` | The upload URL, for twine and uv publish. Hosted repositories only. |
| `/pypi/<repository>/pypi/<project>/json` | The JSON API: the project and its releases. |
| `/pypi/<repository>/pypi/<project>/<version>/json` | The JSON API for one release. |

Project names in URLs are normalized as PEP 503 says: lowercase, with runs of `-`, `_`, and `.` replaced by `-`.
A project page asked for under another spelling, such as `/simple/Zope.Interface/`, redirects to the normalized one, `/simple/zope-interface/`.

Project pages and the root index are served as HTML (PEP 503) or JSON (PEP 691) by content negotiation on the `Accept` header, or the `format` query parameter.
They carry the API version 1.1, and with it each project's versions and each file's size and upload time (PEP 700), the `requires-python` of each file, which files are yanked (PEP 592), and which have a core-metadata file, with its sha256 digest (PEP 658 and PEP 714).
Their links to files are relative, so pages do not depend on the host name clients use.
Pages carry an `ETag`, so clients that revalidate a cached page, as pip does, get `304 Not Modified` when it has not changed.

## Configuring clients

The examples use `https://registry.example` for flint, and the repositories above.

### Credentials

PyPI clients authenticate with HTTP basic credentials: an [API token](auth.md#api-tokens) with the user name `__token__`, or a user name and its password or token.
A repository with `anonymousPull` needs no credentials to install from.
Installing needs the `read` role, publishing `write`, and yanking and deleting `delete` ([permissions](auth.md#permissions)).
A request without credentials that needs them gets `401` with `WWW-Authenticate: Basic realm="flint"`, which makes pip and uv look for credentials in `.netrc` or a keyring.

Create a token for publishing with the [admin API](auth.md#tokens):

```sh
curl -u alice https://registry.example/api/v1/tokens -d '{
  "name": "publish",
  "scopes": [{"repositories": ["pypi-local"], "role": "write"}]
}'
```

Credentials can go in `~/.netrc`, which pip, uv, and twine all read, instead of in URLs:

```
machine registry.example
login __token__
password flint_...
```

### pip

```sh
pip install --index-url https://registry.example/pypi/pypi-all/simple/ requests
```

or in `pip.conf` (`~/.config/pip/pip.conf` on Linux):

```ini
[global]
index-url = https://registry.example/pypi/pypi-all/simple/
```

For a repository that needs credentials, put them in the URL, `https://__token__:<token>@registry.example/pypi/pypi-local/simple/`, or in `.netrc`.
Prefer one virtual repository as the index URL over `--extra-index-url`: pip treats every index as equal, so an extra index cannot protect a first-party name from a package of the same name upstream, while a virtual repository can.

### uv

```sh
uv pip install --index-url https://registry.example/pypi/pypi-all/simple/ requests
```

or for a project, in `pyproject.toml`:

```toml
[[tool.uv.index]]
name = "flint"
url = "https://registry.example/pypi/pypi-all/simple/"
default = true
```

`UV_DEFAULT_INDEX` sets the same for every command, `uv build` included.
uv reads credentials from the URL, `.netrc`, or `UV_INDEX_FLINT_USERNAME` and `UV_INDEX_FLINT_PASSWORD` for an index named `flint`.

### Publishing with twine

```sh
twine upload --repository-url https://registry.example/pypi/pypi-local/legacy/ \
  -u __token__ -p "$FLINT_TOKEN" dist/*
```

or with a repository in `~/.pypirc`:

```ini
[distutils]
index-servers = flint

[flint]
repository = https://registry.example/pypi/pypi-local/legacy/
username = __token__
password = flint_...
```

and `twine upload --repository flint dist/*`.

### Publishing with uv

```sh
uv publish --publish-url https://registry.example/pypi/pypi-local/legacy/ \
  -u __token__ -p "$FLINT_TOKEN" dist/*
```

or in `pyproject.toml`, with `uv publish --index flint`:

```toml
[[tool.uv.index]]
name = "flint"
url = "https://registry.example/pypi/pypi-all/simple/"
publish-url = "https://registry.example/pypi/pypi-local/legacy/"
```

## Hosted repositories

Publishing uploads one file per request with the legacy upload API, as twine and uv publish do.
flint accepts wheels (`.whl`) and source distributions (`.tar.gz`, or `.zip` for older projects), and checks each upload as PyPI does:

- The project name must be valid (PEP 508) and the version a valid PEP 440 version.
- The file name must belong to the project and version, as the wheel file name format and the `{name}-{version}` source distribution convention say, and its type must match the `filetype` field.
- The file must match each digest the client sends: `sha256_digest`, `md5_digest`, and `blake2_256_digest`. twine and uv send all three.
- A wheel must hold `{name}-{version}.dist-info/METADATA` naming the same project and version.
- PEP 740 attestations are not supported, and an upload that carries them is refused.

**File names are never reused.**
Publishing a file under a name the repository has already used fails with `409 Conflict` and "File already exists", unless it is the very same file, which succeeds again, so retrying an upload is harmless.
That holds after the file is deleted, too: a deleted file leaves a tombstone, because a different file under a name that was once installed would break every install that pins its hash.
Publish a new version instead, or a new build number for a wheel.

A file's core metadata is served as its `.metadata` file (PEP 658), so pip and uv resolve dependencies without downloading it: a wheel's `METADATA`, and a source distribution's `PKG-INFO` when it is reliable, metadata version 2.2 or later with no dynamic fields (PEP 643).
The JSON API also uses the metadata of other source distributions, or, for a file that holds none flint can read, the metadata fields of the upload form.

### Yanking and deleting

The [admin API](auth.md#admin-api) yanks, unyanks, and deletes, with the `delete` role on the repository:

| Request | Does |
| --- | --- |
| `PUT /api/v1/pypi/{repository}/projects/{project}/releases/{version}/yank` | Yank every file of a release (PEP 592), with an optional body `{"reason": "..."}`. |
| `DELETE /api/v1/pypi/{repository}/projects/{project}/releases/{version}/yank` | Unyank the release. |
| `DELETE /api/v1/pypi/{repository}/projects/{project}/releases/{version}` | Delete every file of a release. |
| `DELETE /api/v1/pypi/{repository}/projects/{project}/files/{filename}` | Delete one file. |

Each answers `200` with the files it changed, such as `{"project": "my-app", "version": "1.2.0", "files": ["my_app-1.2.0-py3-none-any.whl", "my_app-1.2.0.tar.gz"]}`, and errors as the rest of the admin API does.

```sh
curl -u alice -X PUT https://registry.example/api/v1/pypi/pypi-local/projects/my-app/releases/1.2.0/yank \
  -d '{"reason": "breaks on Python 3.13"}'
```

pip and uv skip a yanked release unless a requirement pins it exactly, as in `my-app==1.2.0`.
A deleted file disappears from the index at once, and its disk space is reclaimed by garbage collection, which arrives with milestone M4; its name stays used forever.
A project whose files are all deleted has no page, but the repository still owns its name, for [dependency-confusion protection](#virtual-repositories).

## Proxy repositories

A proxy repository caches one upstream index, given by the simple index URL you would give pip, such as `https://pypi.org/simple/`, or `https://download.pytorch.org/whl/cpu` for PyTorch's.

- **Project pages** are fetched from the upstream, asking for the JSON form (PEP 691) and reading HTML pages too, and stored in the cache with links rewritten to point at flint. A cached page is served for `revalidateAfter` (default 5 minutes) after the upstream last confirmed it; after that, flint asks the upstream again, sending the page's `ETag` so an unchanged page costs a `304`. flint keeps when the upstream last confirmed a page in memory only, so after a restart each page is revalidated when it is first asked for.
- **Files and core-metadata files** never change, so once cached they are served forever without asking the upstream. They are fetched from wherever the page links, often another host, as pypi.org links `files.pythonhosted.org`, and checked against the sha256 digest the page gives: a file that does not match is refused with `502`, or cut off before its last byte if part of it was already sent, and never enters the cache. Concurrent requests for the same file share one upstream fetch, and the first client streams the file as it arrives.
- **A file whose page entry has no sha256 digest** cannot be verified, so it is passed through from the upstream without being cached. pypi.org gives a digest for every file.
- **When the upstream is unreachable**, because of network errors, timeouts, `5xx` errors, or `429` rate limiting, cached pages and files keep being served, and flint treats the upstream as offline for 30 seconds. A project or file that was never cached is answered with `503`.
- **When the upstream answers that a project is not found or denied**, flint answers `404` too, even if it has the project cached.
- **Disk space and size limits** work as for [OCI proxy repositories](configuration.md#proxy-repositories): under `proxyCache.minFreeSpace`, new files are passed through without being cached; with `proxy.sizeLimit`, the least recently downloaded files and core-metadata files are evicted to stay within the limit. Project pages do not count against the limit.
- **The root index**, `/pypi/<repository>/simple/`, lists the projects cached so far, not every project upstream.
- **Credentials.** With `proxy.username` and `proxy.passwordFile`, flint answers the upstream's authentication challenges, and sends the credentials only to the host of `proxy.url`, never to a host its pages link files on.
- **Read-only.** Uploads are refused with `405`.

flint fetches files from wherever the upstream's pages link, so configure only upstream indexes you trust: a compromised index could send flint, and through it its clients, to other addresses on flint's network.

## Virtual repositories

A virtual repository serves one index over an ordered list of hosted and proxy members:

- A project page lists the files of every member that has the project. Where members have a file of the same name, the first member's is served, and a file's link leads to the member that holds it.
- **Dependency-confusion protection**, on by default: once a hosted member owns a project name, that name's upstream versions are never served through the virtual repository, not even versions the hosted member lacks, and the proxy members are not even asked about it. A hosted repository owns a name from the first upload of a file of it, and keeps it after every file is deleted. So a package someone publishes on pypi.org under the name of a first-party package can never be installed in its place. Set `virtual.dependencyConfusionProtection` to `false` to merge every member for every name.
- A member that fails, such as a proxy whose upstream is unreachable and has the project uncached, is left out with a warning in the log, so one unreachable upstream does not take the whole index down. The request fails only if no member could answer.
- The JSON API merges the members the same way.
- The root index lists the projects of every member.
- Uploads are refused with `405`, naming the hosted members to publish to instead.

Pulling through a virtual repository needs the `read` role on the virtual repository, or its `anonymousPull`; the members' own permissions are not consulted.

## The JSON API

`/pypi/<repository>/pypi/<project>/json` follows PyPI's JSON API: `info` describes the latest release, `releases` lists every release's files, and `urls` the latest release's.
The latest release is the highest final release that is not yanked, falling back to pre-releases and then to yanked releases.
`/pypi/<repository>/pypi/<project>/<version>/json` describes one release, without `releases`, as on PyPI.

`info` comes from the core metadata of the release's files, a wheel's first: the stored metadata of a hosted file, or a proxy file's core-metadata file, fetched and cached when the upstream offers one.
For a release without any, it holds only the name, the version, and `requires_python`.
File URLs are absolute, built from the scheme and host the client used, through [trusted proxies](configuration.md#trusted-proxies) as configured; each file has its `sha256` digest, and for hosted files also `md5` and `blake2b_256`.
`last_serial` is the metadata store's sequence number of the project's latest change in the repository, which changes whenever the project does.
Download counts are `-1`, and `vulnerabilities` is empty.

## Not supported

- XML-RPC search, which PyPI itself disabled.
- Trusted publishing and PEP 740 attestations, which come after v1.
- Uploading documentation, and the legacy `submit` action: register a project by uploading a file of it.
