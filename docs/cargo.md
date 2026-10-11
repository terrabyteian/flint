# Cargo

flint serves Rust crates from three kinds of Cargo repository, over Cargo's sparse registry protocol:

- **Hosted** repositories hold first-party crates, which you publish with `cargo publish`.
- **Proxy** repositories cache an upstream sparse index, such as crates.io's, and keep serving what they cached when it is down.
- **Virtual** repositories merge hosted and proxy repositories into one registry, so Cargo needs a single index URL for installing and publishing, with dependency-confusion protection on by default.

[Configuration](configuration.md#repositories) describes how to declare them.
A typical setup publishes to a hosted repository and builds from a virtual repository over it and a crates.io proxy:

```json
"repositories": [
  {"name": "cargo-local", "format": "cargo", "type": "hosted"},
  {"name": "crates-io", "format": "cargo", "type": "proxy", "proxy": {"url": "sparse+https://index.crates.io/"}},
  {"name": "cargo-all", "format": "cargo", "type": "virtual",
   "virtual": {"members": ["cargo-local", {"name": "crates-io", "exclude": ["acme-*"]}], "publishTo": "cargo-local"}}
]
```

## URLs

Each repository is served under `/cargo/<repository>/`, and its index URL, which Cargo is given, is `sparse+https://registry.example/cargo/<repository>/`:

| URL | Serves |
| --- | --- |
| `/cargo/<repository>/config.json` | The index configuration: where crates are downloaded (`dl`), the web API (`api`), and `auth-required`. |
| `/cargo/<repository>/1/<name>`, `2/<name>`, `3/<c>/<name>`, `<ab>/<cd>/<name>` | A crate's index file: one JSON line per version, with its dependencies, features, checksum, and whether it is yanked. |
| `/cargo/<repository>/api/v1/crates/new` | Publishing, with `PUT`. Hosted repositories, and virtual repositories with `publishTo`. |
| `/cargo/<repository>/api/v1/crates/<name>/<version>/download` | A `.crate` file. |
| `/cargo/<repository>/api/v1/crates/<name>/<version>/yank` | Yanking, with `DELETE`. |
| `/cargo/<repository>/api/v1/crates/<name>/<version>/unyank` | Unyanking, with `PUT`. |
| `/cargo/<repository>/api/v1/crates?q=<query>` | Search. |

Index files are named by the crate's name in lowercase, as Cargo asks for them.
`config.json` names the repository's own URLs: `api` is `/cargo/<repository>` and `dl` is `/cargo/<repository>/api/v1/crates`, under [`publicURL`](configuration.md#public-url) when it is set, and otherwise under the scheme and host the client used, through [trusted proxies](configuration.md#trusted-proxies) as configured.
Set `publicURL` when clients reach flint under more than one name, since Cargo remembers where it downloaded from.
`auth-required` is `true` unless the repository has `anonymousPull`.
Index files and `config.json` carry an `ETag`, so Cargo's revalidation of a cached index file costs a `304 Not Modified` while the crate has not changed.
Errors are answered with the web API's `{"errors": [{"detail": "..."}]}`, whose detail Cargo shows.

## Configuring Cargo

The examples use `https://registry.example` for flint, and the repositories above.
They need Cargo 1.74 or later, which sends credentials with every request to a registry that requires them.

### Registries and credentials

Declare the repositories as registries in `~/.cargo/config.toml`, or in a project's `.cargo/config.toml`:

```toml
[registries.flint]
index = "sparse+https://registry.example/cargo/cargo-all/"
credential-provider = "cargo:token"

[registries.flint-local]
index = "sparse+https://registry.example/cargo/cargo-local/"
credential-provider = "cargo:token"
```

Cargo authenticates with an [API token](auth.md#api-tokens), which it sends as the `Authorization` header as it is.
`credential-provider = "cargo:token"` lets Cargo send it with every request, not only to publish, which a repository without `anonymousPull` needs.
Create a token with the [admin API](auth.md#tokens):

```sh
curl -u alice https://registry.example/api/v1/tokens -d '{
  "name": "cargo",
  "scopes": [{"repositories": ["cargo-all", "cargo-local"], "role": "write"}]
}'
```

and store it with `cargo login --registry flint`, which reads it from standard input and keeps it in `~/.cargo/credentials.toml`, or set it in the environment as `CARGO_REGISTRIES_FLINT_TOKEN`, as in CI.
Building needs the `read` role, publishing and yanking `write`, and deleting `delete` ([permissions](auth.md#permissions)).
A request without credentials that needs them gets `401` with `WWW-Authenticate: Cargo login_url="..."`, after which Cargo retries with its token, or tells you to log in.

### Depending on crates from flint

```toml
[dependencies]
my-crate = { version = "1.2", registry = "flint" }
```

### Replacing crates.io

To fetch every crates.io dependency through flint as well, replace crates.io's source with the virtual repository:

```toml
[source.crates-io]
replace-with = "flint"
```

Cargo then asks flint for every crate, and `Cargo.lock` keeps naming crates.io as their source, so a lockfile works with or without the replacement.
Even without it, a crate published to a hosted repository resolves its crates.io dependencies through a virtual repository that has a crates.io proxy member (see [virtual repositories](#virtual-repositories)).

### Publishing

```sh
cargo publish --registry flint
```

publishes to the virtual repository's `publishTo` member; `--registry flint-local` publishes to the hosted repository directly.
To keep a crate from being published to crates.io by mistake, name the registries it may go to in its `Cargo.toml`:

```toml
[package]
publish = ["flint"]
```

### Yanking and searching

```sh
cargo yank --registry flint my-crate@1.2.0
cargo yank --registry flint --undo my-crate@1.2.0
cargo search --registry flint my-
```

## Hosted repositories

`cargo publish` sends the crate's metadata and its `.crate` file in one request, and flint checks them as crates.io does:

- The crate name must be 1 to 64 ASCII letters, digits, `-`, and `_`, starting with a letter, and the version a semantic version.
- The `.crate` file must be a gzip-compressed tar archive whose files are all under `<name>-<version>/`, including `<name>-<version>/Cargo.toml`.
- The metadata may be at most 16 MiB (it carries the README), the `.crate` file at most 128 MiB, and its content at most 1 GiB unpacked.

flint builds the version's index line from the metadata, as the Cargo reference specifies, without reading `Cargo.toml`.
Its `cksum` is the sha256 digest of the `.crate` file, which is also how the file is stored, so it is stored once whichever repositories hold it.
Features that use the `dep:` or `?` syntax are listed in `features2`, with `v` 2, as on crates.io.
A dependency on a crate from crates.io keeps naming crates.io's index in its `registry` field, so Cargo fetches it from crates.io, or through your source replacement for crates.io.

**Names keep their first spelling.**
A crate name that differs from a published one only in case, or in `-` versus `_`, is the same crate, and is refused with `409 Conflict`: after `my-crate`, neither `My-Crate` nor `my_crate` can be published.

**Versions are never published twice.**
Publishing a version again fails with `409 Conflict`, as on crates.io, as does a version that differs from a published one only in its build metadata, such as `1.0.0+abc` after `1.0.0`.
That holds after the version is deleted, too: a deleted version leaves a tombstone, because a different crate under a version once built would break every build whose `Cargo.lock` pins its checksum.
Publish a new version instead.

**Yanking** with `cargo yank` needs the `write` role, and changes only the `yanked` field of the version's index line: Cargo skips a yanked version when it resolves new dependencies, but a `Cargo.lock` that already pins it still builds.
`cargo yank --undo` unyanks it.

### Deleting versions

The [admin API](auth.md#admin-api) deletes a version, with the `delete` role on the repository:

```sh
curl -u alice -X DELETE https://registry.example/api/v1/cargo/cargo-local/crates/my-crate/1.2.0
```

It answers `200` with `{"crate": "my-crate", "version": "1.2.0"}`, and errors as the rest of the admin API does.
A deleted version disappears from the index file and from downloads at once, and its version stays used forever. [Garbage collection](garbage-collection.md) later reclaims its disk space, unless another repository stores the same bytes.
A crate whose versions are all deleted has no index file, but the repository still owns its name, for [dependency-confusion protection](#virtual-repositories).

## Proxy repositories

A proxy repository caches one upstream sparse index, such as `sparse+https://index.crates.io/` for crates.io.

- **Index files** are fetched from the upstream and stored in the cache exactly as the upstream sent them. A cached index file is served for `revalidateAfter` (default 5 minutes) after the upstream last confirmed it; after that, flint asks the upstream again, sending the file's `ETag` and `Last-Modified` so an unchanged file costs a `304`, also on the first request after a restart. An index file flint cannot read never replaces the cached one. Index lines carry no URLs, and a dependency without a `registry` means the registry serving the line, which is now flint, so they are served as they are.
- **`config.json`** is flint's own, naming the proxy repository's URLs. flint reads the upstream's to learn where its `.crate` files are downloaded, its `dl`, such as `https://static.crates.io/crates` for crates.io, and caches it like an index file.
- **`.crate` files** never change, so once cached they are served forever without asking the upstream. They are checked against the `cksum` of the index line that lists them: a file that does not match is refused with `502`, or cut off before its last byte if part of it was already sent, and never enters the cache. A proxy repository serves only what its upstream sent it: a file is fetched even if flint stores the same bytes for another repository, since a checksum is not a secret. Concurrent requests for the same file share one upstream fetch, and the first client streams the file as it arrives.
- **When the upstream is unreachable**, because of network errors, timeouts, `5xx` errors, or `429` rate limiting, cached index files and `.crate` files keep being served, and flint treats the upstream as offline for 30 seconds. A crate that was never cached is answered with `503`.
- **When the upstream answers that a crate is not found**, with `404`, `410`, or `451`, or denies access, flint answers `404` too, even if it has the crate cached.
- **Disk space and size limits** work as for [OCI proxy repositories](configuration.md#proxy-repositories): under `proxyCache.minFreeSpace`, new `.crate` files are passed through without being cached, still checked; with `proxy.sizeLimit`, the least recently downloaded `.crate` files are evicted to stay within the limit. Index files do not count against the limit.
- **Search** is passed through to the upstream's web API, the `api` of its `config.json`, and is not cached.
- **Credentials.** With `proxy.username` and `proxy.passwordFile`, flint answers the upstream's authentication challenges, and sends the credentials only to the host of `proxy.url`. A Cargo registry's challenge, such as another flint's, is answered as Cargo answers it, with the password file holding a token sent as the `Authorization` header; `proxy.username` is then not sent, but must be set. A Basic challenge is answered with the user name and password.
- **Read-only.** Publishes and yanks are refused with `405`.
- **Fetch policy.** flint fetches only from the host of `proxy.url`, the hosts crates.io serves its files and web API on (`static.crates.io` and `crates.io`, for `index.crates.io`), and the hosts in `proxy.allowHosts`. For another index whose `dl` or `api` is on a separate host, add that host to `proxy.allowHosts`. A host only the upstream's `config.json` names must resolve to a public address, so a compromised index cannot send flint at other services on its network; see [the fetch policy](configuration.md#upstream-fetch-policy).

## Virtual repositories

A virtual repository serves one registry over an ordered list of hosted and proxy members:

- A crate's index file lists the versions of every member that has the crate. Where members have the same version, the first member's line is served, and the version's `.crate` file is downloaded from that member.
- **Dependencies on a proxied registry become local.** A hosted crate's dependency on a registry that a proxy member caches, such as a dependency on crates.io with a crates.io proxy member, is served as a dependency on the virtual repository itself. So the whole dependency graph of a crate published to flint resolves through the virtual repository, even without source replacement.
- **Filters.** A member with `include` or `exclude` patterns is consulted only for the crate names they admit, compared in lowercase with `-` and `_` equal, so `Acme-*` and `acme_*` are the same filter. Exclude your internal prefixes from the crates.io member, as in `{"name": "crates-io", "exclude": ["acme-*"]}`: dependency-confusion protection covers a name only once a hosted member owns it, and the filter also covers internal names you have not published yet.
- **Dependency-confusion protection**, on by default: once a hosted member owns a crate name, in any spelling, that name's upstream versions are never served through the virtual repository, not even versions the hosted member lacks, and the proxy members are not even asked about it. A hosted repository owns a name from the first publish of a version of it, and keeps it after every version is deleted or yanked. So a crate someone publishes on crates.io under the name of a first-party crate can never be built in its place. Set `virtual.dependencyConfusionProtection` to `false` to merge every member for every name.
- A member that fails, such as a proxy whose upstream is unreachable and has the crate uncached, is left out with a warning in the log, counted in `flint_virtual_member_skips_total`, so one unreachable upstream does not take the whole registry down. The request fails only if no member could answer.
- **Search** lists the hosted members' matches first, then the proxy members' answers, each crate once, as the members' filters and dependency-confusion protection admit it.
- **Publishing and yanking** go to the hosted member that `virtual.publishTo` names, so one registry serves both building and publishing; they need the permissions publishing to that member needs. A publish or yank of a crate whose name that member's filters do not admit is refused with `403`, naming the member and the filter, and nothing changes. Without `publishTo`, they are refused with `405`, naming the hosted members to publish to instead.

Building through a virtual repository needs the `read` role on the virtual repository, or its `anonymousPull`; the members' own permissions are not consulted.

## Search

`cargo search` calls `/api/v1/crates?q=<query>&per_page=<n>`, which answers with each crate's name, highest version, and description.
There is no search index: a hosted repository matches the query, compared in lowercase with `-` and `_` equal, against the names of its crates, exact matches first, then names that start with it, then names that contain it.
The highest version is the highest that is neither yanked nor a pre-release, if any, and the description is that version's.
`per_page` defaults to 10 and is at most 100.

## Not supported

- The git index protocol: flint serves only the sparse protocol, which Cargo has used for crates.io by default since 1.70.
- Crate owners: `cargo owner` fails with a message naming flint's [permission grants](auth.md#permissions), which decide who may publish, yank, and delete.
- Asymmetric tokens (`cargo:paseto`) and the `/me` page that `cargo login` suggests, which comes with flint's UI.
- Download counts, and the web API beyond publishing, yanking, downloading, and search.
