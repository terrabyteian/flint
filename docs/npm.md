# npm

flint serves npm packages to npm, pnpm, Yarn (classic and Berry), and Bun from three kinds of npm repositories:

- **Hosted** repositories hold first-party packages, which clients install from them and publish to them.
- **Proxy** repositories cache an upstream registry, such as registry.npmjs.org, so installs keep working when it is slow or down, and a package or version it removes keeps installing from lockfiles.
- **Virtual** repositories merge hosted and proxy repositories into one registry, so clients need a single URL to install everything and to publish, with protection against dependency confusion.

[Configuration](configuration.md#repositories) describes how to declare them:

```json
"repositories": [
  {"name": "npm-local", "format": "npm", "type": "hosted"},
  {"name": "npmjs", "format": "npm", "type": "proxy",
   "proxy": {"url": "https://registry.npmjs.org/"}},
  {"name": "npm", "format": "npm", "type": "virtual",
   "virtual": {"members": ["npm-local", {"name": "npmjs", "exclude": ["@acme/*"]}], "publishTo": "npm-local"}}
]
```

## URLs

A repository's registry URL, the URL to configure clients with, is `/npm/<repository>/`.
Below it is the npm registry API:

| URL | Serves |
| --- | --- |
| `/npm/<repository>/<name>` | A package's packument: its versions, dist-tags, and readme. `PUT` publishes a version, and edits the package to deprecate or unpublish versions. |
| `/npm/<repository>/<name>/<version or dist-tag>` | One version's manifest. |
| `/npm/<repository>/<name>/-/<file>.tgz` | A version's tarball. |
| `/npm/<repository>/-/package/<name>/dist-tags` | The package's dist-tags; `/dist-tags/<tag>` sets or removes one. |
| `/npm/<repository>/-/user/org.couchdb.user:<user>` | `npm login`. |
| `/npm/<repository>/-/whoami`, `/-/ping`, `/-/v1/search` | `npm whoami`, `npm ping`, `npm search`. |
| `/npm/<repository>/-/npm/v1/security/advisories/bulk` | `npm audit`. |
| `/npm/<repository>/-/npm/v1/keys`, `/-/npm/v1/attestations/<name>@<version>` | Registry signing keys and provenance, for `npm audit signatures`. |

A scoped package's name is accepted encoded, as `@acme%2fwidget`, which is how npm sends it, and plain, as `@acme/widget`.
A packument is served in full, or in the abbreviated form installers ask for with `Accept: application/vnd.npm.install-v1+json`, which leaves out readmes and the other fields installing does not need.
Packuments carry an `ETag`, so a client revalidating its cached copy gets `304 Not Modified` when nothing changed.

Tarball URLs in packuments are absolute, because lockfiles record them: `https://registry.example/npm/npm-local/@acme/widget/-/widget-1.0.0.tgz`.
They are built from [`publicURL`](configuration.md#public-url) when it is set, and otherwise from the scheme and host the client used, through [trusted proxies](configuration.md#trusted-proxies) as configured; set `publicURL` so lockfiles hold one stable URL however clients reach flint.
Tarballs are below the registry URL, so clients send the registry's credentials when they download them.
Proxy and virtual repositories serve the same API, with every tarball URL below their own registry URL, so a lockfile records only flint's URLs.

## Configuring clients

The examples use `https://registry.example` for flint and the repository `npm-local`.
To install public and first-party packages from one URL and publish there too, give clients a [virtual repository](#virtual-repositories) instead, such as `npm` above; see [one registry for everything](#one-registry-for-everything).

### Credentials

npm clients authenticate with an [API token](auth.md#api-tokens), which they send as `Authorization: Bearer <token>`.
Create one with the [admin API](auth.md#tokens), or with [`npm login`](#logging-in-with-npm-login):

```sh
curl -u alice https://registry.example/api/v1/tokens -d '{
  "name": "npm",
  "scopes": [{"repositories": ["npm-local"], "role": "write"}]
}'
```

Installing needs the `read` role, publishing, dist-tags, and deprecating `write`, and unpublishing `delete` ([permissions](auth.md#permissions)).
A repository with `anonymousPull` needs no token to install from.
A request without credentials that needs them gets `401`, and npm tells the user to log in; one whose token lacks the permission gets `403`.
Tarballs never change, so flint lets clients cache them for a year; only those of a repository with `anonymousPull` are marked `public`, so a shared cache never hands a private package to a client that could not download it.

Recent releases of pnpm and Yarn Berry hold back versions published less than a day ago by default (pnpm's `minimumReleaseAge`, Yarn's `npmMinimalAgeGate`), judging by the publish times flint serves, so a version just published to flint installs only after a day unless you lower the setting.

### npm

In `.npmrc`, in the project or in your home directory:

```ini
registry=https://registry.example/npm/npm-local/
//registry.example/npm/npm-local/:_authToken=${FLINT_TOKEN}
```

The second line holds the token for every URL below the registry URL; npm reads `${FLINT_TOKEN}` from the environment.
To use flint for one scope only, with the public registry for everything else:

```ini
@acme:registry=https://registry.example/npm/npm-local/
//registry.example/npm/npm-local/:_authToken=${FLINT_TOKEN}
```

`publishConfig` in `package.json` makes `npm publish` go to flint whatever the user's configuration:

```json
"publishConfig": {"registry": "https://registry.example/npm/npm-local/"}
```

### pnpm and Bun

pnpm and Bun read the same `.npmrc` as npm.
Bun also reads `bunfig.toml`:

```toml
[install]
registry = { url = "https://registry.example/npm/npm-local/", token = "$FLINT_TOKEN" }
```

### Yarn classic

Yarn 1 reads the registry and token from `.npmrc` too, but sends the token for unscoped packages only with `always-auth`:

```ini
registry=https://registry.example/npm/npm-local/
//registry.example/npm/npm-local/:_authToken=${FLINT_TOKEN}
always-auth=true
```

### Yarn Berry

In `.yarnrc.yml`:

```yaml
npmRegistryServer: "https://registry.example/npm/npm-local/"
npmAuthToken: "${FLINT_TOKEN}"
npmAlwaysAuth: true
```

or for one scope:

```yaml
npmScopes:
  acme:
    npmRegistryServer: "https://registry.example/npm/npm-local/"
    npmAuthToken: "${FLINT_TOKEN}"
    npmAlwaysAuth: true
```

Yarn Berry refuses plain-HTTP registries unless their host is in `unsafeHttpWhitelist`; serve flint over HTTPS.

### One registry for everything

With a virtual repository whose members are a hosted repository and a proxy of registry.npmjs.org, and whose `publishTo` is the hosted repository, one registry URL serves installing every package and publishing first-party ones.
Each client is configured as above, with the virtual repository's URL:

```ini
# .npmrc, for npm, pnpm, Bun, and Yarn classic
registry=https://registry.example/npm/npm/
//registry.example/npm/npm/:_authToken=${FLINT_TOKEN}
# Yarn classic only:
always-auth=true
```

```yaml
# .yarnrc.yml, for Yarn Berry
npmRegistryServer: "https://registry.example/npm/npm/"
npmAuthToken: "${FLINT_TOKEN}"
npmAlwaysAuth: true
```

```toml
# bunfig.toml, if Bun is configured there rather than in .npmrc
[install]
registry = { url = "https://registry.example/npm/npm/", token = "$FLINT_TOKEN" }
```

Installing needs `read` on the virtual repository only; publishing, dist-tags, deprecating, and unpublishing need their roles on the `publishTo` member, `npm-local` here.
Lockfiles written through flint name only flint's tarball URLs, where the client records URLs at all; pnpm and Yarn Berry record none for registry packages, and fetch them from the registry configured.
npm also installs a lockfile written against registry.npmjs.org through flint, since it fetches the tarballs such a lockfile names from the registry configured (its `replace-registry-host` setting).

### Logging in with npm login

`npm login` asks for a user name and password and stores a token for the registry in `~/.npmrc`:

```sh
npm login --registry https://registry.example/npm/npm-local/
```

npm first tries the web login, which flint does not offer, and then falls back to sending the user name and password, as `npm login --auth-type=legacy` does at once.
flint checks the password and answers with a new [login token](auth.md#tokens-from-client-login-commands): it carries the user's repository permissions, is named after npm and the time of login, such as `npm login 2026-05-01T12:00:00Z`, expires after `auth.loginTokenTTL` (default 90 days), and is listed and revoked like any other token.
A user without a password creates a token through the admin API instead.
`npm whoami` names the user a token belongs to.

`npm adduser` sends the same request, so it logs in an existing user; users are created through the admin API only.

## Publishing

`npm publish`, `pnpm publish`, `yarn publish`, `yarn npm publish`, and `bun publish` publish a version to a hosted repository.
flint checks each publish:

- The package name follows npm's rules for new packages: at most 214 characters, lowercase letters, digits, `-`, `.`, and `_`, not starting with `.` or `_`, with an optional `@scope/`.
- The version is a semantic version (SemVer 2.0.0), such as `1.2.0` or `2.0.0-beta.1`. npm strips build metadata (`+build`) before it publishes, and flint refuses a version that has it.
- The publish carries one version and its tarball. flint computes the tarball's sha512 and sha1 digests itself, which it serves as `dist.integrity` and `dist.shasum`; a publish whose declared digests or length disagree with the tarball is refused with `400`.
- The dist-tags it sets point at the version published.

The tarball is streamed from the request into storage as it arrives, so a publish of any size is never held in memory; the rest of the request is bounded at 32 MiB.

**A version is never published twice.**
Publishing a version that is already published fails with `409 Conflict`, and so does publishing one that was unpublished: lockfiles pin each version's integrity, and other content under a version that was once installed would break them.
Publish a new version instead.
Of concurrent publishes of one version, exactly one succeeds.

The version's manifest is stored as it was published, except for the fields flint sets when it serves it (`dist` and `deprecated`) and the readme, which is kept with the package and served in the packument: a publish that creates or moves `latest` replaces the package's readme with its version's, so publishing an older line with `--tag` leaves it as it is. Moving `latest` with `npm dist-tag` or unpublishing the latest version also leaves the readme as it was.
`_npmUser` records the user who published the version, which `npm view` and `npm search` show.

A repository owns a package from its first publish, and keeps owning it after every version is unpublished.

### Provenance

A provenance bundle published with `npm publish --provenance` is stored with the version, and served at the URL the version's `dist.attestations` names, `/npm/<repository>/-/npm/v1/attestations/<name>@<version>`.
flint does not verify it; `npm audit signatures` does.
flint does not sign packuments, so a hosted repository's `/-/npm/v1/keys` lists no keys.

## Dist-tags

Dist-tags point at versions; `latest` is the version installed when no version is asked for.

```sh
npm dist-tag add @acme/widget@1.2.0 stable
npm dist-tag ls @acme/widget
npm dist-tag rm @acme/widget stable
```

- Publishing points the tag given with `--tag`, by default `latest`, at the version, and `latest` too when the package has none, so a package always has `latest` while it has a version.
- Setting and removing a tag needs `write`. A tag cannot point at a version that is not published, and only removing it, never setting it to an empty version, takes it away.
- `latest` cannot be removed, only pointed at another version.
- A tag is a letter followed by letters, digits, `.`, `_`, and `-`, and must not be a version or a version range, such as `v1`, `v1.2.x`, or `x`, which npm would read as one; `v1-maint` is a tag.

## Deprecating

```sh
npm deprecate @acme/widget@1.1.0 "use 1.2.0 or later"
npm deprecate @acme/widget@1.1.0 ""    # undeprecate
```

npm deprecates by sending back the packument it read, with the messages changed.
flint accepts the edit when it changes nothing but deprecation messages; any other change to a version is refused with `400`, and an edit of a packument that changed since the client read it is refused with `409`.
Deprecating needs `write`.
Installers warn about deprecated versions and avoid them when another version satisfies the range.

## Unpublishing

```sh
npm unpublish @acme/widget@1.1.0       # one version
npm unpublish @acme/widget --force     # every version
```

Unpublishing needs `delete`, and there is no time limit: the role decides.
An unpublished version disappears from the packument at once and its tarball is no longer served; [garbage collection](garbage-collection.md) later reclaims its disk space, unless another repository stores the same bytes.
The version can never be published again.
Dist-tags pointing at it are removed, and if `latest` pointed at it, `latest` moves to the highest version left, preferring releases to pre-releases.
Unpublishing every version leaves the package without a packument, but the repository keeps owning its name, and new versions can be published later.

## Proxy repositories

A proxy repository caches one upstream registry, such as `https://registry.npmjs.org/`:

- **Packuments** are fetched from the upstream and stored in the cache exactly as the upstream sent them, the full form and the abbreviated form installers ask for each in its own right. A cached packument is served for `revalidateAfter` (default 5 minutes) after the upstream last confirmed it; after that, flint asks the upstream again, sending its `ETag` and `Last-Modified` so an unchanged packument costs a `304`, also on the first request after a restart. A packument flint cannot read, or of another package, never replaces the cached one. Packuments of hundreds of megabytes are streamed into the cache, and streamed to clients while their URLs are rewritten.
- **URLs point at flint.** When flint serves a packument, each version's `dist.tarball`, and its `dist.attestations.url`, point below the proxy repository's registry URL, so lockfiles record flint's URLs and clients send flint's credentials with tarball requests. Everything else is served as the upstream sent it, including `dist.integrity` and `dist.signatures`, which sign a version's name, version, and integrity, not its URLs, so `npm audit signatures` verifies proxied packages with the upstream's keys, which flint serves at `/-/npm/v1/keys`.
- **Tarballs** never change, so once cached they are served forever without asking the upstream. Each is checked against its version's `dist.integrity` (sha512), or for versions too old to have one, `dist.shasum` (sha1): a tarball that does not match is refused with `502`, or cut off before its last byte if part of it was already sent, and never enters the cache, and a version with neither is refused with `502`. A proxy repository serves only what its upstream sent it: a tarball is fetched even if flint stores the same bytes for another repository. Concurrent requests for the same tarball share one upstream fetch, and the first client streams it as it arrives.
- **Versions the upstream removes** leave the packument, which follows the upstream, but their cached tarballs keep being served by their URLs, so installs from lockfiles keep working. flint never removes a cached tarball on its own.
- **When the upstream is unreachable**, because of network errors, timeouts, `5xx` errors, or `429` rate limiting, cached packuments and tarballs keep being served, and flint treats the upstream as offline for 30 seconds. A package that was never cached is answered with `503`.
- **When the upstream answers that a package is not found**, with `404`, `410`, or `451`, or denies access, flint answers `404` too, even if it has the package cached; its cached tarballs stay cached.
- **Disk space and size limits** work as for [OCI proxy repositories](configuration.md#proxy-repositories): under `proxyCache.minFreeSpace`, new tarballs are passed through without being cached, still checked; with `proxy.sizeLimit`, the least recently downloaded tarballs are evicted to stay within the limit. Packuments do not count against the limit.
- **Search** is passed through to the upstream and not cached. **`npm audit`** is passed through to the upstream too, unless `npm.forwardAudit` is `false`. The upstream's signing keys and each version's attestations are cached like packuments.
- **Credentials.** With `proxy.passwordFile`, flint sends credentials with every request to the host of `proxy.url`, as npm does, since a registry may answer a request without them `404`: with `proxy.username`, HTTP basic credentials, and without one, the file's token as `Authorization: Bearer`, as an `_authToken` would be sent. They are never sent to another host.
- **Read-only.** Publishes, dist-tag changes, deprecations, and unpublishes are refused with `405`.
- **Fetch policy.** flint fetches only from the host of `proxy.url`, which for registry.npmjs.org also serves its tarballs, and the hosts in `proxy.allowHosts`: a registry whose packuments name tarballs on another host needs that host there. See [the fetch policy](configuration.md#upstream-fetch-policy).

## Virtual repositories

A virtual repository serves one registry over an ordered list of hosted and proxy members:

- **Packuments merge by version.** A package's packument lists the versions of every member that has the package. Where members have the same version, the first member's manifest is served, and the version's tarball is downloaded from that member. The dist-tags come from the first member that has the package, and each version's publish time from the member that supplied it. Tarball URLs point below the virtual repository's registry URL.
- **Merge limit.** Merging holds the members' packuments in memory, so it is bounded by `npm.mergeLimit`, 32MiB by default: when the packuments of the members that have a package are larger than that together, flint does not merge them and serves the first such member's packument alone, as that member serves it, a large one streamed. That member's versions are the only ones listed, though the others' tarballs can still be downloaded by URL; filters and dependency-confusion protection still decide which members are asked. Each fallback is logged with a warning and counted in `flint_npm_virtual_merge_fallbacks_total`. Concurrent requests for the same merge share one build, and merges are cached in memory with the other rendered packuments.
- **Filters.** A member with `include` or `exclude` patterns is consulted only for the package names they admit, compared exactly, so a scope pattern such as `@acme/*` covers a whole scope. Exclude your internal scopes from the registry.npmjs.org member, as in `{"name": "npmjs", "exclude": ["@acme/*"]}`: dependency-confusion protection covers a name only once a hosted member owns it, and the filter also covers internal names you have not published yet, or whose hosted repository is unreachable.
- **Dependency-confusion protection**, on by default: once a hosted member owns a package name, that name's upstream versions are never served through the virtual repository, not even versions the hosted member lacks, and the proxy members are not even asked about it. A hosted repository owns a name from its first publish, and keeps it after every version is unpublished. So a package someone publishes on registry.npmjs.org under the name of a first-party package, even at a higher version, can never be installed in its place. Set `virtual.dependencyConfusionProtection` to `false` to merge every member for every name.
- A member that fails, such as a proxy whose upstream is unreachable and has the package uncached, is left out with a warning in the log, counted in `flint_virtual_member_skips_total`, so one unreachable upstream does not take the whole registry down. The request fails only if no member could answer.
- **Publishing, dist-tags, deprecating, and unpublishing** go to the hosted member that `virtual.publishTo` names, so one `registry=` line serves both installing and publishing; they need the permissions the same change to that member needs. npm reads a package before it edits it, and through the virtual repository it reads the `publishTo` member's packument, which the edit is made to. A change to a package whose name that member's filters do not admit is refused with `403`, naming the member and the filter, and nothing changes. Without `publishTo`, changes are refused with `405`, naming the hosted members to publish to instead.
- **`npm audit`** is forwarded to each proxy member's upstream with only the package names that member may serve and that no hosted member owns, so the names of internal packages never leave the network through `npm audit`; the members' answers merge, the first member's advisories of a package winning. `npm.forwardAudit` set to `false` on the virtual repository forwards nothing.
- **Search** lists the hosted members' matches first, then the proxy members' answers, each package once, as the members' filters and dependency-confusion protection admit it. The signing keys are those of the proxy members' upstreams, and a version's attestations are those of the member that supplies the version.

Installing through a virtual repository needs the `read` role on the virtual repository, or its `anonymousPull`; the members' own permissions are not consulted.

## Search, audit, and ping

- `npm search` through a hosted repository finds the packages whose names contain every word of the query, names that start with the first word first. Qualifiers such as `keywords:` are ignored. Through a proxy repository, the upstream answers; through a virtual one, see [above](#virtual-repositories).
- `npm audit` asks flint for advisories about the versions it installed. flint knows of none for hosted packages, so a hosted repository reports no vulnerabilities; proxy and virtual repositories ask their upstreams, as described above.
- `npm ping` needs no credentials.

## Not supported

- The web login, and two-factor authentication: the `npm-otp` header is ignored.
- `npm access`, `npm owner`, `npm team`, `npm org`, `npm token`, `npm star`, and `npm hook`. Manage tokens and permissions through flint's [admin API](auth.md#admin-api) and [configuration](configuration.md#permissions).
- Staged publishing, and the CouchDB replication endpoints (`/-/all`, `_changes`).
- Trusted publishing over OIDC, which comes with flint's trusted publishing after v1.
- The audit endpoint npm used before the bulk advisories (`/-/npm/v1/security/audits/quick`), which current npm falls back to only when the bulk one fails.
