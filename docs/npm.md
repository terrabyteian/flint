# npm

flint serves npm packages from hosted npm repositories, which hold first-party packages: npm, pnpm, Yarn (classic and Berry), and Bun install from them, and publish to them.

[Configuration](configuration.md#repositories) describes how to declare them:

```json
"repositories": [
  {"name": "npm-local", "format": "npm", "type": "hosted"}
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

## Configuring clients

The examples use `https://registry.example` for flint and the repository `npm-local`.

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
flint does not sign packuments, so `/-/npm/v1/keys` lists no keys.

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

## Search, audit, and ping

- `npm search` finds the packages whose names contain every word of the query, names that start with the first word first. Qualifiers such as `keywords:` are ignored.
- `npm audit` asks flint for advisories about the versions it installed. flint knows of none for hosted packages, so it reports no vulnerabilities.
- `npm ping` needs no credentials.

## Not supported

- The web login, and two-factor authentication: the `npm-otp` header is ignored.
- `npm access`, `npm owner`, `npm team`, `npm org`, `npm token`, `npm star`, and `npm hook`. Manage tokens and permissions through flint's [admin API](auth.md#admin-api) and [configuration](configuration.md#permissions).
- Staged publishing, and the CouchDB replication endpoints (`/-/all`, `_changes`).
- Trusted publishing over OIDC, which comes with flint's trusted publishing after v1.
- Proxy repositories of an upstream registry such as registry.npmjs.org, and virtual repositories merging several, which come next.
