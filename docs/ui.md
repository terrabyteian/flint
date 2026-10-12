# Web UI

flint serves a small web UI at `/ui/`, and redirects its root, `/`, there.
It shows the repositories you may read and what is in them, tells you how to configure each client for them, and lets you change your password and manage your own [API tokens](auth.md#api-tokens).
Administration stays in the [admin API](auth.md) and the [configuration](configuration.md); administrators get a read-only status page.

The pages are rendered on the server from templates built into the binary, with one stylesheet, its icons drawn inline, and a little hand-written JavaScript for conveniences such as copy buttons; everything works without it.
The layout adapts to narrow screens, follows the system's light or dark theme, and can be used with the keyboard alone.
The sign-in page has the same look.
Under a [public URL](configuration.md#public-url) with a path, such as `https://tools.example/flint`, the UI is at `https://tools.example/flint/ui/`, and its links, forms, and redirects stay under that path.

## Signing in

The UI has no sign-in of its own: **Sign in** takes you to flint's [sign-in page](auth.md#signing-in), `/auth/login`, where you sign in with your user name and password or through an [OIDC provider](auth.md#oidc-sign-in), and which brings you back to the page you came from.
The sign-in session, its `flint_session` cookie, how long it lasts (`auth.sessionTTL`), and how it ends are as [authentication](auth.md#signing-in) describes; **Sign out** ends it.
Changing your password on the account page keeps the session you changed it from and ends your others.
Every page checks the session's user as it is at that moment, so a changed admin flag or group membership applies at once.

Without signing in, you see the repositories that allow anonymous pulls.

## Browsing

The repository list shows every repository you may read, with its format and type, and what a proxy repository caches or a virtual repository merges.
It can be filtered by name, format, or type, and narrowed to one format with the format buttons above it.
A repository you may not read is not shown; its pages are not found, or, before you sign in, ask you to sign in.
Reading a virtual repository needs `read` on it only, as its clients need; its members are linked only if you may read them too.

| Repository | What the UI shows |
| --- | --- |
| OCI, hosted or proxy | Images; each image's tags, with the platforms of the index a tag names and whether its manifest is signed or has an SBOM, and its manifests, including untagged ones, grouped: each index with its platform manifests, and every manifest with the signatures, SBOMs, attestations, and other referrers that name it as their subject or that cosign stored under its tag scheme (`sha256-<digest>.sig`, `.att`, `.sbom`); a summary of the image's tags, manifests, platforms, signed tags (cosign's tag-scheme tags are not counted as tagged releases), and last push; each manifest's media type, artifact type (not shown for a plain image, whose artifact type is its config's media type), size, config and layers with their sizes, an index's platforms, annotations, and referrers. A proxy repository shows what it cached, and an index's platform manifests it did not cache are marked so. |
| PyPI, hosted | Projects, their releases newest first, and each release's files, with yanked releases marked. |
| PyPI, proxy | The files the repository cached, by project and version. |
| npm, hosted | Packages, their dist-tags, and their versions with their tarballs; deprecated versions and those with provenance are marked. |
| Maven, hosted | Artifacts as `groupId:artifactId`, their versions, snapshots marked, and each version's files. |
| Cargo, hosted | Crates, their versions with their `.crate` files, yanked versions marked. |
| Generic files, hosted | The repository's directories and files. |
| Proxy repositories of npm, Maven, Cargo, Go, and generic files | The files the repository cached, as a tree of their paths. |
| Virtual repositories | Their members in order, with their filters, the `publishTo` member, and whether dependency-confusion protection is on. Browse the members for their contents. |

Lists show 100 entries at a time and can be filtered by name.
File names link to the routes clients download them from, which authenticate as they do for clients: a repository without anonymous pulls asks the browser for a user name and password or API token where its clients get a `Basic` challenge.

Every repository page has copyable client setup for its format: `docker login`, pull, and push commands, and for a repository with the [Helm view](helm-repository.md), `helm push` and `helm repo add`; the index URL for pip, `pip.conf`, and uv's `pyproject.toml`, and `twine upload`; `.npmrc` and `.yarnrc.yml`; Maven's `settings.xml` and `pom.xml` and Gradle's `settings.gradle.kts`; `GOPROXY` and `.netrc`; Cargo's `.cargo/config.toml`; and `curl` downloads and uploads.
Publishing commands appear for hosted repositories and for virtual repositories with a `publishTo` member.
Package and image pages add the command that installs or pulls that package or image; an image's page also signs in to the registry and, for a hosted repository, tags and pushes a local build of the image, and a manifest's page pulls it by digest.
The URLs are built from flint's [public URL](configuration.md#public-url), or else the address your browser used.

## Your account

The account page, `/ui/account`, shows your user, your groups, and whether you are an administrator, and lists your API tokens: what each may do, which reads "All of your permissions" for a token that carries all of your repository permissions, and when it expires, marking a token that expires within 14 days and one that expired.

- **Create a token** with a name, an expiry of 7, 30, 90, or 365 days or none, and either all of your repository permissions or one role on repositories you name, by name or pattern such as `team-a-*`.
  Administrators may also give a token the global admin role.
  The token is shown once, right after it is created; flint keeps only its hash.
  A sign-in session counts as signing in, so you can create tokens from the UI whether you signed in with a password or through a provider, but an API token can never create another.
- **Revoke a token**, which takes effect at once.
  The UI revokes only your own tokens; administrators revoke others' through the [admin API](auth.md#api-tokens).
- **Change your password**, which needs your current one. Users who sign in through an OIDC provider have no password here.

`cargo login` sends you to this page to create a token.

## The status page

Administrators get a read-only status page, `/ui/admin`, with:

- [garbage collection](garbage-collection.md): the run in progress, the last run's result and what it deleted, the grace period, and the schedule;
- [backups](backup.md): the backup directory, the backup in progress, and the last complete and last attempted backups;
- the free space of the data directory's filesystem, and whether proxy repositories stopped caching because it is below `proxyCache.minFreeSpace`;
- the session and login token lifetimes;
- every configured repository with its settings, and the permission grants.

## Security

- Every page is sent with a strict `Content-Security-Policy` that allows only the UI's own scripts, styles, and images, forms that post back to the UI, and no framing; the pages hold no inline script or style.
- Every form that changes anything is a `POST`, which is refused when the browser says it comes from another origin, by `Sec-Fetch-Site` or `Origin`, as every request with a sign-in session is; the session cookie is also `SameSite=Lax`.
- Pages are sent with `Cache-Control: no-store`, so a page that shows a new token is never cached, and with `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: same-origin`.
- After signing in, the sign-in page returns only to a path on flint.
- Static assets are served from `/ui/static/` with their content's hash in the URL, so browsers cache them until flint is upgraded.

## Endpoints

| Endpoint | Meaning |
| --- | --- |
| `GET /` | Redirects to `/ui/`. |
| `GET /ui/` | The repository list. |
| `GET /ui/repositories/<repository>` | A repository's contents and client setup. |
| `GET /ui/repositories/<repository>/packages/<package>` | A package's versions and files. |
| `GET /ui/repositories/<repository>/images/<image>` | An OCI image's tags and manifests. |
| `GET /ui/repositories/<repository>/manifests/<digest>/<image>` | A manifest, its layers or platforms, and its referrers. |
| `GET /ui/account`, `POST /ui/account/password`, `POST /ui/account/tokens`, `POST /ui/account/tokens/<id>/revoke` | Your account, password, and API tokens. |
| `GET /ui/admin` | The status page, for administrators. |
| `GET /ui/static/<file>` | Stylesheet, script, and icon. |

## Not supported

- Administration beyond your own account: users, groups, permissions, and repositories are managed through the admin API and the configuration.
- Merged views of virtual repositories, which would mean asking every proxy member's upstream; browse the members instead.
- Deleting, yanking, or retagging content; use the clients or the admin API.
