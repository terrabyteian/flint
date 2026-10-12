# Web UI

flint serves a small web UI at `/ui/`, and redirects its root, `/`, there.
It shows the repositories you may read and what is in them, tells you how to configure each client for them, and lets you change your password and manage your own [API tokens](auth.md#api-tokens).
Administration stays in the [admin API](auth.md) and the [configuration](configuration.md); administrators get a read-only status page.

The pages are rendered on the server from templates built into the binary, with a little hand-written JavaScript for conveniences such as copy buttons and the theme switch; everything works without it.
The layout adapts to narrow screens, follows the system's light or dark theme unless you pick one, and can be used with the keyboard alone.

## Signing in

Sign in at `/ui/login` with your user name and password.
A session lasts `auth.sessionTTL`, 12 hours by default (see [configuration](configuration.md#fields)), and ends earlier when you sign out, when your password is changed, by you or an administrator, or when your user is deleted.
Changing your own password on the account page keeps the session you changed it from and ends your others.
Every page checks the session's user as it is at that moment, so a changed admin flag or group membership applies at once.

A user without a password cannot sign in here with one; sign-in providers, such as OpenID Connect, add their own buttons to the sign-in page.

Sessions are held in the `flint_session` cookie, which is `HttpOnly`, `SameSite=Lax`, scoped to `/ui/`, and `Secure` when the browser reached flint over HTTPS, directly or through a [trusted proxy](configuration.md#trusted-proxies) that says so in `X-Forwarded-Proto`.
Only the UI reads it: the admin API and the package and registry routes never accept it, so a browser session cannot be used against them.
flint stores only a hash of the session's secret, as it does for API tokens, so neither the metadata nor a [backup](backup.md) holds anything that signs anyone in.
Signing in and out are recorded in the [audit log](operations.md#audit-log).

Without signing in, you see the repositories that allow anonymous pulls.

## Browsing

The repository list shows every repository you may read, with its format and type, and what a proxy repository caches or a virtual repository merges.
A repository you may not read is not shown; its pages are not found, or, before you sign in, ask you to sign in.
Reading a virtual repository needs `read` on it only, as its clients need; its members are linked only if you may read them too.

| Repository | What the UI shows |
| --- | --- |
| OCI, hosted or proxy | Images; each image's tags and manifests, including untagged ones such as an index's platform manifests and signatures; each manifest's media and artifact type, size, config and layers with their sizes, an index's platforms, annotations, and the referrers that name it as their subject, such as signatures and attestations. A proxy repository shows what it cached. |
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
Package and image pages add the command that installs or pulls that package or image.
The URLs are built from flint's [public URL](configuration.md#public-url), or else the address your browser used.

## Your account

The account page, `/ui/account`, shows your user, groups, and when your session ends, and lists your API tokens.

- **Create a token** with a name, an expiry of 7, 30, 90, or 365 days or none, and either all of your repository permissions or one role on repositories you name, by name or pattern such as `team-a-*`.
  Administrators may also give a token the global admin role.
  The token is shown once, right after it is created; flint keeps only its hash.
  Signing in to the UI counts as signing in with your password, so you can create tokens from a session, but an API token can never create another.
- **Revoke a token**, which takes effect at once.
  The UI revokes only your own tokens; administrators revoke others' through the [admin API](auth.md#api-tokens).
- **Change your password**, which needs your current one.

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
- Every form that changes anything is a `POST` carrying a CSRF token: an HMAC keyed by the session's secret, or for the sign-in form, by the random value of the `flint_csrf` cookie.
  Requests the browser marks as coming from another site, by `Sec-Fetch-Site` or `Origin`, are refused even with a valid token.
- Pages are sent with `Cache-Control: no-store`, so a page that shows a new token is never cached, and with `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: same-origin`.
- After signing in, the UI only redirects to its own pages.
- Static assets are served from `/ui/static/` with their content's hash in the URL, so browsers cache them until flint is upgraded.

## Endpoints

| Endpoint | Meaning |
| --- | --- |
| `GET /` | Redirects to `/ui/`. |
| `GET /ui/` | The repository list. |
| `GET, POST /ui/login`, `POST /ui/logout` | Signing in and out. |
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
