# Authentication and the admin API

flint authenticates clients against local users, users who sign in through OpenID Connect providers, and API tokens, and authorizes them with per-repository roles.
Users, their groups, API tokens, and sign-in sessions are runtime data in the metadata store, managed through the admin API below.
Permission grants, and which repositories allow anonymous pulls, are declared in the [configuration](configuration.md#permissions).

## Users and the first administrator

A user has a name, an optional password, a global `admin` flag, and any number of groups.
User and group names are 1 to 64 lowercase letters, digits, `.`, `_`, `-`, or `@`, starting with a letter or digit.
Passwords are 8 to 1024 bytes and are stored only as PBKDF2-HMAC-SHA256 hashes, with a random per-user salt and 600,000 iterations recorded with each hash.

The first administrator comes from the configuration:

```json
"auth": {
  "bootstrapAdmin": {
    "username": "admin",
    "passwordFile": "/etc/flint/admin/password"
  }
}
```

At startup, if no administrator exists, flint creates `username` (default `admin`) as an administrator with the password in `passwordFile`, ignoring one trailing newline.
The file is read only then, so in Kubernetes it can be a mounted Secret (the Helm chart's `bootstrapAdmin` values do this; see [Helm](helm.md#first-administrator)), and it may be removed after the first start; once an administrator exists, the file is ignored and changing it does not reset the password.
If a user with that name exists but is not an administrator, flint refuses to start rather than take the account over.
Without `bootstrapAdmin` and without an administrator, flint starts and logs a warning.

flint never logs passwords, tokens, or hashes.
The audit trail of the metadata store records who changed which user or token, never the values.

## Signing in

Browsers sign in on the sign-in page at `/auth/login`, with a user name and password or through an [OIDC provider](#oidc-sign-in), and get a sign-in session.
The session is a cookie, `flint_session`, holding a random secret of which flint stores only the SHA-256 hash; it is `HttpOnly`, `SameSite=Lax`, and `Secure` when the browser reached flint over HTTPS.
It lasts `auth.sessionTTL` (default 12 hours; see [configuration](configuration.md#fields)), and signing out (`POST /auth/logout`) ends it at once, as deleting the user does.
Setting a user's password, on the [web UI](ui.md#your-account)'s account page or through the [admin API](#users), ends the user's sessions, except the one that set it: changing your own password signs out your other browsers, and an administrator setting another user's password signs that user out everywhere.
A user keeps at most 50 sessions; signing in again beyond that ends the oldest.

A session authenticates the [admin API](#admin-api) and the [web UI](ui.md), never the registry or package endpoints: Docker, PyPI, npm, and every other package client use [API tokens](#api-tokens).
A session counts as having signed in, as a password does, so a signed-in user can create API tokens for package clients, which is how a user who signs in only through an OIDC provider gets one.
Once signed in, the sign-in page shows who is signed in and can create an API token; the [web UI](ui.md)'s account page lists, creates, and revokes them.

A request with a session that changes anything must come from flint's own pages: a browser request from another origin, as the `Sec-Fetch-Site` or `Origin` header shows, gets `403`.
Requests that are not from a browser carry neither header and are not affected, but they do not have the cookie unless given it.

Every sign-in through `/auth/login` and an OIDC provider takes an optional `return` parameter, a path on flint to go to afterwards; anything else, such as another site's URL, goes to the sign-in page instead.
Starting and ending a session are recorded in the audit log as `auth.session.create` and `auth.session.delete`.

### OIDC sign-in

Each provider configured in [`auth.oidc`](configuration.md#oidc-providers) gets a "Sign in with" button on the sign-in page.
flint uses the authorization code flow with PKCE (`S256`), a state, and a nonce, and verifies the ID token itself: its signature, with a key from the provider's published key set and an algorithm from the allowed list (never `none` or an HMAC algorithm), and its issuer, audience, authorized party, expiry, issue time, not-before time, and nonce, allowing one minute of clock difference.
The provider's discovery document and keys are cached for an hour; a token signed with a key flint has not seen makes it fetch the keys again, at most every 30 seconds, so the provider can rotate its keys.
A sign-in in progress is held only in a short-lived cookie in the browser that started it, so it is bound to that browser; it works once, since the callback clears the cookie, and expires after 10 minutes. flint keeps no state for it.
The cookie holds the sign-in's nonce, PKCE verifier, return path, and expiry, sealed with AES-256-GCM under a key generated on first start with a provider and kept in `<dataDir>/auth/oidc-state.key`, readable only by flint's user, so it can be neither read nor changed, and it opens only at the callback of the provider and state it was made for.
Sign-ins in progress survive a restart; deleting the key file invalidates them at the next start, and their users sign in again.

**Users.** A user who signs in through a provider is identified by the provider's issuer and the user's subject (`sub`), never by email or name.
On the first sign-in, flint creates the user, named after the provider's `usernameClaim` (by default the verified email), lowercased, unless an administrator [assigned the identity's email](#assigning-users-by-email) to a user beforehand.
If a user of that name already exists, local or from another identity, the sign-in is refused rather than take it over; an administrator resolves the conflict, for example by deleting the other user.
Later sign-ins find the user by issuer and subject, so a changed email or name at the provider does not change the flint user.
Users from a provider have no password and cannot be given one, and password sign-in never works for them; local users never sign in through a provider.
Deleting such a user deletes its tokens and sessions, and the identity's next sign-in creates the user anew.
The user's creation, its link to an assigned user, and each change a sign-in makes are recorded in the audit log as `auth.oidc.user.create`, `auth.oidc.user.link`, and `auth.oidc.user.sync`.

**Groups.** For providers other than [Google](#google-sign-in), at every sign-in the user's flint groups are replaced by those the provider's groups claim maps to through `groupMappings`, plus, with `importGroups`, the provider's groups themselves.
With `adminGroups`, the global `admin` flag is set at every sign-in too: on for members of those groups, off for everyone else, except that the last administrator is never demoted.
Groups set through the admin API for such a user last until the next sign-in.
The groups claim must be in the ID token; some providers send it only when asked for a scope such as `groups`, which `scopes` then lists.

**Removing access.** Group changes at the provider take effect at the user's next sign-in through it.
Until then, the user's sessions and API tokens keep the groups and permissions of the last sign-in.
To cut a user off at once, delete the user in flint, which ends its sessions and revokes its tokens, or revoke its tokens; disabling the user at the provider only stops new sign-ins.

**Restricting who signs in.** `allowedDomains`, `allowedEmails`, and, for Google, `hostedDomains` restrict sign-in to users with a verified email in a domain, a verified email from a list, or a Google Workspace domain: with any of them set, a user must match at least one.
`allowedGroups` additionally requires membership of a group at the provider.

### Google sign-in

Google is built in: a provider of `"type": "google"` in [`auth.oidc`](configuration.md#google) needs only an OAuth client's ID and secret, and appears on the sign-in page as "Sign in with Google".
[Configuration](configuration.md#google) describes how to create the OAuth client at Google and its redirect URI, which must be `https` on a real hostname, not an IP address.

Google signs in only users whose email it says is verified, and the user's flint name is that email, lowercased.
`hostedDomains` admits only accounts of your Google Workspace domains, by the ID token's `hd` claim, and `allowedEmails` admits individual accounts, such as a contractor's Gmail address, alongside them or alone.
flint accepts Google's ID tokens with the issuer `https://accounts.google.com` or, as Google sometimes sends it, `accounts.google.com`.

Google's ID tokens carry no groups, so the groups and the `admin` flag of a user who signs in through Google are flint's own: they start empty, are set through the [admin API](#users) (`PATCH /api/v1/users/{name}` and the [group endpoints](#groups)), and are kept at every sign-in.
To give a user groups before its first sign-in, [assign](#assigning-users-by-email) its email.
Removing a Google user's access works as for any user from a provider: delete the user, or remove its groups, which takes effect for its sessions and tokens at once.

### Assigning users by email

An administrator can create a user for an identity at a provider ahead of its first sign-in, by the identity's verified email, with its name, groups, and `admin` flag:

```sh
curl -u admin https://registry.example/api/v1/users -d '{
  "name": "alice",
  "groups": ["ci", "team-a"],
  "oidc": {"provider": "google", "email": "alice@example.com"}
}'
```

The first sign-in through that provider whose email is verified and equal to the assigned one, compared lowercased, signs in as that user instead of creating one, and links the user to the identity's issuer and subject; from then on the user is matched by them like any other, and the email no longer matters.
An email can be assigned to one user per provider issuer, and a user assigned an email has no password.
Assignment applies only to an identity's first sign-in: an identity that already signed in has its user, which an administrator deletes first to assign the email anew.
With a provider that syncs groups, the linked user's groups are replaced by the provider's at sign-in as usual; with Google, they are kept.

## Permissions

| Role | Allows |
| --- | --- |
| `read` | pull |
| `write` | pull, push |
| `delete` | pull, push, delete |
| `admin` | everything on the repository |

Roles are granted in the configuration to users and groups, on repository names or patterns such as `team-a-*`.
A user's role on a repository is the highest one any matching grant gives the user directly or through a group.
A user with the global `admin` flag has the `admin` role on every repository and may use the admin API.
A repository with `anonymousPull` lets everyone pull from it, signed in or not; it is off by default.
An anonymous client may pull from such a repository directly, without a token, as a containerd registry mirror does.

[Proxy repositories](configuration.md#proxy-repositories) use the same roles: pulling, which may fetch from the upstream, needs `read`.
They are read-only, so pushes and deletes are refused whatever the role.
Pulling through a [virtual repository](configuration.md#virtual-repository-settings) needs `read` on the virtual repository; its members' permissions are not consulted.

For PyPI repositories, installing is pulling and publishing is pushing; yanking and deleting files need `delete`.
For Cargo repositories, building is pulling, and publishing and yanking are pushing, which need `write`; deleting a version needs `delete`.
For npm repositories, installing is pulling; publishing, changing dist-tags, and deprecating are pushing; unpublishing needs `delete`. Through a virtual repository, each change needs its role on the virtual repository's `publishTo` member, where it is made.

For generic files repositories, downloading and listing are pulling, uploading a file is pushing, and deleting one needs `delete`; in a repository with `generic.allowOverwrite`, replacing a file with different content needs only `write`.

Permissions apply to flint repositories: the first component of an image path, or the repository of a PyPI, generic files, Cargo, or npm URL.
A grant on `docker-local` covers `host/docker-local/team/app`, one on `pypi-local` covers `host/pypi/pypi-local/...`, one on `files` covers `host/generic/files/...`, one on `cargo-local` covers `host/cargo/cargo-local/...`, and one on `npm-local` covers `host/npm/npm-local/...`.

## API tokens

An API token is a random secret of the form `flint_<id>_<secret>`, shown once when it is created.
flint stores only its SHA-256 hash.
A token belongs to its owner and has a name, an optional expiry, and scopes: a list of repository names or patterns, each with a role.

A token never carries more than its owner has: on each use, the owner's current role on a repository is capped by the highest role the token's scopes give it.
A token created without scopes carries all of its owner's repository permissions.
A token uses its owner's global `admin` role only if it was created with `"admin": true`, which only an administrator can do.
Deleting the owner, demoting an administrator, or revoking or expiring the token takes effect on the next request.

Wherever a password is accepted, an API token is accepted too, in any of these forms:

| Form | Sent by |
| --- | --- |
| HTTP basic credentials with the owner's user name and the token | Docker and most clients with a user name and password |
| HTTP basic credentials with the user name `__token__` and the token | PyPI clients |
| `Authorization: Bearer <token>` | npm and other clients configured with a token |
| `Authorization: <token>`, with no scheme | Cargo and others that send the token alone; `Bearer` may be added |
| `X-NuGet-ApiKey: <token>` | NuGet pushes and deletes |

flint tells an API token in a `Bearer` header apart from a token from the [Docker token endpoint](#docker-clients) by its `flint_` prefix.
`X-NuGet-ApiKey` is used only when the request has no `Authorization` header, so a client that sends source credentials and a placeholder key authenticates with the source credentials.

### Tokens from client login commands

Some package clients log in by sending a user name and password through their own protocol and expect a token back, as npm's legacy `npm login` does.
For those, flint verifies the password and answers with a new API token, which:

- is owned by the user and carries all of the user's repository permissions, but not the global `admin` role;
- is named after the client and the time of login, such as `npm login 2026-05-01T12:00:00Z`;
- expires after `auth.loginTokenTTL` (default 90 days; see [configuration](configuration.md#fields));
- is listed and revoked like any other token.

An API token is not accepted in place of the password there, so a token cannot mint another.
Each package format's documentation says whether its clients log in this way; [npm's](npm.md#logging-in-with-npm-login) do.

## PyPI clients

pip, uv, and twine send HTTP basic credentials with their requests: an API token with the user name `__token__`, or a user name and its password or token.
A request without valid credentials that needs them gets `401` with `WWW-Authenticate: Basic realm="flint"`, and one whose credentials lack the permission gets `403`.
Tokens from the Docker token endpoint are not accepted.
[PyPI](pypi.md#configuring-clients) shows how to configure each client.

## Cargo clients

Cargo sends an API token as the `Authorization` header as it is, which flint accepts, with or without a `Bearer` scheme.
A request without valid credentials that needs them gets `401` with `WWW-Authenticate: Cargo login_url="..."`, naming the [web UI](ui.md#your-account)'s account page under flint's [public URL](configuration.md#public-url), or else the scheme and host the client used; one whose credentials lack the permission gets `403`.
Errors carry Cargo's `{"errors": [{"detail": "..."}]}`, whose detail Cargo shows.
A repository's `config.json` says `"auth-required": true` unless it has `anonymousPull`, which makes Cargo send its token with every request, not only to publish; that needs Cargo 1.74 or later, with `credential-provider = "cargo:token"`.
`cargo login` only stores a token Cargo is given, so create one first, on the [web UI](ui.md#your-account)'s account page, which `cargo login` points to, or with the [admin API](#api-tokens).
Crates have no owners in flint: `cargo owner` fails, and who may publish, yank, and delete is decided by permission grants.
[Cargo](cargo.md#configuring-cargo) shows how to configure it.

## npm clients

npm, pnpm, Yarn Berry, and Bun send an API token from their configuration as `Authorization: Bearer <token>`; `_auth` in `.npmrc` and Yarn's `npmAuthIdent` send HTTP basic credentials, which work too.
A request without valid credentials that needs them gets `401` without a `WWW-Authenticate` header, with the reason as a JSON error, after which npm tells the user to log in; one whose credentials lack the permission gets `403`.
`npm login` sends a user name and password and gets a newly minted [login token](#tokens-from-client-login-commands), which it stores in `.npmrc`, and `npm whoami` names the token's owner.
Tokens from the Docker token endpoint are not accepted.
[npm](npm.md#configuring-clients) shows how to configure each client.

## Maven and Gradle clients

Maven and Gradle send HTTP basic credentials: a user name and its password, or a user name and one of the user's API tokens; Gradle can also send a token as `Authorization: Bearer <token>`.
Both wait for a challenge before they send credentials for a download, so a request without valid credentials that needs them gets `401` with `WWW-Authenticate: Basic realm="flint"`, never `404`, and one whose credentials lack the permission gets `403`.
Maven sends credentials with uploads right away.
Tokens from the Docker token endpoint are not accepted.
[Maven](maven.md#configuring-clients) shows how to configure each client.

## Docker clients

Registry requests use the Docker token authentication flow:

1. A request without valid credentials gets `401` with a challenge naming the token endpoint and the scope it needs:
   `WWW-Authenticate: Bearer realm="https://registry.example/auth/token",service="flint",scope="repository:docker-local/app:pull,push"`.
   The realm uses the scheme and host the client addressed, through trusted proxies as configured.
2. The client requests a token from `GET /auth/token?service=flint&scope=...`, with a password or an API token, in any of the [forms above](#api-tokens), or none for anonymous access.
   containerd's OAuth 2 password grant, `POST /auth/token` with `grant_type=password`, works the same way.
3. flint answers with a JSON Web Token, signed with Ed25519, that grants each requested action the client's role allows and leaves out the rest:
   `{"token": "...", "access_token": "...", "token_type": "Bearer", "expires_in": 300, "issued_at": "..."}`.
   Tokens live for 5 minutes.
4. The client retries with `Authorization: Bearer <token>`.
   A token that lacks an action the request needs gets `401` with `error="insufficient_scope"`; an expired or invalid one gets `error="invalid_token"`.

The registry's base endpoint, `GET /v2/`, challenges any request without credentials, which is how `docker login` finds the token endpoint; any valid token passes it, an anonymous one included.
The catalog, `GET /v2/_catalog`, needs a token with the scope `registry:catalog:*`, which every client gets, and lists only the repositories the client may pull from.

Wrong credentials at the token endpoint get `401`, which is what makes `docker login` fail.
Each request also checks the subject's current permissions, so a token for a deleted user or a revoked API token stops working before it expires.

The signing key is generated on first start and kept in `<dataDir>/auth/token-signing.key`, readable only by flint's user.
Tokens stay valid across restarts; deleting the file invalidates every issued token at the next start.

Registry clients may also send a password or an API token, in any of the [forms above](#api-tokens), on every request instead of using the token endpoint.
Without permission, such a request gets `403 DENIED`.
flint remembers a verified password for 5 minutes, keyed by a hash of the credentials and the stored password hash, so clients that send a password with every request do not pay for PBKDF2 each time.

```sh
docker login registry.example -u ci-bot              # password or API token
echo "$TOKEN" | crane auth login registry.example -u ci-bot --password-stdin
```

## Package clients

Every route family accepts the same credentials, and answers a request without valid credentials with `401` in the style its clients expect:

| Style | Challenge | Used by |
| --- | --- | --- |
| Docker | `WWW-Authenticate: Bearer realm=...,service="flint",scope=...` | The registry API at `/v2/`, as described above |
| Basic | `WWW-Authenticate: Basic realm="flint"` | Clients that wait for a challenge before they send credentials, such as Maven, Gradle, and wget, and Helm chart, generic files, and Go repositories |
| Cargo | `WWW-Authenticate: Cargo login_url="..."` | Cargo, which shows the user where to get a token |
| Plain | none | npm, which then tells the user to log in |

A client that presents a password or an API token without the permission a request needs gets `403`.
Tokens from the Docker token endpoint are accepted only by the registry API, for which they are issued.
Each package format's documentation says which style it uses.

### Signed download URLs

Some clients never send credentials for downloads named in the metadata they fetch.
For those, a format puts signed URLs in the metadata it serves an authenticated client.
A signed URL carries an expiry, 10 minutes after it was issued unless the format chooses otherwise, and the client that requested the metadata: its user and, if it used an API token, the token.
Its signature is an HMAC-SHA256 over the URL's path, the expiry, and that client.
It works without credentials until it expires, and only while that client may still read the repository: deleting the user, revoking or expiring the token, or removing the permission ends it at once.
A signed URL allows downloads only.

The signing key is generated on first start and kept in `<dataDir>/auth/url-signing.key`, readable only by flint's user.
Deleting the file invalidates every signed URL at the next start.

### Virtual repositories

A virtual repository serves a merged view of its member repositories.
Reading through it needs `read` on the virtual repository only, since the view is what its administrator composed: a client needs no role on the members.
Publishing through it needs `write`, and deleting needs `delete`, on the member it publishes to (`publishTo`); a virtual repository without one refuses publishes.
For an OCI virtual repository, the role that counts is the one on the same image name in `publishTo`: pushing `docker/team/app` through a virtual repository `docker` that publishes to `docker-local` needs `write` on `docker-local/team/app`, and `read` on `docker/team/app` for the pulls a push makes.
Docker clients ask the [token endpoint](#docker-clients) for a token for the name they push, `repository:docker/team/app:pull,push`, and flint grants the push for the role on `docker-local/team/app`; a token for `docker-local/team/app` does not cover the virtual repository's name.

### Generic files repositories

[Generic files repositories](generic.md#credentials) at `/generic/<repository>/` use the Basic style.
curl and wget send a password or an API token as HTTP basic credentials (`curl -u`, `wget --user --password`, or a `.netrc` file), and scripts may send an API token as `Authorization: Bearer <token>` instead.
curl sends basic credentials with the first request; wget waits for the challenge.

### Go repositories

[Go repositories](go.md#credentials) use the Basic style.
The go command sends credentials only over HTTPS: a password or an API token from `.netrc`, or, from Go 1.24 on, the headers a `GOAUTH` command prints, such as `Authorization: Bearer <token>`.
Downloading needs the `read` role, or the repository's `anonymousPull`; a virtual repository needs it on the virtual repository only.

### Helm chart repositories

The [classic Helm chart repository view](helm-repository.md#access) at `/helm/<repository>/` uses the Basic style: it takes a password or an API token, as `helm repo add --username --password` sends them, and needs the same permission as a pull.

## Admin API

The admin API serves JSON under `/api/v1/`.
Every request authenticates with a password or an API token, in any of the [forms above](#api-tokens), or with a [sign-in session](#signing-in)'s cookie; tokens from the Docker token endpoint are not accepted.
Without valid credentials the answer is `401` with `WWW-Authenticate: Basic realm="flint"`, except for a request with a session cookie whose session has ended, which gets `401` without the challenge so a browser does not ask for a password.
Errors are `{"error": "message"}` with status `400` (invalid request, such as setting a password for a user from an OIDC provider), `403` (not allowed, or a cross-origin request with a session), `404` (no such user, token, repository, project, release, or file, or backups are not configured), `405` (yanking or deleting in a repository that is not hosted), `409` (the user exists, the email is already assigned to another user, the change would remove the last administrator, a backup is already running, or a garbage collection is in progress), `413` (the body is over 64 KiB), or `503` (the server is shutting down).
Request bodies are strict JSON: unknown fields are errors.

| Request | Who | Does |
| --- | --- | --- |
| `GET /api/v1/user` | anyone | Describe the authenticated client. |
| `GET /api/v1/users` | admin | List users. |
| `POST /api/v1/users` | admin, signed in | Create a user. |
| `GET /api/v1/users/{name}` | admin, or the user | Show a user. |
| `PATCH /api/v1/users/{name}` | admin, signed in | Set the `admin` flag or the groups. |
| `DELETE /api/v1/users/{name}` | admin | Delete a user and the user's tokens, sessions, and OIDC link or assigned email. |
| `PUT /api/v1/users/{name}/password` | admin or the user, signed in | Set a password. |
| `GET /api/v1/groups` | admin | List groups and their members. |
| `PUT /api/v1/groups/{group}/members/{name}` | admin, signed in | Add a user to a group. |
| `DELETE /api/v1/groups/{group}/members/{name}` | admin, signed in | Remove a user from a group. |
| `GET /api/v1/tokens` | anyone | List one's own tokens. |
| `POST /api/v1/tokens` | anyone, signed in | Create a token for oneself. |
| `DELETE /api/v1/tokens/{id}` | the owner, or admin | Revoke a token. |
| `GET /api/v1/backup` | admin | Report the running backup and the last ones; see [backups](backup.md#the-admin-api). |
| `POST /api/v1/backup` | admin | Start a backup. |
| `GET /api/v1/gc` | admin | Show the garbage collection in progress, the last one, and the schedule. |
| `POST /api/v1/gc` | admin | Start a garbage collection: `202` with its report so far, or `409` if one is in progress. The optional body `{"dryRun": true}` asks for a dry run. |
| `PUT, DELETE /api/v1/pypi/{repository}/projects/{project}/releases/{version}/yank` | `delete` role on the repository | Yank or unyank a release of a hosted PyPI repository; see [PyPI](pypi.md#yanking-and-deleting). |
| `DELETE /api/v1/pypi/{repository}/projects/{project}/releases/{version}` | `delete` role on the repository | Delete a release's files. |
| `DELETE /api/v1/pypi/{repository}/projects/{project}/files/{filename}` | `delete` role on the repository | Delete one file. |
| `DELETE /api/v1/cargo/{repository}/crates/{crate}/{version}` | `delete` role on the repository | Delete a version of a crate in a hosted Cargo repository; see [Cargo](cargo.md#deleting-versions). |
| `GET /api/v1/audit` | admin | Query the [audit log](operations.md#audit-log). |
| `GET /api/v1/audit/export` | admin | Export the audit log as JSON lines. |

[Garbage collection](garbage-collection.md) describes the garbage-collection reports, and `flint gc` calls the `/api/v1/gc` endpoints.

"admin" means the global admin role: an administrator authenticated with a password or a session, or with a token created with `"admin": true`.
"Signed in" means authenticated with a password or a [sign-in session](#signing-in), not a token.
Creating a token, creating or updating a user or its groups, and setting a password need the client to be signed in, even with a token created with `"admin": true`, so a leaked token cannot mint longer-lived tokens or take over its owner's or anyone else's account.
The last administrator cannot be deleted or demoted.

### Users

```sh
curl -u admin https://registry.example/api/v1/users -d '{
  "name": "alice",
  "password": "correct-horse-battery",
  "admin": false,
  "groups": ["ci", "team-a"]
}'
```

`password` may be omitted to create a user who cannot log in with a password.
Instead of a password, `"oidc": {"provider": "google", "email": "alice@example.com"}` assigns the user to the identity at a configured provider with that verified email; see [assigning users by email](#assigning-users-by-email).
The response, here `201 Created`, and every other user response has this form:

```json
{
  "name": "alice",
  "admin": false,
  "groups": ["ci", "team-a"],
  "created": "2026-05-01T12:00:00Z",
  "password": true
}
```

`password` reports whether password login is enabled.
A user who signs in through an [OIDC provider](#oidc-sign-in) also has `"oidc": {"provider": "corp", "issuer": "https://sso.example.com/realms/corp", "subject": "..."}`, the identity it signs in with; a user assigned by email that has not signed in yet has `"email"` there instead of `"subject"`.
`PATCH /api/v1/users/{name}` takes `{"admin": true}`, `{"groups": ["ci"]}`, or both; a field left out is unchanged.
`PUT /api/v1/users/{name}/password` takes `{"password": "..."}` and returns `204`; it ends the user's [sign-in sessions](#signing-in), except the one of the request that set it.

### Groups

Groups exist through their members: adding a user to a group creates it, and a group without members is listed only while a configured grant names it.
`GET /api/v1/groups` returns `[{"name": "ci", "members": ["alice"]}]`.
The membership endpoints return `204` and are idempotent.

### Tokens

```sh
curl -u alice https://registry.example/api/v1/tokens -d '{
  "name": "ci pull",
  "expiresIn": "720h",
  "scopes": [{"repositories": ["docker-local", "team-a-*"], "role": "read"}]
}'
```

| Field | Meaning |
| --- | --- |
| `name` | Required: 1 to 128 bytes, to recognize the token by. |
| `expiresIn` | A positive duration such as `"720h"`. Without it, the token does not expire. |
| `scopes` | Repository names or patterns and a role each. Default: all of the owner's repository permissions. |
| `admin` | Let the token use its owner's global admin role. Default `false`; administrators only. |

The response, `201 Created`, is the only one that includes the token:

```json
{
  "id": "k3vqpmzt5j2xw7ab",
  "name": "ci pull",
  "owner": "alice",
  "created": "2026-05-01T12:00:00Z",
  "expires": "2026-05-31T12:00:00Z",
  "expired": false,
  "admin": false,
  "scopes": [{"repositories": ["docker-local", "team-a-*"], "role": "read"}],
  "token": "flint_k3vqpmzt5j2xw7ab_..."
}
```

`GET /api/v1/tokens` lists the caller's tokens, oldest first, without the `token` field.
`DELETE /api/v1/tokens/{id}` revokes a token and returns `204`; another user's token is `404` unless the caller is an administrator.

## Metrics

| Metric | Meaning |
| --- | --- |
| `flint_auth_attempts_total{method, result}` | Credential checks by `method` (`password`, `token`, `jwt`, `url` for a signed URL, `session` for a sign-in session's cookie, or `oidc` for a sign-in through an OIDC provider) and `result` (`success`, `failure`). |
| `flint_auth_tokens_issued_total` | Bearer tokens issued by the token endpoint. |

Requests by an authenticated client carry `user` (and `token_id`, for an API token) in their log line.
