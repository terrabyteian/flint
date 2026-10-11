# Authentication and the admin API

flint authenticates clients against local users and API tokens, and authorizes them with per-repository roles.
Users, their groups, and API tokens are runtime data in the metadata store, managed through the admin API below.
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

Permissions apply to flint repositories: the first component of an image path, or the repository of a PyPI URL.
A grant on `docker-local` covers `host/docker-local/team/app`, and one on `pypi-local` covers `host/pypi/pypi-local/...`.

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
Each package format's documentation says whether its clients log in this way.

## PyPI clients

pip, uv, and twine send HTTP basic credentials with their requests: an API token with the user name `__token__`, or a user name and its password or token.
A request without valid credentials that needs them gets `401` with `WWW-Authenticate: Basic realm="flint"`, and one whose credentials lack the permission gets `403`.
Tokens from the Docker token endpoint are not accepted.
[PyPI](pypi.md#configuring-clients) shows how to configure each client.

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
| Basic | `WWW-Authenticate: Basic realm="flint"` | Clients that wait for a challenge before they send credentials, such as Maven and Gradle, and Helm chart repositories |
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

### Helm chart repositories

The [classic Helm chart repository view](helm-repository.md#access) at `/helm/<repository>/` uses the Basic style: it takes a password or an API token, as `helm repo add --username --password` sends them, and needs the same permission as a pull.

## Admin API

The admin API serves JSON under `/api/v1/`.
Every request authenticates with a password or an API token, in any of the [forms above](#api-tokens); tokens from the Docker token endpoint are not accepted.
Without valid credentials the answer is `401` with `WWW-Authenticate: Basic realm="flint"`.
Errors are `{"error": "message"}` with status `400` (invalid request), `403` (not allowed), `404` (no such user, token, repository, project, release, or file, or backups are not configured), `405` (yanking or deleting in a repository that is not hosted), `409` (the user exists, the change would remove the last administrator, a backup is already running, or a garbage collection is in progress), `413` (the body is over 64 KiB), or `503` (the server is shutting down).
Request bodies are strict JSON: unknown fields are errors.

| Request | Who | Does |
| --- | --- | --- |
| `GET /api/v1/user` | anyone | Describe the authenticated client. |
| `GET /api/v1/users` | admin | List users. |
| `POST /api/v1/users` | admin, with a password | Create a user. |
| `GET /api/v1/users/{name}` | admin, or the user | Show a user. |
| `PATCH /api/v1/users/{name}` | admin, with a password | Set the `admin` flag or the groups. |
| `DELETE /api/v1/users/{name}` | admin | Delete a user and the user's tokens. |
| `PUT /api/v1/users/{name}/password` | admin or the user, with a password | Set a password. |
| `GET /api/v1/groups` | admin | List groups and their members. |
| `PUT /api/v1/groups/{group}/members/{name}` | admin, with a password | Add a user to a group. |
| `DELETE /api/v1/groups/{group}/members/{name}` | admin, with a password | Remove a user from a group. |
| `GET /api/v1/tokens` | anyone | List one's own tokens. |
| `POST /api/v1/tokens` | anyone, with a password | Create a token for oneself. |
| `DELETE /api/v1/tokens/{id}` | the owner, or admin | Revoke a token. |
| `GET /api/v1/backup` | admin | Report the running backup and the last ones; see [backups](backup.md#the-admin-api). |
| `POST /api/v1/backup` | admin | Start a backup. |
| `GET /api/v1/gc` | admin | Show the garbage collection in progress, the last one, and the schedule. |
| `POST /api/v1/gc` | admin | Start a garbage collection: `202` with its report so far, or `409` if one is in progress. The optional body `{"dryRun": true}` asks for a dry run. |
| `PUT, DELETE /api/v1/pypi/{repository}/projects/{project}/releases/{version}/yank` | `delete` role on the repository | Yank or unyank a release of a hosted PyPI repository; see [PyPI](pypi.md#yanking-and-deleting). |
| `DELETE /api/v1/pypi/{repository}/projects/{project}/releases/{version}` | `delete` role on the repository | Delete a release's files. |
| `DELETE /api/v1/pypi/{repository}/projects/{project}/files/{filename}` | `delete` role on the repository | Delete one file. |

[Garbage collection](garbage-collection.md) describes the garbage-collection reports, and `flint gc` calls the `/api/v1/gc` endpoints.

"admin" means the global admin role: an administrator authenticated with a password, or with a token created with `"admin": true`.
Creating a token, creating or updating a user or its groups, and setting a password need a password, even for a token created with `"admin": true`, so a leaked token cannot mint longer-lived tokens or take over its owner's or anyone else's account.
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
`PATCH /api/v1/users/{name}` takes `{"admin": true}`, `{"groups": ["ci"]}`, or both; a field left out is unchanged.
`PUT /api/v1/users/{name}/password` takes `{"password": "..."}` and returns `204`.

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
| `flint_auth_attempts_total{method, result}` | Credential checks by `method` (`password`, `token`, `jwt`, or `url` for a signed URL) and `result` (`success`, `failure`). |
| `flint_auth_tokens_issued_total` | Bearer tokens issued by the token endpoint. |

Requests by an authenticated client carry `user` (and `token_id`, for an API token) in their log line.
