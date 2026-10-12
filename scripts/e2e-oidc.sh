#!/usr/bin/env bash
# e2e-oidc.sh signs in to flint through a real OpenID Connect provider, Dex
# with its mock connector, with curl playing the browser: it follows the
# authorization code flow from flint's sign-in page to Dex and back, checks
# the user flint created and the groups it synced, creates an API token
# with the session, and uses the token with docker, curl, and the Docker
# token endpoint. It checks that the session does not work on registry
# endpoints, that a cross-site request with it is refused, that a later
# sign-in resyncs groups changed in flint, and that signing out and
# deleting the user end the session and the token. It fails on the first
# mismatch.
#
# Usage: E2E_ADMIN_PASSWORD=<password> scripts/e2e-oidc.sh <host:port> <provider> <oci-repo> <generic-repo>
#   <provider>      an auth.oidc provider for Dex's mock connector, whose
#                   user is kilgore@kilgore.trout in group "authors", with
#                   the "groups" scope, importGroups, and groupMappings
#                   mapping "authors" to "ci"
#   <oci-repo>      a hosted OCI repository on which group "ci" has write
#   <generic-repo>  a hosted generic files repository on which group "ci"
#                   has write
#   E2E_ADMIN_PASSWORD is the password of the administrator "admin".
#   E2E_NO_DOCKER, if set, skips the docker push and pull, for a docker
#   daemon that cannot reach <host:port>, as in a VM.
# Requires curl, jq, and docker on PATH.
set -euo pipefail

if [ $# -ne 4 ] || [ -z "${E2E_ADMIN_PASSWORD:-}" ]; then
	echo "usage: E2E_ADMIN_PASSWORD=<password> $0 <host:port> <provider> <oci-repo> <generic-repo>" >&2
	exit 2
fi
reg=$1
provider=$2
oci=$3
generic=$4
base=http://$reg
admin=(-u "admin:$E2E_ADMIN_PASSWORD")
user=kilgore@kilgore.trout
work=$(mktemp -d)
trap 'rm -rf "$work"; docker logout "$reg" >/dev/null 2>&1 || true' EXIT
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
jar=$work/cookies
# status prints the HTTP status of a request.
status() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }
# sign_in follows the whole sign-in through the provider with the cookie
# jar, as a browser does, and prints the page it ends on.
sign_in() { curl -fsS -L -c "$jar" -b "$jar" "$base/auth/oidc/$provider/login"; }

step "the sign-in page offers the provider"
curl -fsS "$base/auth/login" | grep -q "href=\"oidc/$provider/login\"" || fail "no sign-in link for $provider"

step "sign in through the provider"
page=$(sign_in)
grep -q "Signed in as <strong>$user</strong>" <<<"$page" || fail "sign-in ended on: $page"
grep -q flint_session "$jar" || fail "no session cookie"

step "the user was created with synced groups"
who=$(curl -fsS -b "$jar" "$base/api/v1/user")
[ "$(jq -r .name <<<"$who")" = "$user" ] || fail "whoami: $who"
[ "$(jq -c .groups <<<"$who")" = '["authors","ci"]' ] || fail "groups: $who"
record=$(curl -fsS "${admin[@]}" "$base/api/v1/users/$user")
[ "$(jq -r .oidc.provider <<<"$record")" = "$provider" ] && [ "$(jq -r .oidc.subject <<<"$record")" != null ] &&
	[ "$(jq -r .password <<<"$record")" = false ] || fail "user record: $record"

step "the session creates an API token, but not from another site"
[ "$(status -b "$jar" -H 'Sec-Fetch-Site: cross-site' "$base/api/v1/tokens" -d '{"name": "x"}')" = 403 ] ||
	fail "a cross-site request with the session was not refused"
token=$(curl -fsS -b "$jar" "$base/api/v1/tokens" -d '{"name": "e2e", "expiresIn": "1h"}' | jq -r .token)
case $token in flint_*) ;; *) fail "no token: $token" ;; esac

step "registry and package endpoints do not take the session"
[ "$(status -b "$jar" "$base/v2/$oci/oidc-e2e/tags/list")" = 401 ] || fail "registry accepted the session"
[ "$(status -b "$jar" "$base/generic/$generic/")" = 401 ] || fail "generic files accepted the session"

step "the token works with curl, the token endpoint, and docker"
echo "hello from $user" >"$work/hello.txt"
curl -fsS -u "$user:$token" -T "$work/hello.txt" "$base/generic/$generic/oidc/hello.txt" >/dev/null
curl -fsS -H "Authorization: Bearer $token" "$base/generic/$generic/oidc/hello.txt" | cmp - "$work/hello.txt" ||
	fail "downloaded file differs"
claims=$(curl -fsS -u "__token__:$token" "$base/auth/token?service=flint&scope=repository:$oci/oidc-e2e:pull,push" |
	jq -r .token | cut -d. -f2 | tr '_-' '/+')
while [ $((${#claims} % 4)) -ne 0 ]; do claims="$claims="; done
access=$(base64 -d <<<"$claims" | jq -c '.access[0].actions')
[ "$access" = '["pull","push"]' ] || fail "token endpoint granted $access"
if [ -z "${E2E_NO_DOCKER:-}" ]; then
	printf 'FROM scratch\nCOPY hello.txt /hello.txt\n' >"$work/Dockerfile"
	image=$reg/$oci/oidc-e2e:1
	docker build -q -t "$image" "$work" >/dev/null
	docker login "$reg" -u "$user" --password-stdin <<<"$token" >/dev/null
	docker push -q "$image" >/dev/null
	docker rmi -f "$image" >/dev/null
	docker pull -q "$image" >/dev/null
	docker rmi -f "$image" >/dev/null
fi

step "a later sign-in resyncs groups changed in flint"
curl -fsS "${admin[@]}" -X PATCH "$base/api/v1/users/$user" -d '{"groups": []}' >/dev/null
[ "$(curl -fsS -b "$jar" "$base/api/v1/user" | jq -c .groups)" = '[]' ] || fail "groups were not cleared"
[ "$(status -u "$user:$token" -T "$work/hello.txt" "$base/generic/$generic/oidc/again-$$.txt")" = 403 ] ||
	fail "the token kept a removed group's role"
sign_in >/dev/null
[ "$(curl -fsS -b "$jar" "$base/api/v1/user" | jq -c .groups)" = '["authors","ci"]' ] || fail "groups were not resynced"
[ "$(status -u "$user:$token" -T "$work/hello.txt" "$base/generic/$generic/oidc/again-$$.txt")" = 201 ] ||
	fail "the token did not regain the group's role"

step "signing out ends the session"
cp "$jar" "$work/old-cookies"
curl -fsS -o /dev/null -b "$jar" -c "$jar" -X POST "$base/auth/logout"
[ "$(status -b "$work/old-cookies" "$base/api/v1/user")" = 401 ] || fail "the session outlived signing out"

step "deleting the user ends its token"
sign_in >/dev/null
curl -fsS "${admin[@]}" -X DELETE "$base/api/v1/users/$user"
[ "$(status -b "$jar" "$base/api/v1/user")" = 401 ] || fail "the session outlived the user"
[ "$(status -H "Authorization: Bearer $token" "$base/generic/$generic/oidc/hello.txt")" = 401 ] ||
	fail "the token outlived the user"

echo "OIDC end to end: ok"
