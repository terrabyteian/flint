#!/usr/bin/env bash
# e2e-ui.sh drives flint's web UI with curl, as a browser would: it pushes an
# OCI image, a signature that refers to it, and a PyPI package with the
# registries' own APIs, then checks what anonymous visitors see, signs in
# with a password, browses the image, its manifest, layers, and signature,
# and the package, creates an API token and checks that it works, revokes it
# and checks that it no longer does, checks that state-changing forms are
# refused from another site, and signs out. It fails on the first mismatch.
#
# Usage: E2E_USERNAME=<user> E2E_PASSWORD=<password> \
#          scripts/e2e-ui.sh <host:port> <oci> <pypi> <public>
#   <oci>     a hosted OCI repository
#   <pypi>    a hosted PyPI repository
#   <public>  a hosted OCI repository with anonymousPull
#   E2E_USERNAME and E2E_PASSWORD are a user, and its password, with the
#   write role on <oci> and <pypi>; neither may allow anonymous pulls.
# Requires curl, tar, gzip, and sha256sum or shasum on PATH.
set -euo pipefail

if [ $# -ne 4 ] || [ -z "${E2E_USERNAME:-}" ] || [ -z "${E2E_PASSWORD:-}" ]; then
	echo "usage: E2E_USERNAME=<user> E2E_PASSWORD=<password> $0 <host:port> <oci> <pypi> <public>" >&2
	exit 2
fi
reg=$1
oci=$2
pypi=$3
public=$4
user=$E2E_USERNAME
password=$E2E_PASSWORD
base=http://$reg
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
jar=$work/cookies
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

sha() {
	if command -v sha256sum >/dev/null; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

# ui requests a UI page with the cookie jar, writing the body to
# $work/body and the headers to $work/headers, and prints the status.
ui() {
	curl -sS -b "$jar" -c "$jar" -o "$work/body" -D "$work/headers" -w '%{http_code}' "$@"
}
# page fetches a UI page that must be 200.
page() {
	code=$(ui "$base$1")
	[ "$code" = 200 ] || fail "GET $1: $code, want 200"
}
# has fails unless the last body contains $1.
has() { grep -qF -- "$1" "$work/body" || fail "$2: the page lacks \"$1\""; }
# lacks fails if the last body contains $1.
lacks() { ! grep -qF -- "$1" "$work/body" || fail "$2: the page shows \"$1\""; }
# location prints the last response's Location header.
location() { tr -d '\r' <"$work/headers" | awk 'tolower($1) == "location:" { print $2 }'; }

# push_blob uploads file $2 to OCI repository name $1 and prints its digest.
push_blob() {
	d=sha256:$(sha "$2")
	code=$(curl -sS -o /dev/null -w '%{http_code}' -u "$user:$password" -X POST \
		-H 'Content-Type: application/octet-stream' --data-binary "@$2" "$base/v2/$1/blobs/uploads/?digest=$d")
	[ "$code" = 201 ] || fail "pushing blob $2 to $1: $code"
	echo "$d"
}
# push_manifest puts manifest file $3 of media type $4 to $1 as reference $2.
push_manifest() {
	code=$(curl -sS -o /dev/null -w '%{http_code}' -u "$user:$password" -X PUT \
		-H "Content-Type: $4" --data-binary "@$3" "$base/v2/$1/manifests/$2")
	[ "$code" = 201 ] || fail "pushing manifest $3 to $1:$2: $code"
}

step "push an OCI image and a signature to $oci, and a PyPI package to $pypi"
image=$oci/e2e/app
printf '{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}' >"$work/config.json"
printf 'layer of the e2e-ui image\n' | gzip -n >"$work/layer.tar.gz"
config_digest=$(push_blob "$image" "$work/config.json")
layer_digest=$(push_blob "$image" "$work/layer.tar.gz")
cat >"$work/manifest.json" <<JSON
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
 "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"$config_digest","size":$(wc -c <"$work/config.json" | tr -d ' ')},
 "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"$layer_digest","size":$(wc -c <"$work/layer.tar.gz" | tr -d ' ')}]}
JSON
push_manifest "$image" v1 "$work/manifest.json" application/vnd.oci.image.manifest.v1+json
manifest_digest=sha256:$(sha "$work/manifest.json")
printf '{}' >"$work/empty.json"
empty_digest=$(push_blob "$image" "$work/empty.json")
printf 'e2e signature\n' >"$work/sig.txt"
sig_digest=$(push_blob "$image" "$work/sig.txt")
cat >"$work/sig.json" <<JSON
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
 "artifactType":"application/vnd.example.e2e.signature",
 "config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":"$empty_digest","size":2},
 "layers":[{"mediaType":"text/plain","digest":"$sig_digest","size":$(wc -c <"$work/sig.txt" | tr -d ' ')}],
 "subject":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"$manifest_digest","size":$(wc -c <"$work/manifest.json" | tr -d ' ')}}
JSON
signature_digest=sha256:$(sha "$work/sig.json")
push_manifest "$image" "$signature_digest" "$work/sig.json" application/vnd.oci.image.manifest.v1+json

mkdir -p "$work/sdist/e2e_ui-1.0"
printf 'Metadata-Version: 2.1\nName: e2e-ui\nVersion: 1.0\nSummary: A package the UI end-to-end test uploads\n' \
	>"$work/sdist/e2e_ui-1.0/PKG-INFO"
tar -C "$work/sdist" -czf "$work/e2e_ui-1.0.tar.gz" e2e_ui-1.0
code=$(curl -sS -o /dev/null -w '%{http_code}' -u "$user:$password" "$base/pypi/$pypi/legacy/" \
	-F ':action=file_upload' -F name=e2e-ui -F version=1.0 -F filetype=sdist -F pyversion=source \
	-F metadata_version=2.1 -F "sha256_digest=$(sha "$work/e2e_ui-1.0.tar.gz")" -F "content=@$work/e2e_ui-1.0.tar.gz")
[ "$code" = 200 ] || fail "uploading the PyPI package: $code"

step "the server's root redirects to the UI"
code=$(ui "$base/")
[ "$code" = 302 ] && [ "$(location)" = /ui/ ] || fail "GET /: $code to $(location)"

step "anonymous visitors see only $public, and are asked to sign in for the rest"
page /ui/
has "$public" "home"
lacks ">$oci<" "anonymous home"
grep -qi '^content-security-policy: default-src .none.; script-src .self.' "$work/headers" ||
	fail "the UI sends no strict Content-Security-Policy"
code=$(ui "$base/ui/repositories/$oci")
[ "$code" = 303 ] || fail "anonymous GET of $oci: $code, want 303"
case $(location) in /auth/login\?return=*) ;; *) fail "anonymous GET of $oci redirects to $(location)" ;; esac
code=$(ui "$base/ui/account")
[ "$code" = 303 ] || fail "anonymous GET of the account page: $code"
page "/ui/repositories/$public"

step "sign in"
page /ui/
grep -qF 'href="/auth/login?return=%2Fui%2F"' "$work/body" || fail "the UI has no sign-in link"
code=$(ui --data-urlencode "username=$user" --data-urlencode "password=wrong-$password" \
	-d "return=/ui/repositories/$oci" "$base/auth/login")
[ "$code" = 303 ] && case $(location) in *error=invalid*) true ;; *) false ;; esac ||
	fail "signing in with a wrong password: $code to $(location)"
code=$(ui -H 'Sec-Fetch-Site: cross-site' --data-urlencode "username=$user" --data-urlencode "password=$password" \
	"$base/auth/login")
[ "$code" = 403 ] || fail "signing in from another site: $code"
code=$(ui --data-urlencode "username=$user" --data-urlencode "password=$password" \
	-d "return=/ui/repositories/$oci" "$base/auth/login")
[ "$code" = 303 ] && [ "$(location)" = "/ui/repositories/$oci" ] || fail "signing in: $code to $(location)"
grep -qi '^set-cookie: flint_session=.*HttpOnly' "$work/headers" || fail "no HttpOnly session cookie"
grep -qi '^set-cookie: flint_session=.*SameSite=Lax' "$work/headers" || fail "the session cookie is not SameSite=Lax"

step "browse the OCI image, its manifest, layers, and signature"
page /ui/
has ">$oci<" "signed-in home"
page "/ui/repositories/$oci"
has "e2e/app" "$oci"
has "docker pull" "$oci client setup"
page "/ui/repositories/$oci/images/e2e/app"
has ">v1<" "image tags"
has "${manifest_digest:0:19}" "image manifests"
page "/ui/repositories/$oci/manifests/$manifest_digest/e2e/app"
has "${layer_digest}" "manifest layers"
has "${config_digest}" "manifest config"
has "application/vnd.example.e2e.signature" "manifest referrers"
page "/ui/repositories/$oci/manifests/$signature_digest/e2e/app"
has "${manifest_digest:0:19}" "signature subject"
code=$(ui "$base/ui/repositories/$oci/images/e2e/missing")
[ "$code" = 404 ] || fail "a missing image: $code"

step "browse the PyPI package"
page "/ui/repositories/$pypi"
has "e2e-ui" "$pypi"
has "pip install --index-url http://$reg/pypi/$pypi/simple/" "$pypi client setup"
page "/ui/repositories/$pypi/packages/e2e-ui"
has "e2e_ui-1.0.tar.gz" "package files"
has "A package the UI end-to-end test uploads" "package summary"
has "/pypi/$pypi/files/e2e-ui/e2e_ui-1.0.tar.gz" "package download link"

step "create an API token, use it, and revoke it"
page /ui/account
code=$(ui -d name=e2e-ui -d expiry=7d -d scope=selected -d "repositories=$oci" -d role=read \
	"$base/ui/account/tokens")
[ "$code" = 200 ] || fail "creating a token: $code"
grep -qi '^cache-control: no-store' "$work/headers" || fail "the page showing the token may be cached"
api_token=$(grep -o 'flint_[a-z2-7]\{16\}_[a-z2-7]\{52\}' "$work/body" | head -n1)
[ -n "$api_token" ] || fail "the new token is not shown"
has "read on $oci" "the token's scope"
code=$(curl -sS -o /dev/null -w '%{http_code}' -u "__token__:$api_token" "$base/v2/$image/manifests/v1" \
	-H 'Accept: application/vnd.oci.image.manifest.v1+json')
[ "$code" = 200 ] || fail "pulling with the new token: $code"
code=$(curl -sS -o /dev/null -w '%{http_code}' -u "__token__:$api_token" "$base/pypi/$pypi/simple/")
[ "$code" = 403 ] || fail "the token scoped to $oci reads $pypi: $code"
id=$(echo "$api_token" | cut -d_ -f2)
page /ui/account
has "$id" "token list"
code=$(ui -H 'Sec-Fetch-Site: cross-site' -X POST "$base/ui/account/tokens/$id/revoke")
[ "$code" = 403 ] || fail "revoking from another site: $code"
code=$(ui -H 'Origin: https://evil.example' -X POST "$base/ui/account/tokens/$id/revoke")
[ "$code" = 403 ] || fail "revoking with another origin: $code"
code=$(curl -sS -o /dev/null -w '%{http_code}' -u "__token__:$api_token" "$base/v2/$image/manifests/v1")
[ "$code" = 200 ] || fail "a refused revoke revoked the token: $code"
code=$(ui -H 'Sec-Fetch-Site: same-origin' -X POST "$base/ui/account/tokens/$id/revoke")
[ "$code" = 303 ] || fail "revoking: $code"
code=$(curl -sS -o /dev/null -w '%{http_code}' -u "__token__:$api_token" "$base/v2/$image/manifests/v1")
[ "$code" = 401 ] || fail "pulling with the revoked token: $code"
page /ui/account
lacks "$id" "token list after revoking"

step "sign out"
code=$(ui -d return=/ui/ "$base/auth/logout")
[ "$code" = 303 ] && [ "$(location)" = /ui/ ] || fail "signing out: $code to $(location)"
code=$(ui "$base/ui/account")
[ "$code" = 303 ] || fail "the account page after signing out: $code"

echo "PASS"
