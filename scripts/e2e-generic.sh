#!/usr/bin/env bash
# e2e-generic.sh drives flint's generic files repositories with curl and
# wget: it uploads, downloads, and lists files in a hosted repository, and
# checks HEAD, ranges, digest-checked uploads, immutability, overwrites in an
# allowOverwrite repository, and that a deleted file's path is never reused.
# It downloads flint's own release binaries through a proxy of its GitHub
# releases, which redirect to another host, and compares them with their
# published checksums, and uses a virtual repository of the hosted and proxy
# repositories. A second run, after flint has been restarted with its
# upstreams unreachable, downloads the same files again to prove that cached
# content keeps being served offline. It fails on the first mismatch.
#
# Usage: E2E_STATE_DIR=<dir> E2E_USERNAME=<user> E2E_TOKEN=<token> \
#          scripts/e2e-generic.sh online|offline <host:port> <hosted> <scratch> <releases> <revalidated> <virtual>
#   <hosted>       a hosted repository
#   <scratch>      a hosted repository with generic.allowOverwrite
#   <releases>     a proxy repository of
#                  https://github.com/terrabyteian/flint/releases/download/
#                  with generic.immutable and anonymousPull, allowing the
#                  hosts GitHub redirects release downloads to
#   <revalidated>  a proxy repository of the same URL without
#                  generic.immutable, with anonymousPull
#   <virtual>      a virtual repository of <hosted> and <releases>, in that
#                  order, with publishTo <hosted>
#   E2E_USERNAME and E2E_TOKEN are a user and an API token with the delete
#   role on <hosted> and <scratch> and read on <virtual>.
#   E2E_STATE_DIR keeps what the online run downloaded for the offline run.
# Requires curl, wget, jq, and sha256sum on PATH.
set -euo pipefail

if [ $# -ne 7 ] || [ -z "${E2E_STATE_DIR:-}" ] || [ -z "${E2E_USERNAME:-}" ] || [ -z "${E2E_TOKEN:-}" ] ||
	{ [ "$1" != online ] && [ "$1" != offline ]; }; then
	echo "usage: E2E_STATE_DIR=<dir> E2E_USERNAME=<user> E2E_TOKEN=<token> $0 online|offline <host:port> <hosted> <scratch> <releases> <revalidated> <virtual>" >&2
	exit 2
fi
mode=$1
reg=$2
hosted=$3
scratch=$4
releases=$5
revalidated=$6
virtual=$7
state=$E2E_STATE_DIR
mkdir -p "$state"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

base=http://$reg/generic
user=$E2E_USERNAME
token=$E2E_TOKEN
# A release of flint, whose files never change, and the binary of it
# downloaded through the proxies; another binary no step downloads online.
release=v0.3.0
binary=flint-linux-amd64
uncached=flint-darwin-arm64

# status prints the HTTP status of a request.
status() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }
# auth_status is status with the API token as basic credentials.
auth_status() { status -u "$user:$token" "$@"; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

# metric prints the value of a flint metric sample, or 0.
metric() {
	curl -fsS "http://$reg/metrics" | awk -v s="$1" '$1 == s { print $2; found = 1 } END { if (!found) print 0 }'
}

# check_release checks a release file downloaded to $1 against the
# checksum the release's SHA256SUMS, at $2, lists for file $3.
check_release() {
	want=$(awk -v f="$3" '$2 == f || $2 == "*" f { print $1 }' "$2")
	[ -n "$want" ] || fail "SHA256SUMS lists no $3"
	[ "$(sha "$1")" = "$want" ] || fail "$3: sha256 $(sha "$1"), want $want"
}

if [ "$mode" = online ]; then
	head -c 300000 /dev/urandom >"$work/app.bin"
	printf 'hello from flint\n' >"$work/hello.txt"

	step "upload with curl -T and download with curl"
	resp=$(curl -fsS -u "$user:$token" -T "$work/app.bin" "$base/$hosted/tools/1.0/app.bin")
	[ "$(jq -r .sha256 <<<"$resp")" = "$(sha "$work/app.bin")" ] || fail "upload response $resp"
	curl -fsS -u "$user:$token" -o "$work/got.bin" "$base/$hosted/tools/1.0/app.bin"
	cmp "$work/app.bin" "$work/got.bin" || fail "curl download differs"
	cp "$work/app.bin" "$state/app.bin"

	step "HEAD and a range request with curl"
	head=$(curl -fsS -I -u "$user:$token" "$base/$hosted/tools/1.0/app.bin" | tr -d '\r')
	grep -qi "^content-length: 300000$" <<<"$head" || fail "HEAD: $head"
	grep -qi "^etag: \"sha256:$(sha "$work/app.bin")\"$" <<<"$head" || fail "HEAD has no sha256 ETag: $head"
	curl -fsS -u "$user:$token" -r 1000-1999 -o "$work/range.bin" "$base/$hosted/tools/1.0/app.bin"
	dd if="$work/app.bin" of="$work/want-range.bin" bs=1000 skip=1 count=1 2>/dev/null
	cmp "$work/range.bin" "$work/want-range.bin" || fail "the range differs"

	step "download with wget, which waits for the Basic challenge"
	wget -q --user="$user" --password="$token" -O "$work/wget.bin" "$base/$hosted/tools/1.0/app.bin"
	cmp "$work/app.bin" "$work/wget.bin" || fail "wget download differs"

	step "upload with wget and a bearer token"
	wget -q --method=PUT --body-file="$work/hello.txt" --header="Authorization: Bearer $token" \
		-O "$work/wget-put.json" "$base/$hosted/docs/hello.txt"
	# wget sends the form type, which flint replaces with the type of the
	# file's extension.
	[ "$(jq -r .contentType "$work/wget-put.json")" != application/x-www-form-urlencoded ] ||
		fail "wget upload: $(cat "$work/wget-put.json")"
	[ "$(curl -fsS -u "$user:$token" "$base/$hosted/docs/hello.txt")" = "hello from flint" ] || fail "wget upload differs"

	step "digest-checked uploads"
	good=$(openssl dgst -sha256 -binary "$work/hello.txt" | base64)
	bad=$(printf 'other' | openssl dgst -sha256 -binary | base64)
	got=$(auth_status -T "$work/hello.txt" -H "Content-Digest: sha-256=:$bad:" "$base/$hosted/docs/bad.txt")
	[ "$got" = 400 ] || fail "upload with a wrong Content-Digest: $got, want 400"
	got=$(auth_status "$base/$hosted/docs/bad.txt")
	[ "$got" = 404 ] || fail "a refused upload is stored: $got"
	got=$(auth_status -T "$work/hello.txt" -H "X-Checksum-Sha256: $(printf other | sha256sum | cut -d' ' -f1)" "$base/$hosted/docs/bad.txt")
	[ "$got" = 400 ] || fail "upload with a wrong X-Checksum-Sha256: $got, want 400"
	got=$(auth_status -T "$work/hello.txt" -H "Content-Digest: sha-256=:$good:" "$base/$hosted/docs/checked.txt")
	[ "$got" = 201 ] || fail "upload with a matching Content-Digest: $got, want 201"

	step "immutable files: identical re-upload, overwrite refused"
	got=$(auth_status -T "$work/app.bin" "$base/$hosted/tools/1.0/app.bin")
	[ "$got" = 200 ] || fail "identical re-upload: $got, want 200"
	got=$(auth_status -T "$work/hello.txt" "$base/$hosted/tools/1.0/app.bin")
	[ "$got" = 409 ] || fail "overwrite of an immutable file: $got, want 409"

	step "overwrite and delete in $scratch"
	got=$(auth_status -T "$work/hello.txt" "$base/$scratch/latest/app")
	[ "$got" = 201 ] || fail "scratch upload: $got"
	got=$(auth_status -T "$work/app.bin" "$base/$scratch/latest/app")
	[ "$got" = 200 ] || fail "scratch overwrite: $got, want 200"
	curl -fsS -u "$user:$token" -o "$work/latest.bin" "$base/$scratch/latest/app"
	cmp "$work/app.bin" "$work/latest.bin" || fail "the overwritten file differs"
	got=$(auth_status -X DELETE "$base/$scratch/latest/app")
	[ "$got" = 204 ] || fail "scratch delete: $got"
	got=$(auth_status -T "$work/hello.txt" "$base/$scratch/latest/app")
	[ "$got" = 201 ] || fail "scratch upload after delete: $got, want 201"

	step "delete leaves a tombstone"
	got=$(auth_status -T "$work/hello.txt" "$base/$hosted/tmp/once.txt")
	[ "$got" = 201 ] || fail "upload: $got"
	got=$(auth_status -X DELETE "$base/$hosted/tmp/once.txt")
	[ "$got" = 204 ] || fail "delete: $got"
	got=$(auth_status "$base/$hosted/tmp/once.txt")
	[ "$got" = 404 ] || fail "download after delete: $got, want 404"
	got=$(auth_status -T "$work/hello.txt" "$base/$hosted/tmp/once.txt")
	[ "$got" = 409 ] || fail "re-upload after delete: $got, want 409"

	step "listings"
	names=$(curl -fsS -u "$user:$token" -H 'Accept: application/json' "$base/$hosted/" | jq -r '[.entries[].name] | join(" ")')
	[ "$names" = "docs/ tools/" ] || fail "root listing: $names"
	entry=$(curl -fsS -u "$user:$token" -H 'Accept: application/json' "$base/$hosted/tools/1.0/" | jq -c '.entries[0]')
	[ "$(jq -r .sha256 <<<"$entry")" = "$(sha "$work/app.bin")" ] && [ "$(jq -r .size <<<"$entry")" = 300000 ] ||
		fail "file entry: $entry"
	curl -fsS -u "$user:$token" "$base/$hosted/docs/" | grep -q '<a href="hello.txt">' || fail "the HTML listing has no link"
	# wget follows the HTML listings to mirror a directory.
	(cd "$work" && wget -q -r -np -nH --cut-dirs=3 -R 'index.html*' --user="$user" --password="$token" "$base/$hosted/tools/")
	cmp "$work/app.bin" "$work/1.0/app.bin" || fail "the mirrored file differs"

	step "release files through $releases, which redirects to another host"
	curl -fsS -o "$state/SHA256SUMS" "$base/$releases/$release/SHA256SUMS"
	curl -fsS -o "$work/$binary" "$base/$releases/$release/$binary"
	check_release "$work/$binary" "$state/SHA256SUMS" "$binary"
	wget -q -O "$work/wget-$binary" "$base/$releases/$release/$binary"
	check_release "$work/wget-$binary" "$state/SHA256SUMS" "$binary"
	# The file is cached once its fetch finishes, just after the first
	# client received it.
	hit='flint_proxy_requests_total{repository="'"$releases"'",result="hit"}'
	for _ in $(seq 50); do
		curl -fsS -o /dev/null -I "$base/$releases/$release/$binary"
		[ "$(metric "$hit")" -ge 1 ] && break
		sleep 0.2
	done
	[ "$(metric "$hit")" -ge 1 ] || fail "$binary is not served from the cache"

	step "release files through $revalidated, revalidated upstream"
	curl -fsS -o "$work/SHA256SUMS" "$base/$revalidated/$release/SHA256SUMS"
	cmp "$state/SHA256SUMS" "$work/SHA256SUMS" || fail "SHA256SUMS differs"
	sleep 2 # past revalidateAfter
	curl -fsS -o "$work/SHA256SUMS" "$base/$revalidated/$release/SHA256SUMS"
	cmp "$state/SHA256SUMS" "$work/SHA256SUMS" || fail "the revalidated SHA256SUMS differs"

	step "virtual repository $virtual"
	curl -fsS -u "$user:$token" -o "$work/virtual.bin" "$base/$virtual/tools/1.0/app.bin"
	cmp "$work/app.bin" "$work/virtual.bin" || fail "a hosted file through the virtual repository differs"
	curl -fsS -u "$user:$token" -o "$work/virtual-$binary" "$base/$virtual/$release/$binary"
	check_release "$work/virtual-$binary" "$state/SHA256SUMS" "$binary"
	got=$(auth_status -T "$work/hello.txt" "$base/$virtual/published/hello.txt")
	[ "$got" = 201 ] || fail "upload through the virtual repository: $got"
	[ "$(curl -fsS -u "$user:$token" "$base/$hosted/published/hello.txt")" = "hello from flint" ] ||
		fail "the upload through the virtual repository is not in $hosted"
	echo "e2e-generic online: ok"
	exit 0
fi

step "hosted files after the restart"
curl -fsS -u "$user:$token" -o "$work/got.bin" "$base/$hosted/tools/1.0/app.bin"
cmp "$state/app.bin" "$work/got.bin" || fail "the hosted file differs"
got=$(auth_status -T "$work/got.bin" "$base/$hosted/tmp/once.txt")
[ "$got" = 409 ] || fail "re-upload of a deleted path after the restart: $got, want 409"

step "cached release files with the upstream unreachable"
curl -fsS -o "$work/$binary" "$base/$releases/$release/$binary"
check_release "$work/$binary" "$state/SHA256SUMS" "$binary"
wget -q -O "$work/wget-$binary" "$base/$releases/$release/$binary"
check_release "$work/wget-$binary" "$state/SHA256SUMS" "$binary"
curl -fsS -o "$work/SHA256SUMS" "$base/$revalidated/$release/SHA256SUMS"
cmp "$state/SHA256SUMS" "$work/SHA256SUMS" || fail "the stale SHA256SUMS differs"
curl -fsS -u "$user:$token" -o "$work/virtual-$binary" "$base/$virtual/$release/$binary"
check_release "$work/virtual-$binary" "$state/SHA256SUMS" "$binary"

step "a release file never downloaded is unavailable"
got=$(status "$base/$releases/$release/$uncached")
[ "$got" = 503 ] || fail "uncached file: $got, want 503"
echo "e2e-generic $mode: ok"
