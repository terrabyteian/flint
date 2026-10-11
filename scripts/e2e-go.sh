#!/usr/bin/env bash
# e2e-go.sh drives flint's Go repositories with the real go command: it
# builds a module with real dependencies from proxy.golang.org through a
# proxy repository, with go get at fixed versions, at @latest, and at a
# branch, and with checksum database lookups going through flint too, checks
# that go.sum matches the public checksum database, and builds the module
# again through a virtual repository of two proxy repositories. A second
# run, after flint has been restarted with its upstreams unreachable,
# downloads and builds the module again with an empty module cache through
# both repositories, and fetches the checksum database records, to prove
# that cached content keeps being served offline. It fails on the first
# mismatch.
#
# The go command sends credentials only over HTTPS, so flint must serve
# TLS; it reaches flint only, every other connection going to a proxy that
# refuses it, so nothing comes from proxy.golang.org or sum.golang.org
# directly.
#
# Usage: E2E_STATE_DIR=<dir> E2E_TOKEN=<token> SSL_CERT_FILE=<ca.pem> \
#          scripts/e2e-go.sh online|offline <host:port> <proxy> <proxy-b> <virtual>
#   <proxy>    a proxy repository of https://proxy.golang.org, which proxies
#              sum.golang.org, without anonymousPull
#   <proxy-b>  another proxy repository of https://proxy.golang.org
#   <virtual>  a virtual repository of <proxy>, excluding golang.org/x/*,
#              and <proxy-b>, in that order, without anonymousPull
#   E2E_TOKEN  an API token with read on the three repositories
#   SSL_CERT_FILE  the CA certificate flint's TLS certificate chains to
#   E2E_STATE_DIR keeps what the online run built for the offline run.
# Requires go, jq, awk, and curl on PATH.
set -euo pipefail

if [ $# -ne 5 ] || [ -z "${E2E_STATE_DIR:-}" ] || [ -z "${E2E_TOKEN:-}" ] || [ -z "${SSL_CERT_FILE:-}" ] ||
	{ [ "$1" != online ] && [ "$1" != offline ]; }; then
	echo "usage: E2E_STATE_DIR=<dir> E2E_TOKEN=<token> SSL_CERT_FILE=<ca.pem> $0 online|offline <host:port> <proxy> <proxy-b> <virtual>" >&2
	exit 2
fi
mode=$1
reg=$2
proxy=$3
proxyb=$4
virtual=$5
state=$E2E_STATE_DIR
mkdir -p "$state"
work=$(mktemp -d)
# The module cache is read-only to keep builds honest; make it removable.
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

base=https://$reg/go
host=${reg%:*}
sumdb=sum.golang.org

# The go command reads credentials from .netrc: by host and port since Go
# 1.24, by host before.
printf 'machine %s login __token__ password %s\nmachine %s login __token__ password %s\n' \
	"$reg" "$E2E_TOKEN" "$host" "$E2E_TOKEN" >"$work/netrc"
chmod 600 "$work/netrc"

# gocmd runs the go command in a fresh environment that reaches only flint,
# through repository $1, with module cache $2.
gocmd() {
	local repo=$1 cache=$2
	shift 2
	env GOPROXY="$base/$repo" GOSUMDB=$sumdb GONOSUMDB= GONOSUMCHECK= GOPRIVATE= GONOPROXY= GOINSECURE= \
		GOPATH="$work/gopath" GOMODCACHE="$cache" GOFLAGS= GOTOOLCHAIN=local GOENV=off NETRC="$work/netrc" \
		HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 NO_PROXY="$host" go "$@"
}

# status prints the HTTP status of a request to flint.
status() { curl -sS -o /dev/null -w '%{http_code}' --cacert "$SSL_CERT_FILE" "$@"; }

# metric prints the value of a flint metric sample, or 0.
metric() {
	curl -fsS --cacert "$SSL_CERT_FILE" "https://$reg/metrics" |
		awk -v s="$1" '$1 == s { print $2; found = 1 } END { if (!found) print 0 }'
}

# escape case-encodes a module path or version, as GOPROXY URLs need.
escape() {
	awk '{ out = ""; for (i = 1; i <= length($0); i++) { c = substr($0, i, 1); if (c ~ /[A-Z]/) out = out "!" tolower(c); else out = out c }; print out }' <<<"$1"
}

# Real modules: two at fixed versions, one at @latest, and one at a
# branch, which resolves to a pseudo-version.
fixed="github.com/google/uuid@v1.6.0 golang.org/x/text@v0.20.0"
latest=rsc.io/quote
branch=golang.org/x/example/hello@master
# A module version that no step downloads online, so it is never cached.
uncached=rsc.io/quote@v1.5.1

if [ "$mode" = online ]; then
	step "requests without credentials get the Basic challenge"
	[ "$(status "$base/$proxy/github.com/google/uuid/@v/list")" = 401 ] || fail "an anonymous request was not refused"
	curl -sS -o /dev/null -D "$work/headers" --cacert "$SSL_CERT_FILE" "$base/$proxy/github.com/google/uuid/@v/list"
	grep -qi '^www-authenticate: Basic realm="flint"' "$work/headers" || fail "no Basic challenge: $(cat "$work/headers")"
	[ "$(status -u "__token__:$E2E_TOKEN" -X PUT "$base/$proxy/example.com/m/@v/v1.0.0.zip")" = 405 ] ||
		fail "a PUT was not refused with 405"

	step "build a module through $proxy, with go.sum checked through flint's $sumdb proxy"
	mkdir -p "$work/mod"
	cd "$work/mod"
	cat >go.mod <<-'EOF'
		module example.com/e2e

		go 1.22
	EOF
	cat >main.go <<-'EOF'
		package main

		import (
			"fmt"

			"github.com/google/uuid"
			"golang.org/x/example/hello/reverse"
			"golang.org/x/text/cases"
			"golang.org/x/text/language"
			"rsc.io/quote"
		)

		func main() {
			id := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("flint"))
			fmt.Println(cases.Title(language.English).String(reverse.String("tnilf")), id, quote.Go())
		}
	EOF
	[ "$(status -u "__token__:$E2E_TOKEN" "$base/$proxy/sumdb/$sumdb/supported")" = 200 ] ||
		fail "$proxy does not proxy $sumdb"
	# shellcheck disable=SC2086
	gocmd "$proxy" "$work/cache-a" get $fixed
	gocmd "$proxy" "$work/cache-a" get "$latest@latest"
	gocmd "$proxy" "$work/cache-a" get "$branch"
	gocmd "$proxy" "$work/cache-a" mod tidy
	gocmd "$proxy" "$work/cache-a" build -o "$work/e2e" .
	out=$("$work/e2e")
	case $out in
	"Flint "*) ;;
	*) fail "the module built through $proxy printed $out" ;;
	esac
	grep -q $'\tgolang.org/x/example/hello v0.0.0-' go.mod || fail "the branch did not resolve to a pseudo-version: $(cat go.mod)"
	grep -q $'\trsc.io/quote v' go.mod || fail "rsc.io/quote@latest is not required: $(cat go.mod)"

	step "go.sum matches the public checksum database"
	while read -r path version hash; do
		record=$(curl -fsS "https://$sumdb/lookup/$(escape "$path")@$(escape "${version%/go.mod}")")
		grep -qxF "$path $version $hash" <<<"$record" || fail "go.sum has $path $version $hash; $sumdb has:
$record"
	done <go.sum
	cp go.mod go.sum main.go "$state/"

	step "the same module through $virtual"
	mkdir -p "$work/virtual"
	cp go.mod main.go "$work/virtual/"
	cd "$work/virtual"
	before=$(metric "flint_proxy_requests_total{repository=\"$proxyb\",result=\"fetched\"}")
	gocmd "$virtual" "$work/cache-b" mod tidy
	cmp go.sum "$state/go.sum" || fail "go.sum through $virtual differs from go.sum through $proxy"
	gocmd "$virtual" "$work/cache-b" build -o /dev/null .
	after=$(metric "flint_proxy_requests_total{repository=\"$proxyb\",result=\"fetched\"}")
	[ "$after" -gt "$before" ] || fail "golang.org/x modules did not come from $proxyb through $virtual"
	gocmd "$virtual" "$work/cache-b" list -m -versions github.com/google/uuid | grep -q ' v1.6.0' ||
		fail "the version list through $virtual lacks v1.6.0"

	step "a GOAUTH command's bearer token"
	cat >"$work/goauth" <<-EOF
		#!/bin/sh
		printf '%s\n\nAuthorization: Bearer %s\n\n' "$base/" "$E2E_TOKEN"
	EOF
	chmod +x "$work/goauth"
	NETRC=/dev/null GOAUTH="$work/goauth" gocmd "$proxy" "$work/cache-c" mod download github.com/google/uuid@v1.6.0 ||
		fail "the go command could not download with a GOAUTH bearer token"

	step "a module the upstream does not have is passed on as not found"
	code=$(status -u "__token__:$E2E_TOKEN" "$base/$proxy/example.com/flint-e2e-does-not-exist/@v/list")
	[ "$code" = 404 ] || [ "$code" = 410 ] || fail "a missing module answered $code, want 404 or 410"

	step "save the checksum database records for the offline run"
	: >"$state/lookups"
	n=0
	while read -r path version _; do
		[ "${version%/go.mod}" = "$version" ] || continue
		n=$((n + 1))
		echo "$path $version" >>"$state/lookups"
		curl -fsS --cacert "$SSL_CERT_FILE" -u "__token__:$E2E_TOKEN" \
			"$base/$proxy/sumdb/$sumdb/lookup/$(escape "$path")@$(escape "$version")" >"$state/lookup-$n"
	done <go.sum
	echo "OK: built through $proxy and $virtual"
	exit 0
fi

step "flint cannot reach the upstreams"
mkdir -p "$work/mod"
cd "$work/mod"
cp "$state/go.mod" "$state/go.sum" "$state/main.go" .
if gocmd "$proxy" "$work/cache-x" mod download "$uncached" 2>"$work/err"; then
	fail "$uncached, never downloaded, was served, so the upstream is reachable"
fi
grep -q 503 "$work/err" || fail "an uncached module failed without 503: $(cat "$work/err")"

for repo in "$proxy" "$virtual"; do
	step "download and build with an empty module cache through $repo"
	gocmd "$repo" "$work/cache-$repo" mod download
	gocmd "$repo" "$work/cache-$repo" mod verify
	gocmd "$repo" "$work/cache-$repo" build -o "$work/e2e" .
	case $("$work/e2e") in
	"Flint "*) ;;
	*) fail "the module built offline through $repo printed $("$work/e2e")" ;;
	esac
	gocmd "$repo" "$work/cache-$repo" list -m -versions github.com/google/uuid | grep -q ' v1.6.0' ||
		fail "the version list through $repo lacks v1.6.0 offline"
	cmp go.sum "$state/go.sum" || fail "go.sum changed offline through $repo"
done

step "the checksum database records are served from the cache"
n=0
while read -r path version; do
	n=$((n + 1))
	curl -fsS --cacert "$SSL_CERT_FILE" -u "__token__:$E2E_TOKEN" \
		"$base/$proxy/sumdb/$sumdb/lookup/$(escape "$path")@$(escape "$version")" | cmp - "$state/lookup-$n" ||
		fail "the record of $path@$version differs offline"
done <"$state/lookups"
[ "$n" -gt 0 ] || fail "the online run saved no records"

stale=$(metric "flint_proxy_requests_total{repository=\"$proxy\",result=\"stale\"}")
[ "$stale" -gt 0 ] || fail "no request was counted as served stale"
echo "OK: modules and checksum records served with the upstreams unreachable"
