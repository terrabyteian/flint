#!/usr/bin/env bash
# e2e-cargo.sh drives flint's Cargo repositories with real cargo: it fetches
# crates from crates.io through a proxy repository, publishes two crates to
# a hosted repository with cargo publish, one depending on the other and on
# crates.io crates, yanks, searches, and deletes, and builds a consumer with
# a fresh CARGO_HOME through a virtual repository that requires
# authentication, with and without source replacement for crates.io. It
# checks duplicate publishes, dependency-confusion protection, and that the
# whole dependency graph resolves through the virtual repository. A second
# run, after flint has been restarted with its upstream unreachable, builds
# the consumers again with fresh CARGO_HOMEs to prove that cached content
# keeps being served offline. It fails on the first mismatch.
#
# Usage: E2E_STATE_DIR=<dir> E2E_TOKEN=<token> E2E_ADMIN=<user:password> \
#          scripts/e2e-cargo.sh online|offline <host:port> <hosted> <proxy> <virtual>
#   <hosted>   a hosted Cargo repository the token may publish to and read
#   <proxy>    a proxy repository of sparse+https://index.crates.io/ with
#              anonymousPull
#   <virtual>  a virtual repository of <hosted> and <proxy>, in that order,
#              without anonymousPull, with dependency-confusion protection,
#              publishing to <hosted>
#   E2E_TOKEN  an API token with write on <hosted> and read on <virtual>
#   E2E_ADMIN  credentials with the delete role on <hosted>, for deleting
#              through the admin API
#   E2E_STATE_DIR keeps what the online run built for the offline run.
# Requires cargo (1.74 or later), python3, jq, and curl on PATH.
set -euo pipefail

if [ $# -ne 5 ] || [ -z "${E2E_STATE_DIR:-}" ] || [ -z "${E2E_TOKEN:-}" ] || [ -z "${E2E_ADMIN:-}" ] ||
	{ [ "$1" != online ] && [ "$1" != offline ]; }; then
	echo "usage: E2E_STATE_DIR=<dir> E2E_TOKEN=<token> E2E_ADMIN=<user:password> $0 online|offline <host:port> <hosted> <proxy> <virtual>" >&2
	exit 2
fi
mode=$1
reg=$2
hosted=$3
proxy=$4
virtual=$5
state=$E2E_STATE_DIR
mkdir -p "$state"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

base=http://$reg/cargo
export CARGO_TERM_COLOR=never CARGO_TERM_PROGRESS_WHEN=never CARGO_INCREMENTAL=0
# cargo reads each registry's token from CARGO_REGISTRIES_<NAME>_TOKEN.
export CARGO_REGISTRIES_FLINT_TOKEN=$E2E_TOKEN CARGO_REGISTRIES_FLINT_ALL_TOKEN=$E2E_TOKEN

# Crates from crates.io that the consumers use, and one that a hosted crate
# claims, for the dependency-confusion check, and one that no step fetches
# online.
claimed=fastrand
uncached=smallvec

# status prints the HTTP status of a request.
status() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }

# metric prints the value of a flint metric sample, or 0.
metric() {
	curl -fsS "http://$reg/metrics" | awk -v s="$1" '$1 == s { print $2; found = 1 } END { if (!found) print 0 }'
}

# home makes a fresh CARGO_HOME, $work/home-<name>, that knows flint's
# repositories as the registries flint (hosted), flint-all (virtual), and
# flint-proxy, and exports it. With a second argument, crates.io is
# replaced by that registry.
home() {
	export CARGO_HOME=$work/home-$1
	mkdir -p "$CARGO_HOME"
	cat >"$CARGO_HOME/config.toml" <<-TOML
		[registries.flint]
		index = "sparse+$base/$hosted/"
		credential-provider = "cargo:token"

		[registries.flint-all]
		index = "sparse+$base/$virtual/"
		credential-provider = "cargo:token"

		[registries.flint-proxy]
		index = "sparse+$base/$proxy/"
	TOML
	if [ $# -gt 1 ]; then
		printf '\n[source.crates-io]\nreplace-with = "%s"\n' "$2" >>"$CARGO_HOME/config.toml"
	fi
}

# project makes a crate in $work/<dir> named <name>, at <version>, with the
# dependency lines given: a binary that prints ok if <name> starts with
# consumer, and a library otherwise.
project() {
	local dir=$work/$1 name=$2 version=$3
	shift 3
	mkdir -p "$dir/src"
	{
		printf '[package]\nname = "%s"\nversion = "%s"\nedition = "2021"\n' "$name" "$version"
		printf 'description = "flint end-to-end test crate %s"\nlicense = "Apache-2.0"\n\n[dependencies]\n' "$name"
		printf '%s\n' "$@"
	} >"$dir/Cargo.toml"
	case $name in
	consumer*) echo 'fn main() { println!("ok"); }' >"$dir/src/main.rs" ;;
	*) echo "pub const VERSION: &str = \"$version\";" >"$dir/src/lib.rs" ;;
	esac
}

# lock_version prints the version of a package in a Cargo.lock.
lock_version() { awk -v n="$2" '$0 == "name = \"" n "\"" { getline; gsub(/version = |"/, ""); print; exit }' "$1"; }

# lock_sources prints the distinct sources of a Cargo.lock.
lock_sources() { grep '^source = ' "$1" | sort -u; }

# sha256 prints a file's sha256 digest in hex.
sha256() {
	if command -v sha256sum >/dev/null; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

# crates_io_cksum prints a version's checksum in crates.io's own index.
crates_io_cksum() {
	local n=$1
	curl -fsS "https://index.crates.io/${n:0:2}/${n:2:2}/$n" | jq -r --arg v "$2" 'select(.vers == $v) | .cksum'
}

# publish_status sends a publish request for a packaged .crate file, with
# the minimal metadata, straight to a repository, and prints the status.
publish_status() {
	local repo=$1 name=$2 version=$3 crate=$4
	python3 - "$name" "$version" "$crate" "$work/publish.bin" <<-'PY'
		import json, struct, sys
		name, version, crate, out = sys.argv[1:]
		md = json.dumps({"name": name, "vers": version, "deps": [], "features": {}}).encode()
		body = open(crate, "rb").read()
		open(out, "wb").write(struct.pack("<I", len(md)) + md + struct.pack("<I", len(body)) + body)
	PY
	status -X PUT -H "Authorization: $E2E_TOKEN" --data-binary "@$work/publish.bin" "$base/$repo/api/v1/crates/new"
}

if [ "$mode" = online ]; then
	step "cargo fetches from crates.io through $proxy, byte for byte"
	home proxy flint-proxy
	project consumer-proxy consumer-proxy 0.1.0 'itoa = "=1.0.11"' 'memchr = "2"'
	(cd "$work/consumer-proxy" && cargo build --quiet)
	[ "$("$work/consumer-proxy/target/debug/consumer-proxy")" = ok ] || fail "the proxy consumer does not run"
	lock=$work/consumer-proxy/Cargo.lock
	want=$(crates_io_cksum itoa 1.0.11)
	grep -A3 '^name = "itoa"$' "$lock" | grep -q "checksum = \"$want\"" || fail "itoa's checksum is not crates.io's $want"
	cp -r "$work/consumer-proxy" "$state/"
	[ "$(curl -fsS "$base/$proxy/config.json" | jq '."auth-required"')" = false ] ||
		fail "$proxy's config.json requires authentication"

	step "$virtual requires authentication"
	[ "$(status "$base/$virtual/config.json")" = 401 ] || fail "$virtual answered an anonymous client"
	curl -sS -D - -o /dev/null "$base/$virtual/config.json" | grep -qi '^www-authenticate: Cargo login_url=' ||
		fail "$virtual does not challenge with Cargo's login_url"
	[ "$(curl -fsS -H "Authorization: $E2E_TOKEN" "$base/$virtual/config.json" | jq '."auth-required"')" = true ] ||
		fail "$virtual's config.json does not require authentication"

	step "cargo publishes two crates to $hosted, depending on each other and on crates.io"
	home publish flint-proxy
	project base flint-e2e-base 0.1.0 'itoa = "1"'
	(cd "$work/base" && cargo publish --quiet --registry flint)
	project app flint-e2e-app 0.1.0 'flint-e2e-base = { version = "0.1", registry = "flint" }' 'memchr = "2"'
	(cd "$work/app" && cargo publish --quiet --registry flint)
	line=$(curl -fsS -H "Authorization: $E2E_TOKEN" "$base/$hosted/fl/in/flint-e2e-app")
	[ "$(echo "$line" | jq -r '.deps[] | select(.name == "memchr") | .registry')" = https://github.com/rust-lang/crates.io-index ] ||
		fail "the crates.io dependency of flint-e2e-app does not name crates.io in $hosted: $line"
	[ "$(echo "$line" | jq -r '.deps[] | select(.name == "flint-e2e-base") | .registry')" = null ] ||
		fail "the dependency on flint-e2e-base names another registry: $line"
	curl -fsS -H "Authorization: $E2E_TOKEN" -o "$work/app.crate" "$base/$hosted/api/v1/crates/flint-e2e-app/0.1.0/download"
	[ "$(echo "$line" | jq -r .cksum)" = "$(sha256 "$work/app.crate")" ] ||
		fail "the index line's cksum is not the .crate file's sha256"

	step "cargo publishes through $virtual to $hosted"
	project base2 flint-e2e-base 0.2.0 'itoa = "1"'
	(cd "$work/base2" && cargo publish --quiet --registry flint-all)
	[ "$(curl -fsS -H "Authorization: $E2E_TOKEN" "$base/$hosted/fl/in/flint-e2e-base" | jq -sc '[.[].vers]')" = '["0.1.0","0.2.0"]' ] ||
		fail "$hosted does not list both versions of flint-e2e-base"

	step "a duplicate publish fails"
	if (cd "$work/app" && cargo publish --quiet --registry flint 2>/dev/null); then
		fail "cargo published flint-e2e-app 0.1.0 twice"
	fi
	[ "$(publish_status "$hosted" flint-e2e-app 0.1.0 "$work/app.crate")" = 409 ] ||
		fail "$hosted did not refuse a duplicate version with 409"
	[ "$(publish_status "$proxy" flint-e2e-app 0.9.0 "$work/app.crate")" = 405 ] ||
		fail "$proxy did not refuse a publish with 405"

	step "a yanked version is skipped by a fresh lockfile"
	(cd "$work/base2" && cargo yank --quiet --registry flint flint-e2e-base@0.2.0)
	home yank flint-proxy
	project consumer-yank consumer-yank 0.1.0 'flint-e2e-base = { version = ">=0.1", registry = "flint" }'
	(cd "$work/consumer-yank" && cargo generate-lockfile --quiet)
	[ "$(lock_version "$work/consumer-yank/Cargo.lock" flint-e2e-base)" = 0.1.0 ] || fail "a fresh lockfile picked the yanked 0.2.0"
	(cd "$work/base2" && cargo yank --quiet --registry flint --undo flint-e2e-base@0.2.0)
	(cd "$work/consumer-yank" && cargo generate-lockfile --quiet)
	[ "$(lock_version "$work/consumer-yank/Cargo.lock" flint-e2e-base)" = 0.2.0 ] || fail "an unyanked version is not picked"

	step "cargo builds a consumer through $virtual, with crates.io replaced by it"
	home virtual flint-all
	project consumer consumer 0.1.0 'flint-e2e-app = { version = "0.1", registry = "flint-all" }' 'itoa = "=1.0.11"'
	(cd "$work/consumer" && cargo build --quiet)
	[ "$("$work/consumer/target/debug/consumer")" = ok ] || fail "the consumer does not run"
	# A replaced source keeps its own name in Cargo.lock.
	lock_sources "$work/consumer/Cargo.lock" | grep -v -e "^source = \"sparse+$base/$virtual/\"$" \
		-e '^source = "registry+https://github.com/rust-lang/crates.io-index"$' && fail "the consumer resolved packages elsewhere"
	cp -r "$work/consumer" "$state/"

	step "without source replacement, the whole graph resolves through $virtual"
	home direct
	project consumer-direct consumer-direct 0.1.0 'flint-e2e-app = { version = "0.1", registry = "flint-all" }'
	(cd "$work/consumer-direct" && cargo generate-lockfile --quiet)
	[ "$(lock_sources "$work/consumer-direct/Cargo.lock")" = "source = \"sparse+$base/$virtual/\"" ] ||
		fail "dependencies on crates.io were not served through $virtual: $(lock_sources "$work/consumer-direct/Cargo.lock")"
	grep -q '^name = "memchr"$' "$work/consumer-direct/Cargo.lock" || fail "memchr is not in the graph"

	step "cargo search"
	home search
	(cd "$work" && cargo search --registry flint flint-e2e) | grep -q '^flint-e2e-app = "0.1.0"' ||
		fail "cargo search does not find flint-e2e-app in $hosted"
	(cd "$work" && cargo search --registry flint-all --limit 3 flint-e2e-b) | grep -q '^flint-e2e-base = "0.2.0"' ||
		fail "cargo search does not find flint-e2e-base in $virtual"

	step "cargo owner names flint's permission grants"
	if out=$(cd "$work" && cargo owner --registry flint --list flint-e2e-base 2>&1); then
		fail "cargo owner succeeded"
	fi
	echo "$out" | grep -q "permission grants" || fail "cargo owner did not explain: $out"

	step "a deleted version is gone, and can never be published again"
	curl -fsS -u "$E2E_ADMIN" -X DELETE "http://$reg/api/v1/cargo/$hosted/crates/flint-e2e-base/0.2.0" >/dev/null
	[ "$(curl -fsS -H "Authorization: $E2E_TOKEN" "$base/$virtual/fl/in/flint-e2e-base" | jq -sc '[.[].vers]')" = '["0.1.0"]' ] ||
		fail "$virtual still lists the deleted version"
	[ "$(status -H "Authorization: $E2E_TOKEN" "$base/$virtual/api/v1/crates/flint-e2e-base/0.2.0/download")" = 404 ] ||
		fail "the deleted version still downloads"
	home republish flint-proxy
	if out=$(cd "$work/base2" && cargo publish --quiet --registry flint 2>&1); then
		fail "a deleted version was published again"
	fi
	echo "$out" | grep -q "409" || fail "republishing a deleted version did not fail with 409: $out"

	step "dependency-confusion protection: $claimed in $hosted hides crates.io's"
	[ "$(curl -fsS "$base/$proxy/${claimed:0:2}/${claimed:2:2}/$claimed" | wc -l)" -gt 1 ] ||
		fail "$proxy lists no versions of $claimed"
	home claim flint-proxy
	project claimed "$claimed" 0.0.1
	(cd "$work/claimed" && cargo publish --quiet --registry flint)
	[ "$(curl -fsS -H "Authorization: $E2E_TOKEN" "$base/$virtual/${claimed:0:2}/${claimed:2:2}/$claimed" | jq -sc '[.[].vers]')" = '["0.0.1"]' ] ||
		fail "$virtual serves crates.io's versions of $claimed"

	echo "OK: published, built, and proxied"
	exit 0
fi

step "flint answers with its upstream unreachable"
[ "$(status "$base/$proxy/${uncached:0:2}/${uncached:2:2}/$uncached")" = 503 ] || fail "$uncached, never cached, did not fail with 503"

step "cargo builds through $proxy from the cache"
home offline-proxy flint-proxy
cp -r "$state/consumer-proxy" "$work/"
rm -rf "$work/consumer-proxy/target"
(cd "$work/consumer-proxy" && cargo build --quiet --locked)
[ "$("$work/consumer-proxy/target/debug/consumer-proxy")" = ok ] || fail "the proxy consumer does not run offline"

step "cargo builds through $virtual from the cache, with a fresh CARGO_HOME"
home offline-virtual flint-all
cp -r "$state/consumer" "$work/"
rm -rf "$work/consumer/target" "$work/consumer/Cargo.lock"
(cd "$work/consumer" && cargo build --quiet)
[ "$("$work/consumer/target/debug/consumer")" = ok ] || fail "the consumer does not run offline"

step "a crate never cached fails"
home offline-uncached flint-proxy
project consumer-uncached consumer-uncached 0.1.0 "$uncached = \"1\""
if (cd "$work/consumer-uncached" && cargo generate-lockfile --quiet 2>/dev/null); then
	fail "$uncached resolved with the upstream unreachable"
fi
stale=$(metric "flint_proxy_requests_total{repository=\"$proxy\",result=\"stale\"}")
[ "${stale%.*}" -gt 0 ] || fail "no index file was served stale"
echo "OK: served from the cache"
