#!/usr/bin/env bash
# e2e-gc.sh runs garbage collection with flint gc on a running flint
# after scripts/e2e-oci.sh, and in CI the conformance suite, pushed and
# deleted content. It pushes and deletes one more image, ages every
# stored blob past the grace period, and checks that a dry run deletes
# nothing, that a run deletes what the dry run reported, and that every
# image and artifact left in <namespace> still pulls, byte for byte, with
# crane and oras. A second run must find nothing more to delete.
#
# Usage: FLINT_USER=<admin> FLINT_PASSWORD=<secret> scripts/e2e-gc.sh <flint binary> <data dir> <host:port> <namespace>
#   It sets the stored blobs' modification times, so it runs on the
#   server's host. FLINT_USER needs the global admin role.
# Requires crane, oras, jq, curl, and sha256sum or shasum on PATH.
set -euo pipefail

if [ $# -ne 4 ] || [ -z "${FLINT_USER:-}" ] || [ -z "${FLINT_PASSWORD:-}" ]; then
	echo "usage: FLINT_USER=<admin> FLINT_PASSWORD=<secret> $0 <flint binary> <data dir> <host:port> <namespace>" >&2
	exit 2
fi
flint=$1
data=$2
reg=$3
ns=$4
export FLINT_URL="http://$reg"
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
crane() { command crane --insecure "$@"; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi; }
stored() { find "$data/blobs" -type f | wc -l | tr -d ' '; }
printf '%s' "$FLINT_PASSWORD" | command crane auth login "$reg" -u "$FLINT_USER" --password-stdin

step "push an image and delete it, with its blobs' links"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
head -c 4096 /dev/urandom >"$work/garbage.bin"
tar -C "$work" -cf "$work/garbage.tar" garbage.bin
crane append --oci-empty-base -f "$work/garbage.tar" -t "$reg/$ns/gc-garbage:v1" >/dev/null
garbage=$(crane manifest "$reg/$ns/gc-garbage:v1")
crane delete "$reg/$ns/gc-garbage@$(crane digest "$reg/$ns/gc-garbage:v1")"
for d in $(jq -r '.config.digest, .layers[].digest' <<<"$garbage"); do
	code=$(curl -sS -o /dev/null -w '%{http_code}' -u "$FLINT_USER:$FLINT_PASSWORD" -X DELETE "$FLINT_URL/v2/$ns/gc-garbage/blobs/$d")
	[ "$code" = 202 ] || fail "deleting the link of $d: $code"
done

step "age every stored blob past the grace period"
# touch -t takes local time; three days back is past the default grace
# period in any time zone.
stamp=$(date -d '3 days ago' +%Y%m%d%H%M 2>/dev/null || date -v-3d +%Y%m%d%H%M)
find "$data/blobs" -type f -exec touch -m -t "$stamp" {} +
before=$(stored)

step "dry run"
dry=$("$flint" gc run -dry-run -json)
[ "$(jq -r .state <<<"$dry")" = succeeded ] || fail "dry run: $dry"
would=$(jq .deleted.blobs <<<"$dry")
[ "$would" -gt 0 ] || fail "the dry run found nothing to delete after the deletes: $dry"
[ "$(stored)" = "$before" ] || fail "the dry run deleted blobs"

step "run"
report=$("$flint" gc run -json)
[ "$(jq -r .state <<<"$report")" = succeeded ] || fail "run: $report"
deleted=$(jq .deleted.blobs <<<"$report")
[ "$deleted" = "$would" ] || fail "the run deleted $deleted blobs, the dry run reported $would"
[ "$(stored)" = $((before - deleted)) ] || fail "$before blobs stored before, $(stored) after deleting $deleted"
echo "deleted $deleted of $before blobs"

step "every image and artifact in $ns still pulls"
# check verifies a manifest and, recursively, everything it references,
# by digest.
check() {
	local repo=$1 ref=$2 manifest d
	manifest=$(crane manifest "$reg/$repo@$ref")
	[ "sha256:$(printf '%s' "$manifest" | sha256)" = "$ref" ] || fail "$repo@$ref: manifest digest differs"
	for d in $(jq -r '(.config // empty | .digest), (.layers // [] | .[].digest)' <<<"$manifest"); do
		[ "sha256:$(crane blob "$reg/$repo@$d" | sha256)" = "$d" ] || fail "$repo@$ref: blob $d differs"
	done
	for d in $(jq -r '.manifests // [] | .[].digest' <<<"$manifest"); do
		check "$repo" "$d"
	done
}
checked=0
for repo in $(crane catalog "$reg" | grep "^$ns/"); do
	for tag in $(crane ls "$reg/$repo"); do
		check "$repo" "$(crane digest "$reg/$repo:$tag")"
		checked=$((checked + 1))
	done
done
[ "$checked" -gt 0 ] || fail "no tags in $ns to check"
cd "$work"
sig=$(oras discover --plain-http "$reg/$ns/artifact:v1" --format json | jq -r '(.referrers // .manifests)[0].digest')
check "$ns/artifact" "$sig"
oras pull --plain-http "$reg/$ns/artifact@$sig" -o sig >/dev/null
echo "checked $checked tags and the artifact's signature"

step "a second run finds nothing more"
again=$("$flint" gc run -json)
[ "$(jq -r .state <<<"$again")" = succeeded ] && [ "$(jq .deleted.blobs <<<"$again")" = 0 ] ||
	fail "second run: $again"

echo "e2e-gc: ok"
