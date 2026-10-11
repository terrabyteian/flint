#!/usr/bin/env bash
# e2e-gc.sh runs garbage collection with flint gc on a running flint
# after scripts/e2e-oci.sh, and in CI the conformance suite, pushed and
# deleted content. It runs twice, around a move of flint's clock past the
# garbage collector's grace period:
#
#   delete   pushes two images and deletes them as clients do, by their
#            manifests only.
#   collect  checks that a dry run deletes nothing, that a run deletes
#            what the dry run reported, including the first deleted
#            image's manifest, config, and layer, whose links expired, and
#            that every image and artifact left in <namespace> still pulls,
#            byte for byte, with crane and oras. Before the runs, it checks
#            the second image's config and base layer with HEAD, as a
#            rebuild that shares them does; the runs must keep them, and
#            the rebuild's push must succeed after them. A second run must
#            find nothing more to delete.
#
# Usage: E2E_STATE_DIR=<dir> E2E_USERNAME=<admin> E2E_PASSWORD_FILE=<file> \
#          scripts/e2e-gc.sh delete|collect <flint binary> <data dir> <host:port> <namespace>
#   flint must be built with "go build -tags e2e" and run with
#   FLINT_E2E_CLOCK_FILE set to a file; between the two, write a duration
#   of at least the grace period, such as 72h, to that file. E2E_USERNAME
#   needs the global admin role; E2E_STATE_DIR keeps the deleted image for
#   the collect run.
#   collect reads the blob store in <data dir>, so it runs on the server's
#   host.
# Requires crane, oras, jq, and sha256sum or shasum on PATH.
set -euo pipefail

if [ $# -ne 5 ] || [ -z "${E2E_STATE_DIR:-}" ] || [ -z "${E2E_USERNAME:-}" ] || [ -z "${E2E_PASSWORD_FILE:-}" ] ||
	{ [ "$1" != delete ] && [ "$1" != collect ]; }; then
	echo "usage: E2E_STATE_DIR=<dir> E2E_USERNAME=<admin> E2E_PASSWORD_FILE=<file> $0 delete|collect <flint binary> <data dir> <host:port> <namespace>" >&2
	exit 2
fi
mode=$1
flint=$2
data=$3
reg=$4
ns=$5
state=$E2E_STATE_DIR
mkdir -p "$state"
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
crane() { command crane --insecure "$@"; }
gc() { "$flint" gc "$@" -url "http://$reg" -user "$E2E_USERNAME" -password-file "$E2E_PASSWORD_FILE" -json; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi; }
stored() { find "$data/blobs" -type f | wc -l | tr -d ' '; }
blobfile() { local h=${1#sha256:}; echo "$data/blobs/sha256/${h:0:2}/$h"; }
password=$(cat "$E2E_PASSWORD_FILE")
printf '%s' "$password" | command crane auth login "$reg" -u "$E2E_USERNAME" --password-stdin
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ "$mode" = delete ]; then
	step "push an image and delete it by its manifest"
	head -c 4096 /dev/urandom >"$work/garbage.bin"
	tar -C "$work" -cf "$work/garbage.tar" garbage.bin
	crane append --oci-empty-base -f "$work/garbage.tar" -t "$reg/$ns/gc-garbage:v1" >/dev/null
	digest=$(crane digest "$reg/$ns/gc-garbage:v1")
	crane manifest "$reg/$ns/gc-garbage:v1" | jq -r --arg m "$digest" '$m, .config.digest, .layers[].digest' >"$state/garbage"
	crane delete "$reg/$ns/gc-garbage@$digest"

	step "push an image whose rebuild will share its config and base layer, and delete it"
	head -c 4096 /dev/urandom >"$work/base.bin"
	tar -C "$work" -cf "$work/base.tar" base.bin
	head -c 4096 /dev/urandom >"$work/top.bin"
	tar -C "$work" -cf "$work/top.tar" top.bin
	crane append --oci-empty-base -f "$work/base.tar" -t "$reg/$ns/gc-rebuild:base" >/dev/null
	crane append -b "$reg/$ns/gc-rebuild:base" -f "$work/top.tar" -t "$reg/$ns/gc-rebuild:v1" >/dev/null
	crane manifest "$reg/$ns/gc-rebuild:v1" >"$state/rebuild.json"
	crane blob "$reg/$ns/gc-rebuild@$(jq -r '.layers[-1].digest' "$state/rebuild.json")" >"$state/rebuild-top"
	for tag in base v1; do
		crane delete "$reg/$ns/gc-rebuild@$(crane digest "$reg/$ns/gc-rebuild:$tag")"
	done
	echo "e2e-gc delete: ok"
	exit 0
fi

garbage=$(cat "$state/garbage")
for d in $garbage; do
	[ -f "$(blobfile "$d")" ] || fail "the deleted image's blob $d is not stored before the run"
done

step "a rebuild checks the deleted image's config and base layer"
# A rebuild that shares them finds their links with HEAD and skips their
# upload; garbage collection must keep the links it read within the
# grace period. The rebuild's own layer and the old manifest go.
rebuild=$(cat "$state/rebuild.json")
rebuilt="sha256:$(printf '%s' "$rebuild" | sha256)"
reused=$(jq -r '.config.digest, .layers[0].digest' <<<"$rebuild")
replaced="$rebuilt $(jq -r '.layers[-1].digest' <<<"$rebuild")"
for d in $reused; do
	[ "$(curl -sS -o /dev/null -w '%{http_code}' -I -u "$E2E_USERNAME:$password" "http://$reg/v2/$ns/gc-rebuild/blobs/$d")" = 200 ] ||
		fail "HEAD of the deleted image's blob $d in $ns/gc-rebuild"
done
before=$(stored)

step "dry run"
dry=$(gc run -dry-run)
[ "$(jq -r .state <<<"$dry")" = succeeded ] || fail "dry run: $dry"
would=$(jq .deleted.blobs <<<"$dry")
[ "$would" -gt 0 ] || fail "the dry run found nothing to delete after the deletes: $dry"
for d in $garbage; do
	jq -e --arg d "$d" '.blobsTruncated or (.blobs | map(.digest) | index($d) != null)' <<<"$dry" >/dev/null ||
		fail "the dry run does not list the deleted image's blob $d: $dry"
done
[ "$(stored)" = "$before" ] || fail "the dry run deleted blobs"

step "run"
report=$(gc run)
[ "$(jq -r .state <<<"$report")" = succeeded ] || fail "run: $report"
deleted=$(jq .deleted.blobs <<<"$report")
[ "$deleted" = "$would" ] || fail "the run deleted $deleted blobs, the dry run reported $would"
[ "$(jq .pruned <<<"$report")" = "$(jq .pruned <<<"$dry")" ] || fail "the run pruned other links than the dry run: $report"
[ "$(stored)" = $((before - deleted)) ] || fail "$before blobs stored before, $(stored) after deleting $deleted"
for d in $garbage $replaced; do
	[ ! -f "$(blobfile "$d")" ] || fail "the deleted image's blob $d survived"
done
for d in $reused; do
	[ -f "$(blobfile "$d")" ] || fail "the run deleted blob $d, which a rebuild read within the grace period"
done
echo "deleted $deleted of $before blobs, after removing $(jq .pruned <<<"$report") expired links"

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

step "the rebuild pushes its own layer and its manifest"
top=$(jq -r '.layers[-1].digest' <<<"$rebuild")
curl -fsS -o /dev/null -u "$E2E_USERNAME:$password" -H 'Content-Type: application/octet-stream' \
	--data-binary @"$state/rebuild-top" "http://$reg/v2/$ns/gc-rebuild/blobs/uploads/?digest=$top" ||
	fail "pushing the rebuild's layer $top"
printf '%s' "$rebuild" | curl -fsS -o /dev/null -u "$E2E_USERNAME:$password" -X PUT \
	-H "Content-Type: $(jq -r .mediaType <<<"$rebuild")" --data-binary @- "http://$reg/v2/$ns/gc-rebuild/manifests/v2" ||
	fail "pushing the rebuild's manifest, which references the blobs it read before the run"
check "$ns/gc-rebuild" "$(crane digest "$reg/$ns/gc-rebuild:v2")"

step "a second run finds nothing more"
again=$(gc run)
[ "$(jq -r .state <<<"$again")" = succeeded ] && [ "$(jq .deleted.blobs <<<"$again")" = 0 ] ||
	fail "second run: $again"

echo "e2e-gc collect: ok"
