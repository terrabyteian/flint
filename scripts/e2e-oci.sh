#!/usr/bin/env bash
# e2e-oci.sh pushes and pulls real content through a running flint with
# real clients: a multi-arch image (crane, then docker), an image built and
# pushed by docker, a cross-repository copy, and an OCI artifact with a
# referrer (oras). It fails on the first mismatch.
#
# Usage: scripts/e2e-oci.sh <host:port> <namespace>
#   <namespace> is a configured hosted OCI repository, such as "e2e".
# Requires crane, oras, docker, and jq on PATH; set E2E_SKIP_DOCKER=1 to
# skip the docker steps.
set -euo pipefail

if [ $# -ne 2 ]; then
	echo "usage: $0 <host:port> <namespace>" >&2
	exit 2
fi
reg=$1
ns=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
crane() { command crane --insecure "$@"; }
oras_() { command oras "$@" --plain-http; }

step "multi-arch image with crane"
for arch in amd64 arm64; do
	mkdir -p "$work/$arch"
	echo "$arch" >"$work/$arch/arch.txt"
	tar -C "$work/$arch" -cf "$work/$arch.tar" arch.txt
	crane append --oci-empty-base -f "$work/$arch.tar" -t "$reg/$ns/multi:$arch-base"
	crane mutate --set-platform "linux/$arch" -t "$reg/$ns/multi:$arch" "$reg/$ns/multi:$arch-base"
done
crane index append -m "$reg/$ns/multi:amd64" -m "$reg/$ns/multi:arm64" -t "$reg/$ns/multi:latest"
[ "$(crane manifest "$reg/$ns/multi:latest" | jq '.manifests | length')" = 2 ] || fail "index does not list 2 manifests"
for arch in amd64 arm64; do
	got=$(crane export --platform "linux/$arch" "$reg/$ns/multi:latest" - | tar -xOf - arch.txt)
	[ "$got" = "$arch" ] || fail "linux/$arch pulled $got"
	[ "$(crane config --platform "linux/$arch" "$reg/$ns/multi:latest" | jq -r .architecture)" = "$arch" ] ||
		fail "linux/$arch config has the wrong architecture"
done
crane ls "$reg/$ns/multi" | sort | tr '\n' ' ' | grep -qx 'amd64 amd64-base arm64 arm64-base latest ' ||
	fail "unexpected tags: $(crane ls "$reg/$ns/multi" | tr '\n' ' ')"

step "cross-repository copy with crane (blob mounts)"
crane copy "$reg/$ns/multi:latest" "$reg/$ns/copy:latest"
[ "$(crane digest "$reg/$ns/copy:latest")" = "$(crane digest "$reg/$ns/multi:latest")" ] || fail "copy digest differs"
crane catalog "$reg" | grep -qx "$ns/copy" || fail "catalog lacks $ns/copy"

step "delete with crane"
digest=$(crane digest "$reg/$ns/copy:latest")
crane delete "$reg/$ns/copy@$digest"
if crane manifest "$reg/$ns/copy@$digest" >/dev/null 2>&1; then
	fail "deleted manifest still served"
fi

step "artifact with a referrer with oras"
cd "$work"
echo "artifact payload" >artifact.txt
echo "signature payload" >signature.txt
oras_ push "$reg/$ns/artifact:v1" --artifact-type application/vnd.flint.e2e.artifact artifact.txt:text/plain
oras_ attach "$reg/$ns/artifact:v1" --artifact-type application/vnd.flint.e2e.signature \
	--annotation org.flint.e2e=signed signature.txt:text/plain
refs=$(oras_ discover "$reg/$ns/artifact:v1" --format json)
[ "$(echo "$refs" | jq '[(.referrers // .manifests)[] | select(.artifactType == "application/vnd.flint.e2e.signature")] | length')" = 1 ] ||
	fail "discover did not find the signature: $refs"
sig=$(echo "$refs" | jq -r '(.referrers // .manifests)[0].digest')
# The referrers API was used, not the tag-schema fallback.
[ "$(crane ls "$reg/$ns/artifact" | tr '\n' ' ')" = "v1 " ] || fail "unexpected tags: $(crane ls "$reg/$ns/artifact")"
mkdir out sig
oras_ pull "$reg/$ns/artifact:v1" -o out
cmp artifact.txt out/artifact.txt || fail "pulled artifact differs"
oras_ pull "$reg/$ns/artifact@$sig" -o sig
cmp signature.txt sig/signature.txt || fail "pulled signature differs"
[ "$(oras_ manifest fetch "$reg/$ns/artifact@$sig" | jq -r '.annotations["org.flint.e2e"]')" = signed ] ||
	fail "signature annotation lost"

if [ "${E2E_SKIP_DOCKER:-}" = 1 ]; then
	echo "e2e-oci: ok (docker skipped)"
	exit 0
fi

step "docker pull of the multi-arch image"
docker pull "$reg/$ns/multi:latest"
[ "$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$reg/$ns/multi:latest")" = "linux/$(docker version -f '{{.Server.Arch}}')" ] ||
	fail "docker pulled the wrong platform"
docker image rm "$reg/$ns/multi:latest" >/dev/null

step "docker build, push, and pull"
mkdir ctx
echo "built by docker" >ctx/hello.txt
printf 'FROM scratch\nCOPY hello.txt /\n' >ctx/Dockerfile
docker build -q -t "$reg/$ns/docker:v1" ctx
docker push "$reg/$ns/docker:v1"
docker image rm "$reg/$ns/docker:v1" >/dev/null
docker pull "$reg/$ns/docker:v1"
id=$(docker create "$reg/$ns/docker:v1" /none)
docker cp "$id:/hello.txt" pulled.txt
docker rm "$id" >/dev/null
cmp ctx/hello.txt pulled.txt || fail "docker round trip differs"
docker image rm "$reg/$ns/docker:v1" >/dev/null

echo "e2e-oci: ok"
