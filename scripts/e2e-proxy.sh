#!/usr/bin/env bash
# e2e-proxy.sh pulls real public images from Docker Hub and ghcr.io through
# running flint proxy repositories with real clients, then, in a second run
# after flint has been restarted with its upstreams unreachable, pulls them
# again to prove that cached content keeps being served offline. It fails
# on the first mismatch.
#
# Usage: E2E_STATE_DIR=<dir> scripts/e2e-proxy.sh online|offline <host:port> <dockerhub-repo> <ghcr-repo>
#   <dockerhub-repo> and <ghcr-repo> are proxy repositories of
#   https://registry-1.docker.io and https://ghcr.io with anonymousPull.
#   online   pulls with crane, docker, and containerd (as a registry mirror)
#            and checks that flint serves what the upstreams serve.
#   offline  runs against the same data directory once flint cannot reach
#            the upstreams: it pulls the same images, by tag and by digest,
#            and checks that an image never pulled fails.
#   E2E_STATE_DIR keeps the digests the online run saw for the offline run.
# Requires crane, docker, jq, and curl on PATH, and ctr with sudo for the
# containerd mirror; set E2E_SKIP_DOCKER=1 or E2E_SKIP_CONTAINERD=1 to skip
# those steps.
set -euo pipefail

if [ $# -ne 4 ] || [ -z "${E2E_STATE_DIR:-}" ] || { [ "$1" != online ] && [ "$1" != offline ]; }; then
	echo "usage: E2E_STATE_DIR=<dir> $0 online|offline <host:port> <dockerhub-repo> <ghcr-repo>" >&2
	exit 2
fi
mode=$1
reg=$2
hub=$3
ghcr=$4
state=$E2E_STATE_DIR
mkdir -p "$state"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
crane() { command crane --insecure "$@"; }
docker_steps() { [ "${E2E_SKIP_DOCKER:-}" != 1 ]; }
containerd_steps() { [ "${E2E_SKIP_CONTAINERD:-}" != 1 ]; }

# Images pulled through the proxies: official Docker Hub images by their
# full and their short name (which gets the library/ prefix), flint's own
# image on ghcr.io, and one image only containerd pulls.
alpine=library/alpine:3.20
busybox=busybox:1.36
ghcr_image=terrabyteian/flint:v0.1.1
mirrored=library/hello-world:latest
# An image that no step pulls online, so it is never cached.
uncached=library/redis:7-alpine

# metric prints the value of a flint metric sample, or 0.
metric() {
	curl -fsS "http://$reg/metrics" | awk -v s="$1" '$1 == s { print $2; found = 1 } END { if (!found) print 0 }'
}

if [ "$mode" = online ]; then
	step "Docker Hub through $hub with crane"
	want=$(command crane digest "docker.io/$alpine")
	got=$(crane digest "$reg/$hub/$alpine")
	[ "$got" = "$want" ] || fail "$hub/$alpine resolved to $got, Docker Hub to $want"
	echo "$got" >"$state/alpine.digest"
	crane pull --platform linux/amd64 "$reg/$hub/$alpine" "$work/alpine.tar"
	[ "$(crane config --platform linux/arm64 "$reg/$hub/$alpine" | jq -r .architecture)" = arm64 ] ||
		fail "the linux/arm64 config of $alpine has the wrong architecture"
	crane ls "$reg/$hub/${alpine%:*}" >"$work/tags"
	grep -qxF "${alpine#*:}" "$work/tags" || fail "the tag list of ${alpine%:*} lacks ${alpine#*:}"

	step "a single-component name gets the library/ prefix"
	want=$(command crane digest "docker.io/library/$busybox")
	got=$(crane digest "$reg/$hub/$busybox")
	[ "$got" = "$want" ] || fail "$hub/$busybox resolved to $got, Docker Hub to $want"
	echo "$got" >"$state/busybox.digest"
	crane pull --platform linux/amd64 "$reg/$hub/$busybox" "$work/busybox.tar"

	step "ghcr.io through $ghcr with crane"
	want=$(command crane digest "ghcr.io/$ghcr_image")
	got=$(crane digest "$reg/$ghcr/$ghcr_image")
	[ "$got" = "$want" ] || fail "$ghcr/$ghcr_image resolved to $got, ghcr.io to $want"
	echo "$got" >"$state/ghcr.digest"
	crane pull --platform linux/amd64 "$reg/$ghcr/$ghcr_image" "$work/ghcr.tar"

	step "pushes are refused"
	status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "http://$reg/v2/$hub/library/e2e/blobs/uploads/")
	[ "$status" = 405 ] || fail "a push to $hub answered $status, want 405"

	if docker_steps; then
		step "docker pull and run"
		docker pull "$reg/$hub/$alpine"
		[ "$(docker run --rm "$reg/$hub/$alpine" cat /etc/alpine-release | cut -d. -f1,2)" = "${alpine#*:}" ] ||
			fail "$alpine is not alpine ${alpine#*:}"
		docker pull "$reg/$hub/$busybox"
		[ "$(docker run --rm "$reg/$hub/$busybox" echo ok)" = ok ] || fail "busybox did not run"
		docker pull "$reg/$ghcr/$ghcr_image"
		[ "$(docker run --rm "$reg/$ghcr/$ghcr_image" version)" = "flint ${ghcr_image#*:}" ] ||
			fail "$ghcr_image did not run"
	fi

	if containerd_steps; then
		step "containerd pulls docker.io through $hub as a registry mirror"
		mkdir -p "$work/certs.d/docker.io"
		cat >"$work/certs.d/docker.io/hosts.toml" <<-TOML
			server = "https://registry-1.docker.io"

			[host."http://$reg/v2/$hub"]
			  capabilities = ["pull", "resolve"]
			  override_path = true
		TOML
		before=$(metric "flint_proxy_requests_total{repository=\"$hub\",result=\"fetched\"}")
		# content fetch resolves and downloads the image as a pull does,
		# without unpacking it into a snapshotter.
		sudo ctr content fetch --platform linux/amd64 --hosts-dir "$work/certs.d" "docker.io/$mirrored"
		after=$(metric "flint_proxy_requests_total{repository=\"$hub\",result=\"fetched\"}")
		[ "$after" -gt "$before" ] || fail "containerd's pull did not go through flint"
		sudo ctr images rm "docker.io/$mirrored" >/dev/null 2>&1 || true
		crane digest "$reg/$hub/$mirrored" >"$state/mirrored.digest"
	fi
	echo "OK: pulled through the proxies"
	exit 0
fi

step "flint cannot reach the upstreams"
if crane digest "$reg/$hub/$uncached" >/dev/null 2>"$work/err"; then
	fail "$hub/$uncached, never pulled, was served, so the upstream is reachable"
fi
grep -q UNAVAILABLE "$work/err" || fail "an uncached image failed without UNAVAILABLE: $(cat "$work/err")"

step "cached images are served by tag and by digest"
for name in alpine busybox ghcr mirrored; do
	case $name in
	alpine) ref=$hub/$alpine ;;
	busybox) ref=$hub/$busybox ;;
	ghcr) ref=$ghcr/$ghcr_image ;;
	mirrored)
		containerd_steps || continue
		ref=$hub/$mirrored
		;;
	esac
	want=$(cat "$state/$name.digest")
	got=$(crane digest "$reg/$ref")
	[ "$got" = "$want" ] || fail "$ref resolved to $got offline, $want online"
	crane manifest "$reg/${ref%:*}@$want" >/dev/null
	crane pull --platform linux/amd64 "$reg/$ref" "$work/$name.tar"
done

if docker_steps; then
	step "docker pull and run offline"
	docker rmi "$reg/$hub/$alpine" "$reg/$hub/$busybox" "$reg/$ghcr/$ghcr_image"
	docker pull "$reg/$hub/$alpine"
	[ "$(docker run --rm "$reg/$hub/$alpine" cat /etc/alpine-release | cut -d. -f1,2)" = "${alpine#*:}" ] ||
		fail "$alpine is not alpine ${alpine#*:}"
	docker pull "$reg/$ghcr/$ghcr_image"
	[ "$(docker run --rm "$reg/$ghcr/$ghcr_image" version)" = "flint ${ghcr_image#*:}" ] ||
		fail "$ghcr_image did not run"
fi

stale=$(metric "flint_proxy_requests_total{repository=\"$hub\",result=\"stale\"}")
[ "$stale" -gt 0 ] || fail "no pull was counted as served stale"
echo "OK: cached images served with the upstreams unreachable"
