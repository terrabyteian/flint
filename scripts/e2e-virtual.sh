#!/usr/bin/env bash
# e2e-virtual.sh pushes and pulls through a running flint OCI virtual
# repository that fronts a hosted repository and proxies of Docker Hub and
# ghcr.io, with real clients, then, in a second run after flint has been
# restarted with its upstreams unreachable, pulls again to prove that
# cached content keeps being served offline and that the unreachable
# members are skipped. It fails on the first mismatch.
#
# Usage: E2E_USERNAME=<user> E2E_PASSWORD=<secret> E2E_STATE_DIR=<dir> \
#          scripts/e2e-virtual.sh online|offline <host:port> <virtual> <hosted> <dockerhub-repo> <ghcr-repo>
#   <virtual> is a virtual repository with anonymousPull whose members are,
#   in order, the hosted repository <hosted> and the proxy repositories
#   <dockerhub-repo> and <ghcr-repo> of https://registry-1.docker.io and
#   https://ghcr.io, with publishTo <hosted>. E2E_USERNAME needs write on
#   <hosted>; it needs no role on <virtual>.
#   online   pushes through the virtual repository with crane and docker,
#            and pulls the pushed images, Docker Hub images, and a ghcr.io
#            image through it with crane, docker, and containerd (as the
#            registry mirror of both docker.io and ghcr.io).
#   offline  runs against the same data directory once flint cannot reach
#            the upstreams: it pulls the same images, by tag and by digest,
#            and checks that an image never pulled fails.
#   E2E_STATE_DIR keeps the digests the online run saw for the offline run.
# Requires crane, docker, jq, and curl on PATH, and ctr with sudo for the
# containerd mirror; set E2E_SKIP_DOCKER=1 or E2E_SKIP_CONTAINERD=1 to skip
# those steps.
set -euo pipefail

if [ $# -ne 6 ] || [ -z "${E2E_STATE_DIR:-}" ] || { [ "$1" != online ] && [ "$1" != offline ]; } ||
	[ -z "${E2E_USERNAME:-}" ] || [ -z "${E2E_PASSWORD:-}" ]; then
	echo "usage: E2E_USERNAME=<user> E2E_PASSWORD=<secret> E2E_STATE_DIR=<dir> $0 online|offline <host:port> <virtual> <hosted> <dockerhub-repo> <ghcr-repo>" >&2
	exit 2
fi
mode=$1
reg=$2
virtual=$3
hosted=$4
hub=$5
ghcr=$6
state=$E2E_STATE_DIR
mkdir -p "$state"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
# Pulls are anonymous; pushes use the logged-in configuration.
mkdir -p "$work/anonymous" "$work/login"
crane() { DOCKER_CONFIG=$work/anonymous command crane --insecure "$@"; }
crane_login() { DOCKER_CONFIG=$work/login command crane --insecure "$@"; }
docker_login() { DOCKER_CONFIG=$work/login docker "$@"; }
docker_steps() { [ "${E2E_SKIP_DOCKER:-}" != 1 ]; }
containerd_steps() { [ "${E2E_SKIP_CONTAINERD:-}" != 1 ]; }

# Images pulled through the virtual repository: Docker Hub images by their
# full and their short name, flint's own image on ghcr.io, which Docker Hub
# does not have, and images only containerd pulls.
alpine=library/alpine:3.20
busybox=busybox:1.36
ghcr_image=terrabyteian/flint:v0.1.1
mirrored_hub=library/hello-world:latest
mirrored_ghcr=terrabyteian/flint:v0.2.0
# An image that no step pulls online, so it is never cached.
uncached=library/redis:7-alpine

# metric prints the value of a flint metric sample, or 0.
metric() {
	curl -fsS "http://$reg/metrics" | awk -v s="$1" '$1 == s { print $2; found = 1 } END { if (!found) print 0 }'
}
# requests prints how many requests a proxy repository served, whatever
# their result.
requests() {
	curl -fsS "http://$reg/metrics" |
		awk -v p="flint_proxy_requests_total{repository=\"$1\"," 'index($1, p) == 1 { n += $2 } END { print n + 0 }'
}

# layer writes a one-file tar archive holding $2 to $1.
layer() {
	mkdir -p "$work/layer"
	echo "$2" >"$work/layer/content.txt"
	tar -C "$work/layer" -cf "$1" content.txt
}

# mirror_hosts writes containerd hosts.toml files that send docker.io and
# ghcr.io pulls to the virtual repository.
mirror_hosts() {
	for upstream in docker.io:https://registry-1.docker.io ghcr.io:https://ghcr.io; do
		mkdir -p "$work/certs.d/${upstream%%:*}"
		cat >"$work/certs.d/${upstream%%:*}/hosts.toml" <<-TOML
			server = "${upstream#*:}"

			[host."http://$reg/v2/$virtual"]
			  capabilities = ["pull", "resolve"]
			  override_path = true
		TOML
	done
}

# ctr_fetch fetches an image through the mirror, as a pull does, without
# unpacking it into a snapshotter.
ctr_fetch() {
	sudo ctr content fetch --platform linux/amd64 --hosts-dir "$work/certs.d" "$1" >/dev/null
	sudo ctr images rm "$1" >/dev/null 2>&1 || true
}

if [ "$mode" = online ]; then
	step "anonymous pushes through $virtual are refused"
	layer "$work/app.tar" "pushed through the virtual repository"
	if crane append --oci-empty-base -f "$work/app.tar" -t "$reg/$virtual/e2e/app:v1" >/dev/null 2>&1; then
		fail "an anonymous push through $virtual succeeded"
	fi
	printf '%s' "$E2E_PASSWORD" | crane_login auth login "$reg" -u "$E2E_USERNAME" --password-stdin

	step "crane push through $virtual lands in $hosted"
	crane_login append --oci-empty-base -f "$work/app.tar" -t "$reg/$virtual/e2e/app:v1"
	got=$(crane digest "$reg/$virtual/e2e/app:v1")
	[ "$got" = "$(crane_login digest "$reg/$hosted/e2e/app:v1")" ] || fail "e2e/app:v1 differs between $virtual and $hosted"
	echo "$got" >"$state/app.digest"
	crane pull "$reg/$virtual/e2e/app:v1" "$work/app-pulled.tar"
	crane_login copy "$reg/$virtual/e2e/app:v1" "$reg/$virtual/e2e/copy:v1"
	[ "$(crane digest "$reg/$virtual/e2e/copy:v1")" = "$got" ] || fail "the copy through $virtual differs"

	step "Docker Hub images through $virtual"
	want=$(command crane digest "docker.io/$alpine")
	got=$(crane digest "$reg/$virtual/$alpine")
	[ "$got" = "$want" ] || fail "$virtual/$alpine resolved to $got, Docker Hub to $want"
	echo "$got" >"$state/alpine.digest"
	crane pull --platform linux/amd64 "$reg/$virtual/$alpine" "$work/alpine.tar"
	crane ls "$reg/$virtual/${alpine%:*}" >"$work/tags"
	grep -qxF "${alpine#*:}" "$work/tags" || fail "the tag list of $virtual/${alpine%:*} lacks ${alpine#*:}"
	want=$(command crane digest "docker.io/library/$busybox")
	got=$(crane digest "$reg/$virtual/$busybox")
	[ "$got" = "$want" ] || fail "$virtual/$busybox resolved to $got, Docker Hub to $want"
	echo "$got" >"$state/busybox.digest"
	crane pull --platform linux/amd64 "$reg/$virtual/$busybox" "$work/busybox.tar"

	step "a ghcr.io image through $virtual, which Docker Hub does not have"
	want=$(command crane digest "ghcr.io/$ghcr_image")
	got=$(crane digest "$reg/$virtual/$ghcr_image")
	[ "$got" = "$want" ] || fail "$virtual/$ghcr_image resolved to $got, ghcr.io to $want"
	echo "$got" >"$state/ghcr.digest"
	crane pull --platform linux/amd64 "$reg/$virtual/$ghcr_image" "$work/ghcr.tar"

	step "a name $hosted owns is never served from an upstream"
	layer "$work/nginx.tar" "a first-party image named library/nginx"
	crane_login append --oci-empty-base -f "$work/nginx.tar" -t "$reg/$virtual/library/nginx:first-party"
	crane digest "$reg/$virtual/library/nginx:first-party" >/dev/null
	if crane digest "$reg/$virtual/library/nginx:latest" >/dev/null 2>"$work/err"; then
		fail "$virtual served Docker Hub's library/nginx:latest although $hosted owns library/nginx"
	fi
	grep -q MANIFEST_UNKNOWN "$work/err" || fail "the owned name failed without MANIFEST_UNKNOWN: $(cat "$work/err")"
	[ "$(crane ls "$reg/$virtual/library/nginx" | tr '\n' ' ')" = "first-party " ] ||
		fail "the tags of the owned name: $(crane ls "$reg/$virtual/library/nginx" | tr '\n' ' ')"

	if docker_steps; then
		step "docker push through $virtual, and docker pull and run"
		printf '%s' "$E2E_PASSWORD" | docker_login login "$reg" -u "$E2E_USERNAME" --password-stdin
		mkdir "$work/ctx"
		echo "built by docker" >"$work/ctx/hello.txt"
		printf 'FROM scratch\nCOPY hello.txt /\n' >"$work/ctx/Dockerfile"
		docker_login build -q -t "$reg/$virtual/e2e/docker:v1" "$work/ctx"
		docker_login push "$reg/$virtual/e2e/docker:v1"
		docker_login image rm "$reg/$virtual/e2e/docker:v1" >/dev/null
		got=$(crane digest "$reg/$virtual/e2e/docker:v1")
		[ "$got" = "$(crane_login digest "$reg/$hosted/e2e/docker:v1")" ] || fail "e2e/docker:v1 differs between $virtual and $hosted"
		echo "$got" >"$state/docker.digest"
		docker pull "$reg/$virtual/e2e/docker:v1"
		docker pull "$reg/$virtual/$alpine"
		[ "$(docker run --rm "$reg/$virtual/$alpine" cat /etc/alpine-release | cut -d. -f1,2)" = "${alpine#*:}" ] ||
			fail "$alpine is not alpine ${alpine#*:}"
		docker pull "$reg/$virtual/$ghcr_image"
		[ "$(docker run --rm "$reg/$virtual/$ghcr_image" version)" = "flint ${ghcr_image#*:}" ] ||
			fail "$ghcr_image did not run"
	fi

	if containerd_steps; then
		step "containerd pulls docker.io and ghcr.io through $virtual as their registry mirror"
		mirror_hosts
		before=$(requests "$hub")
		ctr_fetch "docker.io/$mirrored_hub"
		[ "$(requests "$hub")" -gt "$before" ] || fail "containerd's docker.io pull did not go through $hub"
		# The ns parameter sends the ghcr.io pull to the ghcr.io proxy only:
		# Docker Hub, which does not have the image, is not asked.
		before=$(requests "$ghcr")
		errors=$(metric "flint_proxy_upstream_errors_total{repository=\"$hub\"}")
		ctr_fetch "ghcr.io/$mirrored_ghcr"
		[ "$(requests "$ghcr")" -gt "$before" ] || fail "containerd's ghcr.io pull did not go through $ghcr"
		now=$(metric "flint_proxy_upstream_errors_total{repository=\"$hub\"}")
		[ "$now" = "$errors" ] || fail "containerd's ghcr.io pull asked Docker Hub"
		crane digest "$reg/$virtual/$mirrored_hub" >"$state/mirrored_hub.digest"
		crane digest "$reg/$virtual/$mirrored_ghcr" >"$state/mirrored_ghcr.digest"
	fi
	echo "OK: pushed and pulled through $virtual"
	exit 0
fi

step "flint cannot reach the upstreams"
if crane digest "$reg/$virtual/$uncached" >/dev/null 2>"$work/err"; then
	fail "$virtual/$uncached, never pulled, was served, so the upstream is reachable"
fi
grep -q UNAVAILABLE "$work/err" || fail "an uncached image failed without UNAVAILABLE: $(cat "$work/err")"

step "pushed and cached images are served by tag and by digest"
skips=$(metric "flint_virtual_member_skips_total{repository=\"$virtual\",member=\"$hub\"}")
for name in app docker alpine busybox ghcr mirrored_hub mirrored_ghcr; do
	case $name in
	app) ref=e2e/app:v1 ;;
	docker)
		docker_steps || continue
		ref=e2e/docker:v1
		;;
	alpine) ref=$alpine ;;
	busybox) ref=$busybox ;;
	ghcr) ref=$ghcr_image ;;
	mirrored_hub | mirrored_ghcr)
		containerd_steps || continue
		ref=$mirrored_hub
		[ "$name" = mirrored_ghcr ] && ref=$mirrored_ghcr
		;;
	esac
	want=$(cat "$state/$name.digest")
	got=$(crane digest "$reg/$virtual/$ref")
	[ "$got" = "$want" ] || fail "$virtual/$ref resolved to $got offline, $want online"
	crane manifest "$reg/$virtual/${ref%:*}@$want" >/dev/null
	crane pull --platform linux/amd64 "$reg/$virtual/$ref" "$work/$name.tar"
done
# The ghcr.io images were served once Docker Hub, the member before
# ghcr.io, failed.
now=$(metric "flint_virtual_member_skips_total{repository=\"$virtual\",member=\"$hub\"}")
[ "$now" -gt "$skips" ] || fail "no unreachable member of $virtual was skipped"

if docker_steps; then
	step "docker pull and run offline"
	docker rmi "$reg/$virtual/$alpine" "$reg/$virtual/$ghcr_image" "$reg/$virtual/e2e/docker:v1" >/dev/null
	docker pull "$reg/$virtual/e2e/docker:v1"
	docker pull "$reg/$virtual/$alpine"
	[ "$(docker run --rm "$reg/$virtual/$alpine" cat /etc/alpine-release | cut -d. -f1,2)" = "${alpine#*:}" ] ||
		fail "$alpine is not alpine ${alpine#*:}"
	docker pull "$reg/$virtual/$ghcr_image"
	[ "$(docker run --rm "$reg/$virtual/$ghcr_image" version)" = "flint ${ghcr_image#*:}" ] ||
		fail "$ghcr_image did not run"
fi

if containerd_steps; then
	step "containerd pulls through $virtual offline"
	mirror_hosts
	# containerd falls back to the upstream itself if flint fails, so
	# flint must have served the pulls.
	before=$(requests "$hub")
	ctr_fetch "docker.io/$mirrored_hub"
	[ "$(requests "$hub")" -gt "$before" ] || fail "containerd's offline docker.io pull did not go through $hub"
	before=$(requests "$ghcr")
	ctr_fetch "ghcr.io/$mirrored_ghcr"
	[ "$(requests "$ghcr")" -gt "$before" ] || fail "containerd's offline ghcr.io pull did not go through $ghcr"
fi
echo "OK: pushed and cached images served through $virtual with the upstreams unreachable"
