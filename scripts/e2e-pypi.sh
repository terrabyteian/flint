#!/usr/bin/env bash
# e2e-pypi.sh drives flint's PyPI repositories with real clients: it builds
# two packages with uv, publishes them to a hosted repository with twine and
# uv publish, installs them and real projects from pypi.org with pip and uv
# through the hosted, proxy, and virtual repositories, and checks file name
# reuse, yanking, deletes, and dependency-confusion protection. A second run,
# after flint has been restarted with its upstream unreachable, installs the
# same projects again to prove that cached content keeps being served
# offline. It fails on the first mismatch.
#
# Usage: E2E_STATE_DIR=<dir> E2E_TOKEN=<token> E2E_ADMIN=<user:password> \
#          scripts/e2e-pypi.sh online|offline <host:port> <hosted> <proxy> <virtual>
#   <hosted>   a hosted PyPI repository the token may upload to and read
#   <proxy>    a proxy repository of https://pypi.org with anonymousPull
#   <virtual>  a virtual repository of <hosted> and <proxy>, in that order,
#              with anonymousPull and dependency-confusion protection
#   E2E_TOKEN  an API token, sent as __token__, with write on <hosted>
#   E2E_ADMIN  credentials with the delete role on <hosted>, for yanking and
#              deleting through the admin API
#   E2E_STATE_DIR keeps what the online run built and installed for the
#   offline run.
# Requires python3 (3.9 or later) with venv, pip, uv, twine, jq, and curl on
# PATH.
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

base=http://$reg/pypi
# The hosted repository needs credentials; the others allow anonymous pulls.
hosted_index="http://__token__:$E2E_TOKEN@$reg/pypi/$hosted/simple/"
proxy_index=$base/$proxy/simple/
virtual_index=$base/$virtual/simple/
export PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PIP_NO_INPUT=1 UV_NO_CACHE=1

# Real projects installed through the proxy: requests and its dependencies,
# and attrs, which only uv installs.
proxied="requests==2.32.3"
uv_proxied="attrs==25.3.0"
# A project on pypi.org that a hosted package claims, for the
# dependency-confusion check, and one that no step installs online.
claimed=toolz
uncached=flask

# venv makes a fresh virtual environment and prints its python.
venv() {
	python3 -m venv "$work/$1"
	echo "$work/$1/bin/python"
}

# status prints the HTTP status of a request.
status() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }

# metric prints the value of a flint metric sample, or 0.
metric() {
	curl -fsS "http://$reg/metrics" | awk -v s="$1" '$1 == s { print $2; found = 1 } END { if (!found) print 0 }'
}

# upload_status publishes a file with twine and prints the HTTP status
# twine reports, or 200.
upload_status() {
	if out=$(twine upload --disable-progress-bar --non-interactive --repository-url "$base/$hosted/legacy/" \
		-u __token__ -p "$E2E_TOKEN" "$@" 2>&1); then
		echo 200
	else
		echo "$out" | grep -oE 'HTTPError: [0-9]{3}' | head -n 1 | cut -d' ' -f2
	fi
}

# build makes a wheel and an sdist of package flint-e2e-<name> at version,
# depending on six, in $work/dist-<name>-<version>. uv installs the build
# backend through the virtual repository.
build() {
	local name=$1 version=$2 src=$work/src-$1-$2
	mkdir -p "$src/src/flint_e2e_$name"
	cat >"$src/pyproject.toml" <<-TOML
		[build-system]
		requires = ["hatchling"]
		build-backend = "hatchling.build"

		[project]
		name = "flint-e2e-$name"
		version = "$version"
		description = "flint end-to-end test package $name"
		requires-python = ">=3.9"
		dependencies = ["six>=1.16"]
	TOML
	echo "VERSION = \"$version\"" >"$src/src/flint_e2e_$name/__init__.py"
	UV_DEFAULT_INDEX=$virtual_index uv build --quiet --out-dir "$work/dist-$name-$version" "$src"
}

if [ "$mode" = online ]; then
	step "pip installs from pypi.org through $proxy, byte for byte"
	sha=$(curl -fsS https://pypi.org/pypi/six/1.17.0/json |
		jq -r '.urls[] | select(.packagetype == "bdist_wheel") | .digests.sha256')
	echo "six==1.17.0 --hash=sha256:$sha" >"$work/pinned.txt"
	py=$(venv pinned)
	"$py" -m pip install --quiet --require-hashes --index-url "$proxy_index" -r "$work/pinned.txt"
	py=$(venv proxy)
	"$py" -m pip install --quiet --index-url "$proxy_index" "$proxied"
	"$py" -c 'import requests' || fail "requests did not install through $proxy"
	echo "$proxied" >"$state/proxied"

	step "uv installs through $proxy"
	py=$(venv uv-proxy)
	uv pip install --quiet --python "$py" --index-url "$proxy_index" "$uv_proxied"
	"$py" -c 'import attrs' || fail "attrs did not install through $proxy"
	echo "$uv_proxied" >"$state/uv-proxied"

	step "the JSON API through $proxy"
	[ "$(curl -fsS "$base/$proxy/pypi/six/1.17.0/json" | jq -r .info.name)" = six ] ||
		fail "the JSON API of $proxy does not describe six"

	step "build packages with uv through $virtual"
	build hello 0.1.0
	build hello 0.2.0
	build hello 0.3.0
	cp -r "$work"/dist-hello-0.1.0 "$state/"

	step "twine publishes to $hosted"
	[ "$(upload_status "$work"/dist-hello-0.1.0/*)" = 200 ] || fail "twine could not publish 0.1.0"
	step "uv publishes to $hosted"
	uv publish --quiet --publish-url "$base/$hosted/legacy/" -u __token__ -p "$E2E_TOKEN" "$work"/dist-hello-0.2.0/* ||
		fail "uv publish could not publish 0.2.0"
	twine upload --disable-progress-bar --repository-url "$base/$hosted/legacy/" -u __token__ -p "$E2E_TOKEN" \
		"$work"/dist-hello-0.3.0/*.whl >/dev/null

	step "publishing the same file again succeeds; other content under its name is refused"
	[ "$(upload_status "$work"/dist-hello-0.1.0/*.whl)" = 200 ] || fail "republishing the same file failed"
	sed -i.bak 's/end-to-end test package/changed package/' "$work/src-hello-0.1.0/pyproject.toml"
	UV_DEFAULT_INDEX=$virtual_index uv build --quiet --wheel --out-dir "$work/changed" "$work/src-hello-0.1.0"
	[ "$(upload_status "$work"/changed/*.whl)" = 409 ] || fail "a changed file under a used name was not refused with 409"

	step "uploads to $proxy and $virtual are refused"
	for repo in "$proxy" "$virtual"; do
		code=$(status -u "__token__:$E2E_TOKEN" -F ':action=file_upload' -F name=x -F version=1 "$base/$repo/legacy/")
		[ "$code" = 405 ] || fail "an upload to $repo answered $code, want 405"
	done

	step "pip and uv install from $hosted"
	py=$(venv hosted)
	"$py" -m pip install --quiet --no-deps --index-url "$hosted_index" flint-e2e-hello
	[ "$("$py" -c 'import flint_e2e_hello; print(flint_e2e_hello.VERSION)')" = 0.3.0 ] ||
		fail "pip did not install the latest version from $hosted"
	py=$(venv hosted-uv)
	uv pip install --quiet --python "$py" --no-deps --index-url "$hosted_index" flint-e2e-hello==0.1.0
	[ "$("$py" -c 'import flint_e2e_hello; print(flint_e2e_hello.VERSION)')" = 0.1.0 ] ||
		fail "uv did not install 0.1.0 from $hosted"
	[ "$(status "$base/$hosted/simple/flint-e2e-hello/")" = 401 ] || fail "$hosted answered an anonymous client"

	step "pip and uv install through $virtual, with dependencies from $proxy"
	py=$(venv virtual)
	"$py" -m pip install --quiet --index-url "$virtual_index" flint-e2e-hello
	"$py" -c 'import flint_e2e_hello, six' || fail "pip did not install through $virtual"
	py=$(venv virtual-uv)
	uv pip install --quiet --python "$py" --index-url "$virtual_index" flint-e2e-hello
	"$py" -c 'import flint_e2e_hello, six' || fail "uv did not install through $virtual"
	[ "$(curl -fsS "$base/$virtual/pypi/flint-e2e-hello/json" | jq -r .info.version)" = 0.3.0 ] ||
		fail "the JSON API of $virtual does not report 0.3.0"

	step "yanked releases are skipped unless pinned"
	curl -fsS -u "$E2E_ADMIN" -X PUT "http://$reg/api/v1/pypi/$hosted/projects/flint-e2e-hello/releases/0.3.0/yank" \
		-d '{"reason": "e2e"}' >/dev/null
	py=$(venv yanked)
	"$py" -m pip install --quiet --no-deps --index-url "$virtual_index" flint-e2e-hello
	[ "$("$py" -c 'import flint_e2e_hello; print(flint_e2e_hello.VERSION)')" = 0.2.0 ] || fail "pip installed a yanked release"
	"$py" -m pip install --quiet --no-deps --index-url "$virtual_index" flint-e2e-hello==0.3.0
	[ "$("$py" -c 'import flint_e2e_hello; print(flint_e2e_hello.VERSION)')" = 0.3.0 ] || fail "pip refused a pinned yanked release"

	step "a deleted file's name can never be used again"
	whl=$(basename "$work"/dist-hello-0.2.0/*.whl)
	curl -fsS -u "$E2E_ADMIN" -X DELETE "http://$reg/api/v1/pypi/$hosted/projects/flint-e2e-hello/files/$whl" >/dev/null
	[ "$(status "$base/$virtual/files/flint-e2e-hello/$whl")" = 404 ] || fail "a deleted file is still served"
	[ "$(upload_status "$work"/dist-hello-0.2.0/*.whl)" = 409 ] || fail "a deleted file name was reused"

	step "dependency-confusion protection: $claimed in $hosted hides pypi.org's"
	upstream_versions=$(curl -fsS -H 'Accept: application/vnd.pypi.simple.v1+json' "$proxy_index$claimed/" | jq '.versions | length')
	[ "$upstream_versions" -gt 1 ] || fail "$proxy lists no versions of $claimed"
	mkdir -p "$work/claimed/src/$claimed"
	cat >"$work/claimed/pyproject.toml" <<-TOML
		[build-system]
		requires = ["hatchling"]
		build-backend = "hatchling.build"

		[project]
		name = "$claimed"
		version = "0.0.1"
	TOML
	echo 'OWNER = "flint"' >"$work/claimed/src/$claimed/__init__.py"
	UV_DEFAULT_INDEX=$virtual_index uv build --quiet --wheel --out-dir "$work/claimed/dist" "$work/claimed"
	[ "$(upload_status "$work"/claimed/dist/*.whl)" = 200 ] || fail "could not publish $claimed"
	[ "$(curl -fsS -H 'Accept: application/vnd.pypi.simple.v1+json' "$virtual_index$claimed/" | jq -c .versions)" = '["0.0.1"]' ] ||
		fail "$virtual serves pypi.org's versions of $claimed"
	py=$(venv claimed)
	"$py" -m pip install --quiet --index-url "$virtual_index" "$claimed"
	[ "$("$py" -c "import $claimed; print($claimed.OWNER)")" = flint ] || fail "pip installed pypi.org's $claimed"

	echo "OK: published, installed, and proxied"
	exit 0
fi

step "flint answers with its upstream unreachable"
[ "$(status "$proxy_index$uncached/")" = 503 ] || fail "$uncached, never cached, did not fail with 503"

step "pip installs through $proxy and $virtual from the cache"
for index in "$proxy_index" "$virtual_index"; do
	py=$(venv "offline-$(basename "$(dirname "$index")")")
	"$py" -m pip install --quiet --index-url "$index" "$(cat "$state/proxied")"
	"$py" -c 'import requests' || fail "requests did not install offline through $index"
done

step "uv installs through $proxy from the cache"
py=$(venv offline-uv)
uv pip install --quiet --python "$py" --index-url "$proxy_index" "$(cat "$state/uv-proxied")"
"$py" -c 'import attrs' || fail "attrs did not install offline"

step "hosted packages install through $virtual, with cached dependencies"
py=$(venv offline-hosted)
uv pip install --quiet --python "$py" --index-url "$virtual_index" flint-e2e-hello==0.1.0
"$py" -c 'import flint_e2e_hello, six' || fail "the hosted package did not install offline"
[ "$(upload_status "$state"/dist-hello-0.1.0/*.whl)" = 200 ] || fail "republishing offline failed"

step "a project never cached fails"
py=$(venv offline-uncached)
if "$py" -m pip install --quiet --index-url "$proxy_index" "$uncached" 2>/dev/null; then
	fail "$uncached installed with the upstream unreachable"
fi
stale=$(metric "flint_proxy_requests_total{repository=\"$proxy\",result=\"stale\"}")
[ "${stale%.*}" -gt 0 ] || fail "no project page was served stale"
echo "OK: served from the cache"
