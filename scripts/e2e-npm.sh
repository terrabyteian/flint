#!/usr/bin/env bash
# e2e-npm.sh drives a hosted npm repository of flint with real clients: npm
# publishes a scoped and an unscoped package with a token in .npmrc, then
# runs dist-tag add, ls, and rm, deprecate, unpublish of one version and of
# a whole package, whoami, search, audit, and the legacy npm login, and
# proves that a version is never published twice, not even after it was
# unpublished. npm installs the packages from a lockfile, which must record
# flint's tarball URLs, and npm ci installs them again; pnpm, Yarn classic,
# Yarn Berry, and Bun install them and publish a package of their own too,
# each when named in E2E_CLIENTS. It fails on the first mismatch.
#
# Usage: E2E_TOKEN=<token> E2E_USERNAME=<user> E2E_PASSWORD=<password> \
#          scripts/e2e-npm.sh <host:port> <hosted>
#   <hosted>      a hosted npm repository without anonymousPull
#   E2E_TOKEN     an API token of E2E_USERNAME, who has the delete role on
#                 <hosted>
#   E2E_PASSWORD  E2E_USERNAME's password, for npm login
#   E2E_CLIENTS   the other clients to install and publish with, of: pnpm, yarn (Yarn
#                 classic), yarn-berry, bun. Yarn Berry runs as the command
#                 in E2E_YARN_BERRY, by default yarn-berry.
# Requires node, npm, python3 (for npm login's prompts), jq, and curl on
# PATH, and the clients E2E_CLIENTS names.
set -euo pipefail

if [ $# -ne 2 ] || [ -z "${E2E_TOKEN:-}" ] || [ -z "${E2E_USERNAME:-}" ] || [ -z "${E2E_PASSWORD:-}" ]; then
	echo "usage: E2E_TOKEN=<token> E2E_USERNAME=<user> E2E_PASSWORD=<password> $0 <host:port> <hosted>" >&2
	exit 2
fi
reg=$1
hosted=$2
clients=" ${E2E_CLIENTS:-} "
yarn_berry=${E2E_YARN_BERRY:-yarn-berry}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

registry=http://$reg/npm/$hosted/
# Names unique to the run, so the script can run again against one server.
run=$(date +%s)-$RANDOM
plain=flint-e2e-plain-$run
scoped=@flint-e2e/lib-$run
escaped=${scoped/\//%2f}

# Every npm command reads $work/.npmrc, with the registry and the token,
# and keeps its cache in $work, so nothing is shared with the user's own.
export npm_config_userconfig=$work/.npmrc npm_config_cache=$work/npm-cache npm_config_update_notifier=false \
	npm_config_fund=false
cat >"$work/.npmrc" <<EOF
registry=$registry
//$reg/npm/$hosted/:_authToken=$E2E_TOKEN
EOF

# status prints the HTTP status of a request.
status() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }
auth=(-H "Authorization: Bearer $E2E_TOKEN")

# package writes package $1 at version $2 into $work/src-$1-$2, with the
# dependencies of $3, a JSON object, and prints its directory.
package() {
	local dir=$work/src-${1//\//-}-$2 deps=${3:-"{}"}
	mkdir -p "$dir"
	cat >"$dir/package.json" <<-EOF
		{"name": "$1", "version": "$2", "description": "flint end-to-end test package", "main": "index.js",
		 "license": "MIT", "dependencies": $deps}
	EOF
	echo "module.exports = '$1@$2';" >"$dir/index.js"
	echo "# $1" >"$dir/README.md"
	echo "$dir"
}

# publish publishes the package in directory $1 with npm, with any further
# arguments.
publish() {
	(cd "$1" && shift && npm publish --loglevel=error "$@" >/dev/null)
}

# packument prints the full packument of package $1.
packument() { curl -fsS "${auth[@]}" "$registry${1/\//%2f}"; }

step "npm $(npm --version): whoami with the token"
[ "$(npm whoami)" = "$E2E_USERNAME" ] || fail "npm whoami did not name $E2E_USERNAME"

step "npm publishes $plain and $scoped"
publish "$(package "$plain" 1.0.0)"
publish "$(package "$plain" 1.1.0)"
publish "$(package "$plain" 2.0.0-beta.1)" --tag next
publish "$(package "$scoped" 1.0.0 "{\"$plain\": \"^1.0.0\"}")"
publish "$(package "$scoped" 1.0.1 "{\"$plain\": \"^1.0.0\"}")"
doc=$(packument "$plain")
[ "$(jq -r '."dist-tags" | "\(.latest) \(.next)"' <<<"$doc")" = "1.1.0 2.0.0-beta.1" ] ||
	fail "the dist-tags of $plain are $(jq -c '."dist-tags"' <<<"$doc")"
[ "$(jq -r '.versions["1.0.0"].dist.tarball' <<<"$doc")" = "$registry$plain/-/$plain-1.0.0.tgz" ] ||
	fail "the tarball URL of $plain@1.0.0 is $(jq -r '.versions["1.0.0"].dist.tarball' <<<"$doc")"
[ "$(npm view "$scoped" version)" = 1.0.1 ] || fail "npm view does not show $scoped@1.0.1"
[ "$(status "$registry$plain")" = 401 ] || fail "$hosted answered an anonymous client"

step "publishing a version that is published fails"
if publish "$(package "$plain" 1.0.0)" 2>/dev/null; then
	fail "npm published $plain@1.0.0 twice"
fi
# The registry itself refuses it, whatever the client checks first.
dup=$(cd "$work/src-$plain-1.0.0" && npm pack --silent --pack-destination "$work")
body=$(jq -n --arg name "$plain" --arg data "$(base64 <"$work/$dup" | tr -d '\n')" \
	'{name: $name, "dist-tags": {latest: "1.0.0"}, versions: {"1.0.0": {name: $name, version: "1.0.0"}},
	  _attachments: {($name + "-1.0.0.tgz"): {data: $data}}}')
code=$(status "${auth[@]}" -X PUT -H 'Content-Type: application/json' --data-binary "$body" "$registry$plain")
[ "$code" = 409 ] || fail "a duplicate publish answered $code, want 409"

step "npm dist-tag add, ls, and rm"
npm dist-tag add "$plain@1.0.0" stable >/dev/null
tags=$(npm dist-tag ls "$plain")
grep -qx 'stable: 1.0.0' <<<"$tags" || fail "dist-tag ls shows no stable tag: $tags"
grep -qx 'latest: 1.1.0' <<<"$tags" || fail "dist-tag ls shows no latest tag: $tags"
npm dist-tag rm "$plain" stable >/dev/null
if npm dist-tag ls "$plain" | grep -q '^stable:'; then fail "dist-tag rm left the stable tag"; fi
if npm dist-tag rm "$plain" latest >/dev/null 2>&1; then fail "the latest tag was removed"; fi

step "npm deprecate and undeprecate"
npm deprecate "$plain@1.0.0" "use 1.1.0" >/dev/null
[ "$(npm view "$plain@1.0.0" deprecated)" = "use 1.1.0" ] || fail "npm deprecate did not deprecate $plain@1.0.0"
npm deprecate "$scoped@1.0.0" "old" >/dev/null
npm deprecate "$scoped@1.0.0" "" >/dev/null
[ -z "$(npm view "$scoped@1.0.0" deprecated)" ] || fail "npm deprecate did not undeprecate $scoped@1.0.0"

step "npm search and ping"
npm search --parseable "$plain" | grep -q "^$plain" || fail "npm search did not find $plain"
npm ping >/dev/null 2>&1 || fail "npm ping failed"

step "npm installs from a lockfile with flint's tarball URLs, and npm ci again"
app=$work/app
mkdir -p "$app"
cat >"$app/package.json" <<EOF
{"name": "app", "version": "1.0.0", "private": true, "dependencies": {"$scoped": "1.0.1"}}
EOF
(cd "$app" && npm install --loglevel=error >/dev/null)
urls=$(jq -r '.packages | to_entries[] | select(.key != "") | .value.resolved' "$app/package-lock.json")
[ "$(wc -l <<<"$urls")" -eq 2 ] || fail "the lockfile resolves $(wc -l <<<"$urls") packages, want 2"
while read -r url; do
	[[ $url == "$registry"* ]] || fail "the lockfile has a tarball URL not at flint: $url"
done <<<"$urls"
# check checks that the app in directory $1 has the versions installed
# that the registry should resolve; $2 names the installer. The dependency
# of the scoped package is resolved from it, as clients such as pnpm do
# not hoist it.
check() {
	(cd "$1" && node -e "
		const dep = require.resolve('$plain', {paths: [require.resolve('$scoped')]});
		const got = require('$scoped') + ' ' + require(dep);
		if (got !== '$scoped@1.0.1 $plain@1.1.0') { console.error(got); process.exit(1) }") ||
		fail "$2 installed the wrong versions in $1"
}
check "$app" "npm install"
cp "$app/package.json" "$app/package-lock.json" "$work/" && rm -rf "$app" && mkdir -p "$app" &&
	mv "$work/package.json" "$work/package-lock.json" "$app/"
(cd "$app" && npm_config_cache=$work/npm-ci-cache npm ci --loglevel=error >/dev/null)
check "$app" "npm ci"

step "npm audit"
(cd "$app" && npm audit >/dev/null) || fail "npm audit failed"

# client_dir makes $work/app-$1, for another client to install the app
# in, and prints it.
client_dir() {
	local dir=$work/app-$1
	mkdir -p "$dir"
	cp "$app/package.json" "$dir/"
	cp "$work/.npmrc" "$dir/.npmrc"
	echo "$dir"
}
if [[ $clients == *" pnpm "* ]]; then
	step "pnpm $(pnpm --version) installs"
	dir=$(client_dir pnpm)
	# pnpm holds back versions published less than a day ago by default,
	# as every version here is.
	(cd "$dir" && pnpm install --reporter=silent --store-dir "$work/pnpm-store" --config.minimum-release-age=0)
	check "$dir" "pnpm install"
fi
if [[ $clients == *" yarn "* ]]; then
	step "Yarn $(yarn --version) installs"
	dir=$(client_dir yarn)
	# Yarn classic sends the token for unscoped packages only with this.
	echo "always-auth=true" >>"$dir/.npmrc"
	(cd "$dir" && yarn install --silent --non-interactive --cache-folder "$work/yarn-cache")
	check "$dir" "yarn install"
	grep -E '^  resolved ' "$dir/yarn.lock" | grep -v "\"$registry" &&
		fail "yarn.lock has a tarball URL not at flint"
fi
if [[ $clients == *" yarn-berry "* ]]; then
	step "Yarn $($yarn_berry --version) installs"
	dir=$(client_dir berry)
	rm "$dir/.npmrc"
	# Like pnpm, Yarn holds back versions published less than a day ago.
	cat >"$dir/.yarnrc.yml" <<EOF
npmRegistryServer: "$registry"
npmAuthToken: "$E2E_TOKEN"
npmAlwaysAuth: true
npmMinimalAgeGate: 0
unsafeHttpWhitelist: ["${reg%:*}"]
nodeLinker: node-modules
enableGlobalCache: false
cacheFolder: "$work/berry-cache"
EOF
	touch "$dir/yarn.lock"
	out=$(cd "$dir" && $yarn_berry install 2>&1) || {
		echo "$out"
		fail "yarn berry install failed"
	}
	check "$dir" "yarn berry install"
fi
if [[ $clients == *" bun "* ]]; then
	step "Bun $(bun --version) installs"
	dir=$(client_dir bun)
	(cd "$dir" && BUN_INSTALL_CACHE_DIR=$work/bun-cache bun install --silent)
	check "$dir" "bun install"
fi

# published checks that package $1@1.0.0 is published, as $2 published
# it.
published() {
	[ "$(npm view "$1@1.0.0" version 2>/dev/null)" = 1.0.0 ] || fail "$2 did not publish $1"
	[ "$(status "${auth[@]}" "$registry$1/-/$1-1.0.0.tgz")" = 200 ] || fail "the tarball $2 published is not served"
}
if [[ $clients == *" pnpm "* ]]; then
	step "pnpm publishes"
	dir=$(package "flint-e2e-pnpm-$run" 1.0.0)
	cp "$work/.npmrc" "$dir/"
	(cd "$dir" && pnpm publish --no-git-checks >/dev/null)
	published "flint-e2e-pnpm-$run" "pnpm publish"
fi
if [[ $clients == *" yarn "* ]]; then
	step "Yarn classic publishes"
	dir=$(package "flint-e2e-yarn-$run" 1.0.0)
	cp "$work/.npmrc" "$dir/"
	echo "always-auth=true" >>"$dir/.npmrc"
	(cd "$dir" && yarn publish --non-interactive --new-version 1.0.0 --silent >/dev/null)
	published "flint-e2e-yarn-$run" "yarn publish"
fi
if [[ $clients == *" yarn-berry "* ]]; then
	step "Yarn Berry publishes"
	dir=$(package "flint-e2e-berry-$run" 1.0.0)
	cp "$work/app-berry/.yarnrc.yml" "$dir/"
	touch "$dir/yarn.lock"
	(cd "$dir" && $yarn_berry install >/dev/null && $yarn_berry npm publish >/dev/null)
	published "flint-e2e-berry-$run" "yarn npm publish"
fi
if [[ $clients == *" bun "* ]]; then
	step "Bun publishes"
	dir=$(package "flint-e2e-bun-$run" 1.0.0)
	cp "$work/.npmrc" "$dir/"
	(cd "$dir" && bun publish --silent >/dev/null)
	published "flint-e2e-bun-$run" "bun publish"
fi

step "npm unpublish of one version, which can never be published again"
npm unpublish "$plain@1.1.0" >/dev/null
doc=$(packument "$plain")
[ "$(jq -r '.versions | keys | join(" ")' <<<"$doc")" = "1.0.0 2.0.0-beta.1" ] ||
	fail "after unpublishing 1.1.0, $plain has versions $(jq -c '.versions | keys' <<<"$doc")"
[ "$(jq -r '."dist-tags".latest' <<<"$doc")" = 1.0.0 ] || fail "latest did not move to 1.0.0"
[ "$(status "${auth[@]}" "$registry$plain/-/$plain-1.1.0.tgz")" = 404 ] || fail "the unpublished tarball is served"
if publish "$work/src-$plain-1.1.0" 2>/dev/null; then
	fail "npm published the unpublished $plain@1.1.0 again"
fi

step "npm unpublish of a whole package"
npm unpublish "$scoped" --force >/dev/null
[ "$(status "${auth[@]}" "$registry$escaped")" = 404 ] || fail "$scoped is still served"
if publish "$work/src-${scoped//\//-}-1.0.1" 2>/dev/null; then
	fail "npm published the unpublished $scoped@1.0.1 again"
fi

# npm login tries the web login first, which flint does not offer, and
# falls back to asking for a user name and password.
step "npm login with a password mints a token"
login=$work/login
mkdir -p "$login"
echo "registry=$registry" >"$login/.npmrc"
cat >"$work/login.py" <<'EOF'
# login.py runs a command in a pseudo-terminal and answers its user name
# and password prompts, as a user would answer npm login's.
import os, pty, sys
user, password, args = sys.argv[1], sys.argv[2], sys.argv[3:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(args[0], args)
seen, answers = b"", [(b"Username:", user), (b"Password:", password)]
while True:
    try:
        chunk = os.read(fd, 1024)
    except OSError:
        break
    if not chunk:
        break
    seen += chunk
    if answers and answers[0][0] in seen:
        os.write(fd, answers.pop(0)[1].encode() + b"\r")
        seen = b""
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
EOF
npm_config_userconfig=$login/.npmrc python3 "$work/login.py" "$E2E_USERNAME" "$E2E_PASSWORD" \
	npm login >/dev/null || fail "npm login failed"
grep -q "^//$reg/npm/$hosted/:_authToken=flint_" "$login/.npmrc" || fail "npm login stored no token"
[ "$(npm_config_userconfig=$login/.npmrc npm whoami)" = "$E2E_USERNAME" ] || fail "npm whoami after login did not name $E2E_USERNAME"
curl -fsS -u "$E2E_USERNAME:$E2E_PASSWORD" "http://$reg/api/v1/tokens" |
	jq -e '[.[] | select(.name | startswith("npm login "))] | length > 0' >/dev/null ||
	fail "the token npm login minted is not listed"
if npm_config_userconfig=$login/.npmrc python3 "$work/login.py" "$E2E_USERNAME" wrong-password \
	npm login >/dev/null 2>&1; then
	fail "npm login succeeded with a wrong password"
fi

echo "OK: npm end to end"
