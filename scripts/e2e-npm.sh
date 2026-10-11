#!/usr/bin/env bash
# e2e-npm.sh drives flint's npm repositories with real clients.
#
# Hosted: npm publishes a scoped and an unscoped package with a token in
# .npmrc, then runs dist-tag add, ls, and rm, deprecate, unpublish of one
# version and of a whole package, whoami, search, audit, and the legacy
# npm login, and proves that a version is never published twice, not even
# after it was unpublished. npm installs the packages from a lockfile,
# which must record flint's tarball URLs, and npm ci installs them again;
# pnpm, Yarn classic, Yarn Berry, and Bun install them and publish a
# package of their own too, each when named in E2E_CLIENTS.
#
# Proxy and virtual: npm installs public packages from registry.npmjs.org
# through a proxy repository, verifying their registry signatures, and an
# app of a hosted package and public packages through a virtual
# repository, as do the clients of E2E_CLIENTS, each lockfile recording
# only flint's tarball URLs; npm ci installs it again from its lockfile,
# and npm publishes through the virtual repository. Dependency confusion:
# a second hosted repository plays a malicious upstream, with a higher
# version of a name the hosted repository owns and a package in an
# internal scope; through a virtual repository whose proxy member caches
# it and excludes that scope, the hosted version wins, and the excluded
# scope never reaches the fake upstream.
#
# A second run, after flint has been restarted with its upstream
# unreachable, installs the apps again from their lockfiles with empty
# caches, to prove that cached content keeps being served offline. It
# fails on the first mismatch.
#
# Usage: E2E_STATE_DIR=<dir> E2E_TOKEN=<token> E2E_USERNAME=<user> E2E_PASSWORD=<password> \
#          scripts/e2e-npm.sh online|offline <host:port> <hosted> <proxy> <virtual> <decoy> <decoy-proxy> <guarded>
#   <hosted>       a hosted npm repository without anonymousPull
#   <proxy>        a proxy repository of https://registry.npmjs.org/ with
#                  anonymousPull
#   <virtual>      a virtual repository of <hosted> and <proxy>, in that
#                  order, without anonymousPull, publishing to <hosted>
#   <decoy>        a hosted repository with anonymousPull, which plays a
#                  malicious upstream
#   <decoy-proxy>  a proxy repository of <decoy>'s registry URL
#   <guarded>      a virtual repository of <hosted> and <decoy-proxy>, in
#                  that order, with dependency-confusion protection, whose
#                  <decoy-proxy> member excludes "@flint-internal/*"
#   E2E_TOKEN      an API token of E2E_USERNAME, who has the delete role on
#                  <hosted>, write on <decoy>, and read on <virtual> and
#                  <guarded>
#   E2E_PASSWORD   E2E_USERNAME's password, for npm login
#   E2E_STATE_DIR  keeps what the online run installed for the offline run
#   E2E_CLIENTS    the other clients to install and publish with, of: pnpm, yarn (Yarn
#                  classic), yarn-berry, bun. Yarn Berry runs as the command
#                  in E2E_YARN_BERRY, by default yarn-berry.
# Requires node, npm, python3 (for npm login's prompts), jq, and curl on
# PATH, and the clients E2E_CLIENTS names.
set -euo pipefail

if [ $# -ne 8 ] || [ -z "${E2E_STATE_DIR:-}" ] || [ -z "${E2E_TOKEN:-}" ] || [ -z "${E2E_USERNAME:-}" ] ||
	[ -z "${E2E_PASSWORD:-}" ] || { [ "$1" != online ] && [ "$1" != offline ]; }; then
	echo "usage: E2E_STATE_DIR=<dir> E2E_TOKEN=<token> E2E_USERNAME=<user> E2E_PASSWORD=<password> $0 online|offline <host:port> <hosted> <proxy> <virtual> <decoy> <decoy-proxy> <guarded>" >&2
	exit 2
fi
mode=$1
reg=$2
hosted=$3
proxy=$4
virtual=$5
decoy=$6
decoy_proxy=$7
guarded=$8
state=$E2E_STATE_DIR
mkdir -p "$state"
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

# Every npm command reads $work/.npmrc, with the registry and the token
# for each repository, and keeps its cache in $work, so nothing is shared
# with the user's own.
export npm_config_userconfig=$work/.npmrc npm_config_cache=$work/npm-cache npm_config_update_notifier=false \
	npm_config_fund=false
{
	echo "registry=$registry"
	for r in "$hosted" "$proxy" "$virtual" "$decoy" "$guarded"; do
		echo "//$reg/npm/$r/:_authToken=$E2E_TOKEN"
	done
} >"$work/.npmrc"

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

proxy_registry=http://$reg/npm/$proxy/
virtual_registry=http://$reg/npm/$virtual/
decoy_registry=http://$reg/npm/$decoy/
guarded_registry=http://$reg/npm/$guarded/

# metric prints the value of a flint metric sample, or 0.
metric() {
	curl -fsS "http://$reg/metrics" | awk -v s="$1" '$1 == s { print $2; found = 1 } END { if (!found) print 0 }'
}

# The public packages the proxy and virtual apps install from
# registry.npmjs.org, pinned; debug brings ms 2.1.2.
public='"debug": "4.3.4", "is-number": "7.0.0", "@isaacs/string-locale-compare": "1.1.0"'

# make_app writes an app into directory $1 with the dependencies of $2,
# JSON object members, and an .npmrc with registry $3 and every token.
make_app() {
	mkdir -p "$1"
	echo "{\"name\": \"app\", \"version\": \"1.0.0\", \"private\": true, \"dependencies\": {$2}}" >"$1/package.json"
	{
		echo "registry=$3"
		grep '_authToken=' "$work/.npmrc"
	} >"$1/.npmrc"
}

# resolved checks that the npm lockfile in directory $1 resolves $3
# packages, every tarball URL below registry URL $2.
resolved() {
	local urls
	urls=$(jq -r '.packages | to_entries[] | select(.key != "") | .value.resolved' "$1/package-lock.json")
	[ "$(wc -l <<<"$urls")" -eq "$3" ] || fail "the lockfile in $1 resolves $(wc -l <<<"$urls") packages, want $3"
	while read -r url; do
		[[ $url == "$2"* ]] || fail "the lockfile in $1 has a tarball URL not at $2: $url"
	done <<<"$urls"
}

# check_app checks that the app in directory $1 has the public packages
# installed, and the hosted package $3@1.0.0 if $3 is set; $2 names the
# installer. Dependencies are resolved from their dependents, as clients
# such as pnpm do not hoist them.
check_app() {
	local dep=${3:-}
	(cd "$1" && node -e "
		const version = (p, from) => require(require.resolve(p + '/package.json', {paths: [from || process.cwd()]})).version;
		const got = [version('debug'), version('is-number'), version('@isaacs/string-locale-compare'),
			version('ms', require.resolve('debug'))];
		const want = ['4.3.4', '7.0.0', '1.1.0', '2.1.2'];
		if ('$dep') {
			got.push(require('$dep'), version('is-number', require.resolve('$dep')));
			want.push('$dep@1.0.0', '7.0.0');
		}
		if (got.join(' ') !== want.join(' ')) { console.error(got.join(' ')); process.exit(1) }") ||
		fail "$2 installed the wrong versions in $1"
}

# berry_config writes the .yarnrc.yml of Yarn Berry for registry $2 into
# directory $1, with its cache in $3.
berry_config() {
	# Yarn holds back versions published less than a day ago by default.
	cat >"$1/.yarnrc.yml" <<-YML
		npmRegistryServer: "$2"
		npmAuthToken: "$E2E_TOKEN"
		npmAlwaysAuth: true
		npmMinimalAgeGate: 0
		unsafeHttpWhitelist: ["${reg%:*}"]
		nodeLinker: node-modules
		enableGlobalCache: false
		cacheFolder: "$3"
	YML
}

if [ "$mode" = offline ]; then
	# Every public package was cached by the online run, so the apps
	# install again from their lockfiles with empty caches, while a public
	# package that was never fetched fails.
	step "the upstream is unreachable"
	code=$(status "${proxy_registry}left-pad")
	[ "$code" = 503 ] || fail "a package the proxy never cached answered $code with the upstream unreachable, want 503"
	vdep=$(cat "$state/vdep")

	step "npm ci through $proxy and $virtual again, with empty caches"
	cp -r "$state/papp" "$state/vapp-npm" "$work/"
	(cd "$work/papp" && npm_config_cache=$work/cache-papp npm ci --loglevel=error >/dev/null)
	check_app "$work/papp" "npm ci through $proxy"
	(cd "$work/vapp-npm" && npm_config_cache=$work/cache-vapp npm ci --loglevel=error >/dev/null)
	check_app "$work/vapp-npm" "npm ci through $virtual" "$vdep"
	if [[ $clients == *" pnpm "* ]]; then
		step "pnpm installs again from its lockfile"
		cp -r "$state/vapp-pnpm" "$work/"
		(cd "$work/vapp-pnpm" && pnpm install --frozen-lockfile --reporter=silent --store-dir "$work/pnpm-store-offline" \
			--config.minimum-release-age=0)
		check_app "$work/vapp-pnpm" "pnpm install" "$vdep"
	fi
	if [[ $clients == *" yarn "* ]]; then
		step "Yarn classic installs again from its lockfile"
		cp -r "$state/vapp-yarn" "$work/"
		(cd "$work/vapp-yarn" && yarn install --frozen-lockfile --silent --non-interactive --cache-folder "$work/yarn-cache-offline")
		check_app "$work/vapp-yarn" "yarn install" "$vdep"
	fi
	if [[ $clients == *" yarn-berry "* ]]; then
		step "Yarn Berry installs again from its lockfile"
		cp -r "$state/vapp-berry" "$work/"
		berry_config "$work/vapp-berry" "$virtual_registry" "$work/berry-cache-offline"
		out=$(cd "$work/vapp-berry" && $yarn_berry install --immutable 2>&1) || {
			echo "$out"
			fail "yarn berry install failed"
		}
		check_app "$work/vapp-berry" "yarn berry install" "$vdep"
	fi
	if [[ $clients == *" bun "* ]]; then
		step "Bun installs again from its lockfile"
		cp -r "$state/vapp-bun" "$work/"
		(cd "$work/vapp-bun" && BUN_INSTALL_CACHE_DIR=$work/bun-cache-offline bun install --frozen-lockfile --silent)
		check_app "$work/vapp-bun" "bun install" "$vdep"
	fi
	echo "OK: npm end to end, offline"
	exit 0
fi


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
	# Yarn turns on immutable installs in CI, and this project starts
	# with no lockfile, so the install must be allowed to write one.
	cat >"$dir/.yarnrc.yml" <<EOF
npmRegistryServer: "$registry"
npmAuthToken: "$E2E_TOKEN"
npmAlwaysAuth: true
npmMinimalAgeGate: 0
enableImmutableInstalls: false
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


step "npm installs public packages through $proxy, with registry signatures"
[ "$(status "${proxy_registry}debug")" = 200 ] || fail "$proxy did not answer an anonymous client"
doc=$(curl -fsS -H 'Accept: application/vnd.npm.install-v1+json' "${proxy_registry}@isaacs%2fstring-locale-compare")
[ "$(jq -r '.versions["1.1.0"].dist.tarball' <<<"$doc")" = "${proxy_registry}@isaacs/string-locale-compare/-/string-locale-compare-1.1.0.tgz" ] ||
	fail "the proxied tarball URL is $(jq -r '.versions["1.1.0"].dist.tarball' <<<"$doc")"
[ "$(jq '.versions["1.1.0"].dist.signatures | length' <<<"$doc")" -gt 0 ] || fail "the proxied packument lost its signatures"
papp=$work/papp
make_app "$papp" "$public" "$proxy_registry"
(cd "$papp" && npm install --loglevel=error >/dev/null)
resolved "$papp" "$proxy_registry" 4
check_app "$papp" "npm install through $proxy"
(cd "$papp" && npm audit signatures 2>&1 | grep -q 'have verified registry signatures') ||
	fail "npm audit signatures did not verify the proxied packages"
(cd "$papp" && npm audit --audit-level=critical >/dev/null) || fail "npm audit through $proxy failed"
rm -rf "$state/papp" && mkdir -p "$state/papp" && cp "$papp/package.json" "$papp/package-lock.json" "$papp/.npmrc" "$state/papp/"

step "npm installs an app of hosted and public packages through $virtual"
vdep=@flint-e2e/vdep-$run
publish "$(package "$vdep" 1.0.0 '{"is-number": "^7.0.0"}')"
echo "$vdep" >"$state/vdep"
[ "$(status "$virtual_registry${vdep/\//%2f}")" = 401 ] || fail "$virtual answered an anonymous client"
vapp=$work/vapp-npm
make_app "$vapp" "$public, \"$vdep\": \"1.0.0\"" "$virtual_registry"
(cd "$vapp" && npm install --loglevel=error >/dev/null)
resolved "$vapp" "$virtual_registry" 5
check_app "$vapp" "npm install through $virtual" "$vdep"
(cd "$vapp" && npm audit --audit-level=critical >/dev/null) || fail "npm audit through $virtual failed"
rm -rf "$state/vapp-npm" && mkdir -p "$state/vapp-npm" && cp "$vapp/package.json" "$vapp/package-lock.json" "$vapp/.npmrc" "$state/vapp-npm/"
rm -rf "$vapp/node_modules"
(cd "$vapp" && npm_config_cache=$work/npm-ci-vcache npm ci --loglevel=error >/dev/null)
check_app "$vapp" "npm ci through $virtual" "$vdep"

# vclient_dir makes $state/vapp-$1, for another client to install the
# virtual repository's app in, and prints it.
vclient_dir() {
	local dir=$state/vapp-$1
	rm -rf "$dir"
	make_app "$dir" "$public, \"$vdep\": \"1.0.0\"" "$virtual_registry"
	echo "$dir"
}
if [[ $clients == *" pnpm "* ]]; then
	step "pnpm installs through $virtual"
	dir=$(vclient_dir pnpm)
	(cd "$dir" && pnpm install --reporter=silent --store-dir "$work/pnpm-store-v" --config.minimum-release-age=0)
	check_app "$dir" "pnpm install through $virtual" "$vdep"
	rm -rf "$dir/node_modules"
fi
if [[ $clients == *" yarn "* ]]; then
	step "Yarn classic installs through $virtual"
	dir=$(vclient_dir yarn)
	echo "always-auth=true" >>"$dir/.npmrc"
	(cd "$dir" && yarn install --silent --non-interactive --cache-folder "$work/yarn-cache-v")
	check_app "$dir" "yarn install through $virtual" "$vdep"
	n=$(grep -cE '^  resolved ' "$dir/yarn.lock")
	[ "$n" -eq 5 ] || fail "yarn.lock resolves $n packages, want 5"
	grep -E '^  resolved ' "$dir/yarn.lock" | grep -v "\"$virtual_registry" &&
		fail "yarn.lock has a tarball URL not at $virtual"
	rm -rf "$dir/node_modules"
fi
if [[ $clients == *" yarn-berry "* ]]; then
	step "Yarn Berry installs through $virtual"
	dir=$(vclient_dir berry)
	rm "$dir/.npmrc"
	berry_config "$dir" "$virtual_registry" "$work/berry-cache-v"
	# Yarn turns on immutable installs in CI, and this project starts with
	# no lockfile, so the install must be allowed to write one.
	echo "enableImmutableInstalls: false" >>"$dir/.yarnrc.yml"
	touch "$dir/yarn.lock"
	out=$(cd "$dir" && $yarn_berry install 2>&1) || {
		echo "$out"
		fail "yarn berry install failed"
	}
	check_app "$dir" "yarn berry install through $virtual" "$vdep"
	rm -rf "$dir/node_modules" "$dir/.yarnrc.yml" "$dir/.yarn"
fi
if [[ $clients == *" bun "* ]]; then
	step "Bun installs through $virtual"
	dir=$(vclient_dir bun)
	(cd "$dir" && BUN_INSTALL_CACHE_DIR=$work/bun-cache-v bun install --silent)
	check_app "$dir" "bun install through $virtual" "$vdep"
	rm -rf "$dir/node_modules"
fi

step "npm publishes through $virtual to $hosted"
via=flint-e2e-via-$run
publish "$(package "$via" 1.0.0)" --registry "$virtual_registry"
[ "$(status "${auth[@]}" "$registry$via")" = 200 ] || fail "the package published through $virtual is not in $hosted"
[ "$(npm view "$via" version --registry "$virtual_registry")" = 1.0.0 ] || fail "$virtual does not serve what was published through it"

step "dependency confusion: $guarded serves the hosted version, and keeps the internal scope from $decoy"
owned=flint-e2e-owned-$run
decoy_only=flint-e2e-decoy-$run
internal=@flint-internal/secret-$run
publish "$(package "$owned" 1.0.0)"
publish "$(package "$owned" 9.0.0)" --registry "$decoy_registry"
publish "$(package "$decoy_only" 1.0.0)" --registry "$decoy_registry"
publish "$(package "$internal" 1.0.0)" --registry "$decoy_registry"
doc=$(curl -fsS "${auth[@]}" "$guarded_registry$owned")
[ "$(jq -r '.versions | keys | join(" ")' <<<"$doc")" = 1.0.0 ] ||
	fail "$guarded serves versions $(jq -c '.versions | keys' <<<"$doc") of $owned, want only the hosted 1.0.0"
gapp=$work/gapp
make_app "$gapp" "\"$owned\": \"*\"" "$guarded_registry"
(cd "$gapp" && npm install --loglevel=error >/dev/null)
[ "$(jq -r --arg n "node_modules/$owned" '.packages[$n].version' "$gapp/package-lock.json")" = 1.0.0 ] ||
	fail "npm installed $owned from the fake upstream through $guarded"
# The fake upstream's answers count as packument requests answered 200:
# a name it alone has is fetched from it through $guarded, while the
# excluded scope never reaches it.
packuments() { metric 'flint_http_requests_total{method="GET",route="npm.packument",code="200"}'; }
before=$(packuments)
[ "$(status "${auth[@]}" "$guarded_registry$decoy_only")" = 200 ] || fail "$guarded does not serve $decoy_only from $decoy_proxy"
after=$(packuments)
[ "$after" -ge $((before + 2)) ] || fail "the packument requests answered 200 went from $before to $after, so they do not count the fake upstream's"
before=$after
code=$(status "${auth[@]}" "$guarded_registry${internal/\//%2f}")
[ "$code" = 404 ] || fail "$guarded answered $code for the excluded $internal, want 404"
after=$(packuments)
[ "$after" = "$before" ] || fail "the excluded $internal reached the fake upstream"

echo "OK: npm end to end"
