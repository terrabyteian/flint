#!/usr/bin/env bash
# e2e-helm.sh pushes Helm charts to a running flint with helm push and
# uses them through flint's classic Helm repository view: helm repo add,
# helm search repo, helm pull (with provenance verification), helm
# template, and helm repo update after a new version is pushed. It checks
# that a chart pulled from the view is byte-identical to the one pulled
# over OCI, and fails on the first mismatch.
#
# Usage: E2E_USERNAME=<user> E2E_PASSWORD=<secret> scripts/e2e-helm.sh <host:port> <repository>
#   <repository> is a configured hosted OCI repository with helmIndex,
#   such as "charts", that holds no charts yet.
#   E2E_PASSWORD is the user's password or an API token; the user needs the
#   write role on <repository>.
# Requires helm (3 or 4), gpg, curl, and jq on PATH. helm's configuration,
# cache, and keys live in a temporary directory, so the caller's are
# untouched.
set -euo pipefail

if [ $# -ne 2 ] || [ -z "${E2E_USERNAME:-}" ] || [ -z "${E2E_PASSWORD:-}" ]; then
	echo "usage: E2E_USERNAME=<user> E2E_PASSWORD=<secret> $0 <host:port> <repository>" >&2
	exit 2
fi
reg=$1
repo=$2
url=http://$reg/helm/$repo
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
step() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
export HELM_CONFIG_HOME=$work/config HELM_CACHE_HOME=$work/cache HELM_DATA_HOME=$work/data
export GNUPGHOME=$work/gnupg
mkdir -m 700 "$GNUPGHOME"
cd "$work"
helm version
helm_major=$(helm version --template '{{.Version}}' | cut -c2)

# package <chart> <version> [--sign]: packages a chart made by helm create.
package() {
	local name=$1 version=$2
	shift 2
	[ -d "src/$name" ] || helm create "src/$name" >/dev/null
	helm package "src/$name" --version "$version" --app-version "app-$version" -d pkg "$@" >/dev/null
}
# push <file> <oci path>: pushes a packaged chart, and its provenance file if any.
push() { helm push "$1" "oci://$reg/$2" --plain-http; }
# versions <repo>/<chart>: the versions helm search repo lists, newest first.
versions() { helm search repo "$1" --versions -o json | jq -r --arg n "$1" '[.[] | select(.name == $n) | .version] | join(" ")'; }

step "anonymous access is refused with a Basic challenge"
code=$(curl -sS -o /dev/null -D headers.txt -w '%{http_code}' "$url/index.yaml")
[ "$code" = 401 ] || fail "anonymous index.yaml: $code"
grep -qi '^www-authenticate: Basic realm="flint"' headers.txt || fail "no Basic challenge: $(cat headers.txt)"

step "a signing key for provenance files"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'flint e2e <e2e@flint.invalid>' rsa2048 sign never
# helm reads the legacy keyring format.
gpg --batch --export-secret-keys >secring.gpg
gpg --batch --export >pubring.gpg

step "package and push two charts, two versions each, with helm push"
# Helm 4 needs --plain-http to log in over HTTP; Helm 3 tries HTTP itself.
login_http=--insecure
[ "$helm_major" = 3 ] || login_http=--plain-http
printf '%s' "$E2E_PASSWORD" | helm registry login "$reg" "$login_http" -u "$E2E_USERNAME" --password-stdin
mkdir pkg src
package alpha 0.1.0
package alpha 0.2.0 --sign --key 'flint e2e' --keyring secring.gpg
package beta 1.0.0
package beta 1.1.0+build.5
[ -f pkg/alpha-0.2.0.tgz.prov ] || fail "helm package --sign wrote no provenance file"
for f in alpha-0.1.0 alpha-0.2.0 beta-1.0.0 beta-1.1.0+build.5; do
	push "pkg/$f.tgz" "$repo"
done
package gamma 3.0.0
push pkg/gamma-3.0.0.tgz "$repo/team"

step "helm repo add and helm search repo"
helm repo add flint "$url" --username "$E2E_USERNAME" --password "$E2E_PASSWORD"
[ "$(versions flint/alpha)" = "0.2.0 0.1.0" ] || fail "alpha versions: $(versions flint/alpha)"
[ "$(versions flint/beta)" = "1.1.0+build.5 1.0.0" ] || fail "beta versions: $(versions flint/beta)"
[ -z "$(versions flint/gamma)" ] || fail "gamma, below $repo/team, is listed in $repo"
helm repo add flint-team "$url/team" --username "$E2E_USERNAME" --password "$E2E_PASSWORD"
[ "$(versions flint-team/gamma)" = 3.0.0 ] || fail "gamma versions: $(versions flint-team/gamma)"
app=$(helm search repo flint/beta --version 1.0.0 -o json | jq -r '.[0].app_version')
[ "$app" = app-1.0.0 ] || fail "beta 1.0.0 app version: $app"

step "helm pull from the classic repository matches the OCI chart and the package"
mkdir classic oci
for chart in alpha:0.1.0 alpha:0.2.0 beta:1.0.0 beta:1.1.0+build.5 gamma:3.0.0; do
	name=${chart%%:*}
	version=${chart#*:}
	src=flint/$name
	path=$repo/$name
	if [ "$name" = gamma ]; then
		src=flint-team/$name
		path=$repo/team/$name
	fi
	helm pull "$src" --version "$version" -d classic
	helm pull "oci://$reg/$path" --version "$version" --plain-http -d oci
	cmp "classic/$name-$version.tgz" "oci/$name-$version.tgz" || fail "$name $version differs from the OCI layer"
	cmp "classic/$name-$version.tgz" "pkg/$name-$version.tgz" || fail "$name $version differs from the pushed package"
done

step "helm pull --verify checks the provenance file"
rm -f classic/alpha-0.2.0.tgz
helm pull flint/alpha --version 0.2.0 --verify --keyring pubring.gpg -d classic
cmp classic/alpha-0.2.0.tgz.prov pkg/alpha-0.2.0.tgz.prov || fail "the provenance file differs"
if helm pull flint/alpha --version 0.1.0 --verify --keyring pubring.gpg -d classic 2>/dev/null; then
	fail "an unsigned chart verified"
fi

step "helm template from the classic repository"
helm template demo flint/alpha --version 0.2.0 >rendered.yaml
grep -q 'name: demo-alpha' rendered.yaml || fail "the rendered chart lacks its Deployment: $(head -20 rendered.yaml)"

step "the index is JSON and revalidates with its ETag"
curl -fsS -u "$E2E_USERNAME:$E2E_PASSWORD" -D headers.txt "$url/index.yaml" -o index.json
jq -e '.apiVersion == "v1" and (.entries.alpha | length) == 2' index.json >/dev/null || fail "unexpected index: $(cat index.json)"
etag=$(grep -i '^etag:' headers.txt | cut -d' ' -f2 | tr -d '\r')
code=$(curl -sS -o /dev/null -w '%{http_code}' -u "$E2E_USERNAME:$E2E_PASSWORD" -H "If-None-Match: $etag" "$url/index.yaml")
[ "$code" = 304 ] || fail "conditional index request: $code"

step "helm repo update sees a newly pushed version"
package alpha 0.3.0
push pkg/alpha-0.3.0.tgz "$repo"
[ "$(versions flint/alpha)" = "0.2.0 0.1.0" ] || fail "the cached index changed before an update"
helm repo update flint
[ "$(versions flint/alpha)" = "0.3.0 0.2.0 0.1.0" ] || fail "after helm repo update: $(versions flint/alpha)"
helm pull flint/alpha -d classic
cmp classic/alpha-0.3.0.tgz pkg/alpha-0.3.0.tgz || fail "the latest alpha differs from the pushed package"

helm repo remove flint flint-team >/dev/null
echo "OK: helm $helm_major pushed over OCI and installed from the classic repository at $url"
