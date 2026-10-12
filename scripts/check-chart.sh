#!/bin/sh
# Lints and renders the Helm chart in deploy/helm/flint with its default
# values, docs/helm-values.example.yaml, and each file in its ci directory.
# For each, it checks the rendered manifests against the Kubernetes schemas
# with kubeconform and the rendered flint configuration with flint config
# check, then checks that invalid values fail to render.
#
# Needs helm, yq (github.com/mikefarah/yq), kubeconform, and go.
set -eu

cd "$(dirname "$0")/.."
chart=deploy/helm/flint
# The oldest Kubernetes version the chart supports; see kubeVersion in
# Chart.yaml.
kube_version=1.30.0
crd_schemas='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
go build -o "$tmp/flint" ./cmd/flint

check() {
	name=$1
	shift
	echo "== $name"
	helm lint --strict "$chart" "$@"
	helm template flint "$chart" --namespace flint --kube-version "$kube_version" "$@" > "$tmp/manifests.yaml"
	kubeconform -strict -summary -kubernetes-version "$kube_version" \
		-schema-location default -schema-location "$crd_schemas" "$tmp/manifests.yaml"
	yq -e 'select(.kind == "ConfigMap") | .data["config.json"]' "$tmp/manifests.yaml" > "$tmp/config.json"
	"$tmp/flint" config check "$tmp/config.json"
}

check "default values"
check docs/helm-values.example.yaml --values docs/helm-values.example.yaml
for values in "$chart"/ci/*-values.yaml; do
	check "$values" --values "$values"
done

# Each line sets values the chart must refuse to render.
status=0
while read -r set; do
	if helm template flint "$chart" --set "$set" > /dev/null 2> "$tmp/err"; then
		echo "FAIL: rendered with invalid values --set $set"
		status=1
	else
		echo "ok: refused --set $set: $(head -n 1 "$tmp/err")"
	fi
done <<'INVALID'
config.listen=:80
config.dataDir=/data
config.tls.certFile=/x
tls.enabled=true
tls.certManager.enabled=true
tls.enabled=true,tls.certManager.enabled=true
tls.enabled=true,tls.existingSecret=x,tls.certManager.enabled=true,tls.certManager.issuerRef.name=ca
service.type=ExternalName
imag.tag=typo
bootstrapAdmin.enabled=true
config.auth.bootstrapAdmin.passwordFile=/x
config.backup.directory=/backups
backup.enabled=true
upstreamSecrets[0].name=Bad_Name,upstreamSecrets[0].existingSecret=x
upstreamSecrets[0].name=dockerhub
oidcSecrets[0].name=Bad_Name,oidcSecrets[0].existingSecret=x
oidcSecrets[0].name=corp
googleSignIn.enabled=true
googleSignIn.enabled=true,googleSignIn.clientId=x
googleSignIn.enabled=true,googleSignIn.clientId=x,googleSignIn.existingSecret=x
googleSignIn.enabled=true,googleSignIn.clientId=x,googleSignIn.existingSecret=x,oidcSecrets[0].name=google,oidcSecrets[0].existingSecret=x
googleSignIn.hostedDomain=example.com
INVALID
exit "$status"
