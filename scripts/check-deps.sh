#!/usr/bin/env bash
# check-deps.sh enforces flint's zero-dependency rule: the build may use only
# the Go standard library and packages inside the flint module.
#
# It fails when go.mod has any require directive, when a go.sum file exists,
# or when `go list -deps -test ./...` reports a package (for any release
# target) that is neither standard library nor part of this module.
#
# Usage: scripts/check-deps.sh   (run from anywhere inside the repository)
set -euo pipefail

cd "$(dirname "$0")/.."

# Check this module alone, even inside a contributor's multi-module go.work.
export GOWORK=off

module=$(go list -m)
status=0

if go mod edit -json | grep -q '"Require"'; then
	echo "check-deps: go.mod has require directives; flint allows no external modules:" >&2
	go mod edit -json | sed -n '/"Require"/,/]/p' >&2
	status=1
fi

if [ -e go.sum ]; then
	echo "check-deps: go.sum exists; flint has no external modules, so it must not exist" >&2
	status=1
fi

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
	external=$(GOOS=${target%/*} GOARCH=${target#*/} CGO_ENABLED=0 go list -deps -test \
		-f '{{if not .Standard}}{{.ImportPath}} {{with .Module}}{{.Path}}{{end}}{{end}}' ./... |
		awk -v m="$module" 'NF && $NF != m { print $1 }' | sort -u)
	if [ -n "$external" ]; then
		echo "check-deps: $target build depends on packages outside the standard library and $module:" >&2
		echo "$external" | sed 's/^/  /' >&2
		status=1
	fi
done

if [ "$status" -eq 0 ]; then
	echo "check-deps: ok (standard library only)"
fi
exit "$status"
