#!/usr/bin/env bash
# check-dco_test.sh tests scripts/check-dco.sh against temporary repositories:
# a signed-off contributor commit and an unsigned owner commit pass, and an
# unsigned or mismatched contributor commit fails.
#
# Usage: scripts/check-dco_test.sh
set -euo pipefail

check="$(cd "$(dirname "$0")" && pwd)/check-dco.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
failures=0

# commit NAME EMAIL [git commit flags...] makes an empty commit as NAME.
commit() {
	local name=$1 email=$2
	shift 2
	GIT_AUTHOR_NAME=$name GIT_AUTHOR_EMAIL=$email \
		GIT_COMMITTER_NAME=$name GIT_COMMITTER_EMAIL=$email \
		git commit -q --allow-empty -m change "$@"
}

# expect WANT NAME SETUP runs SETUP in a fresh repository and checks that
# check-dco.sh over its new commits exits with WANT (pass or fail).
expect() {
	local want=$1 name=$2 setup=$3 got
	rm -rf "$tmp/repo"
	git init -q "$tmp/repo"
	(cd "$tmp/repo" && commit base base@example.com && git tag base)
	(cd "$tmp/repo" && eval "$setup")
	if (cd "$tmp/repo" && "$check" base HEAD) >/dev/null 2>&1; then
		got=pass
	else
		got=fail
	fi
	if [ "$got" != "$want" ]; then
		echo "FAIL $name: got $got, want $want" >&2
		failures=$((failures + 1))
	else
		echo "ok   $name"
	fi
}

owner_name=terrabyteian
owner_email=terrabyteian@users.noreply.github.com

expect pass "contributor signed off" 'commit Alice alice@example.com -s'
expect pass "owner without sign-off" "commit $owner_name $owner_email"
expect fail "contributor without sign-off" 'commit Alice alice@example.com'
expect fail "sign-off by someone else" 'commit Alice alice@example.com -m "Signed-off-by: Bob <bob@example.com>"'
expect fail "owner name with another email" "commit $owner_name other@example.com"
expect fail "one unsigned among signed" 'commit Alice alice@example.com -s; commit Bob bob@example.com; commit Alice alice@example.com -s'

if [ "$failures" -ne 0 ]; then
	exit 1
fi
