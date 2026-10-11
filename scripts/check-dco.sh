#!/usr/bin/env bash
# check-dco.sh checks that every commit in a range carries a Signed-off-by
# trailer matching its author, as the Developer Certificate of Origin
# requires (see CONTRIBUTING.md).
#
# Commits authored by the project owner are exempt: the DCO is an attestation
# for outside contributors, and automated review fixes are committed under
# the owner identity without a sign-off. Merge commits are skipped.
#
# Usage: scripts/check-dco.sh <base> <head>   (checks commits in base..head)
set -euo pipefail

owner='terrabyteian <terrabyteian@users.noreply.github.com>'

if [ $# -ne 2 ]; then
	echo "usage: $0 <base> <head>" >&2
	exit 2
fi

status=0
count=0
for sha in $(git rev-list --no-merges "$1..$2"); do
	count=$((count + 1))
	author=$(git show -s --format='%an <%ae>' "$sha")
	if [ "$author" = "$owner" ]; then
		continue
	fi
	if ! git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" |
		sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -qxF -- "$author"; then
		echo "check-dco: $(git show -s --format='%h %s' "$sha"): missing Signed-off-by: $author" >&2
		status=1
	fi
done

if [ "$status" -ne 0 ]; then
	echo "check-dco: sign off each commit with git commit -s; to fix a branch, run git rebase --signoff <base>" >&2
	exit 1
fi
echo "check-dco: ok ($count commits checked)"
