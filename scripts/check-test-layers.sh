#!/usr/bin/env bash
# Every tracked *_test.go must have a layer in scripts/test_layers.tsv, and
# every entry must name a real file with a valid layer (docs/testing.md).
set -euo pipefail
cd "$(dirname "$0")/.."
map=scripts/test_layers.tsv
rc=0
while read -r f; do
	grep -q -P "^\Q$f\E\t" "$map" || { echo "unlabelled test file: $f"; rc=1; }
done < <(git ls-files '*_test.go')
while IFS=$'\t' read -r f layer; do
	case "$f" in '#'*|'') continue ;; esac
	[ -e "$f" ] || { echo "stale entry (no such file): $f"; rc=1; }
	[[ "$layer" =~ ^L([0-9]|1[0-4])$ ]] || { echo "bad layer '$layer' for $f"; rc=1; }
done < "$map"
exit $rc
