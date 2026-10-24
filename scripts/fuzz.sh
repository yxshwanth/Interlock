#!/usr/bin/env bash
# Run every Go fuzz target for FUZZTIME each (default 30s). Go allows one
# -fuzz target per invocation, so this lists them and loops. A crash writes a
# reproducer under <pkg>/testdata/fuzz/; commit it, it becomes a permanent test.
#   FUZZTIME=5m scripts/fuzz.sh
#   scripts/fuzz.sh FuzzLoad        # only targets matching the argument
set -euo pipefail
cd "$(dirname "$0")/.."
GO="${GO:-$(command -v go || echo /usr/local/go/bin/go)}"
FUZZTIME="${FUZZTIME:-30s}"
pat="${1:-.}"
fail=0
for pkg in $("$GO" list ./...); do
	for target in $("$GO" test -list '^Fuzz' "$pkg" 2>/dev/null | grep '^Fuzz' || true); do
		echo "$target" | grep -q -- "$pat" || continue
		echo "==> $pkg $target ($FUZZTIME)"
		"$GO" test "$pkg" -run '^$' -fuzz "^${target}\$" -fuzztime "$FUZZTIME" || fail=1
	done
done
exit $fail
