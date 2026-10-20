#!/usr/bin/env bash
# Fails if any package in scripts/coverage_floor.tsv is below its floor.
set -euo pipefail
cd "$(dirname "$0")/.."
go test -cover ./internal/... | awk -F'\t' '
	NR==FNR { if ($0 !~ /^#/ && NF) floor[$1]=$2; next }
	/coverage:/ {
		pkg=$2; sub(/^github.com\/yxshwanth\/Interlock\//, "", pkg)
		match($0, /coverage: [0-9.]+/); pct=substr($0, RSTART+10, RLENGTH-10)
		if ((pkg in floor) && pct+0 < floor[pkg]+0) { printf "%s %.1f%% < floor %s%%\n", pkg, pct, floor[pkg]; bad=1 }
		seen[pkg]=1
	}
	END { for (p in floor) if (!(p in seen)) { print "no coverage line for " p; bad=1 } exit bad }
' scripts/coverage_floor.tsv -
