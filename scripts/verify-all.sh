#!/usr/bin/env bash
# One command for every Wave 0 check: build, vet, tests, race, both corpora and
# the budget gate (docs/budgets.json), benchmarks against bench ceilings, and
# the kernel suite. The kernel suite needs root + BTF; without them it is
# reported as SKIPPED (not passed) and, if REQUIRE_KERNEL=1, fails the run.
#
#   scripts/verify-all.sh                 # everything the host can run
#   REQUIRE_KERNEL=1 scripts/verify-all.sh # CI on the Linux VM (deploy/ec2)
#   QUICK=1 scripts/verify-all.sh          # skip race + http benches
set -uo pipefail
cd "$(dirname "$0")/.."

GO=${GO:-go}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
declare -a results
fail=0

step() { # name cmd...
	local name=$1; shift
	echo "==> $name"
	if "$@" >"$out/$name.log" 2>&1; then
		results+=("PASS    $name")
	else
		results+=("FAIL    $name  (log below)")
		tail -30 "$out/$name.log"
		fail=1
	fi
}

step gofmt sh -c 'test -z "$(gofmt -l $(git ls-files "*.go"))"'
step build "$GO" build ./...
step vet "$GO" vet ./...
step servers make GO="$GO" build
step test "$GO" test ./...
[ -z "${QUICK:-}" ] && step race env CGO_ENABLED=1 "$GO" test -race -short ./internal/proxy/... ./internal/engine/... ./internal/k8s/... ./internal/config/...
step test-layers scripts/check-test-layers.sh
step spdx scripts/check-spdx.sh

"$GO" test -run='^$' -bench=. -benchmem -benchtime=50ms ./internal/engine/... 2>&1 | grep '^Benchmark' >"$out/bench.txt"
if [ -z "${QUICK:-}" ]; then
	"$GO" test -run='TestHTTP_OverheadReport|TestHTTP_ConcurrentLoad' -bench=BenchmarkHTTP_EngineDelta -benchmem -benchtime=500ms ./internal/proxy/http/... 2>&1 | grep '^Benchmark' >>"$out/bench.txt"
	bench_args=(-bench "$out/bench.txt")
else
	bench_args=(-bench "$out/bench.txt" -skip '^BenchmarkHTTP_')
fi
step gate "$GO" run ./cmd/gate "${bench_args[@]}"

echo "==> kernel"
if [ "$(id -u)" = 0 ] && [ -e /sys/kernel/btf/vmlinux ]; then
	step kernel "$GO" test -count=1 -v ./internal/ebpf/...
	skipped=$(grep -c -- '--- SKIP' "$out/kernel.log" || true)
	results+=("NOTE    kernel: $skipped test(s) skipped inside the suite (e.g. LSM not active, ringbuf not saturated)")
elif [ -n "${REQUIRE_KERNEL:-}" ]; then
	results+=("FAIL    kernel  (REQUIRE_KERNEL=1 but not root with BTF)")
	fail=1
else
	results+=("SKIPPED kernel  (needs root + /sys/kernel/btf/vmlinux; run on the deploy/ec2 VM)")
fi

echo
printf '%s\n' "${results[@]}"
exit $fail
