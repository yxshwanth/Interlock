# Testing strategy (ROADMAP §80)

This file adopts the layers, CI tiers and targets of [ROADMAP §0.8](ROADMAP.md) for the current Go tree, and records what is measured today. The Rust port (§76) reuses the layers; tool names change, the contract does not.

## Layers present in the Go tree

Every `*_test.go` file is labelled with a layer in [`scripts/test_layers.tsv`](../scripts/test_layers.tsv). `scripts/check-test-layers.sh` fails if a test file has no label or a label names a missing file, and it runs in `scripts/verify-all.sh` and CI. New test files add a row in the same PR.

| Layer | Status today | Where |
|---|---|---|
| L0 Static | `go vet`, `go build`; no secret scanner, `govulncheck` or SPDX check in the PR tier yet | CI, `scripts/check-spdx.sh` |
| L1 Unit | 42 files | most of `internal/*` |
| L2 Property / metamorphic | none yet | Wave 2 (§83) |
| L3 Differential | none yet | Wave 3 onward (Go vs Rust) |
| L4 Corpus | 4 test files + `cmd/fp-corpus`, `cmd/cve-corpus`, `cmd/gate` | `internal/corpus` |
| L5 Integration | 8 files (proxy, HTTP transport, bridge, demo narrative) | `internal/proxy`, `internal/bridge`, `cmd/demo` |
| L6 End to end | manual (`make demo*`, `make demo-k8s`) | not automated |
| L7 Fuzz | none yet | Wave 2 (§84) |
| L8 Kernel | 6 files; need root and BTF, skip otherwise | `internal/ebpf` |
| L9 Isolation / escape | 1 file (netns); privilege-drop escape tests land in Wave 1 | `internal/proxy` |
| L10 Chaos / crash | none yet | later wave |
| L11 Performance | 5 files; budgets in [`budgets.json`](budgets.json) | `internal/engine`, `internal/proxy/http` |
| L12 to L14 | none yet | later waves |

A layer marked "none yet" is a gap, not a pass.

## CI tiers

| Tier | When | Budget | Contents now |
|---|---|---|---|
| PR | every push | p90 under 15 min | build, vet, `go test ./...`, race (proxy, engine), bench smoke, `cmd/gate` corpus gates, DCO, test-layer and SPDX checks |
| Merge queue | before merge | under 45 min | not set up; will add kernel VM subset and the bench gate |
| Nightly | every night | hours | not set up; `scripts/verify-all.sh` on the Linux VM with `REQUIRE_KERNEL=1` is the seed |
| Weekly / release | later | | not set up |

Measured on the dev laptop (Wave 0 baseline): `go test ./...` takes about 86 s wall, of which 84 s is `internal/proxy/http` (the overhead reports run 10,000 samples by default; CI sets `OVERHEAD_SAMPLES=100`). The 15-minute PR budget has room; p90 over real CI runs is not measured yet.

## One command

```
scripts/verify-all.sh                  # everything the host can run
QUICK=1 scripts/verify-all.sh          # skip race and HTTP benches
REQUIRE_KERNEL=1 scripts/verify-all.sh # fail instead of skipping the kernel suite
```

Results are `PASS`, `FAIL` or `SKIPPED`; a skipped kernel suite is never reported as a pass.

## Gates and what blocks a merge or release

`cmd/gate` reads [`budgets.json`](budgets.json) and fails on:

1. Any EXFIL-tier false positive on the benign corpus (budget 0).
2. Any change in the corpus counts: true positives, false negatives, known-gap misses, bonus catches, CVE caught/total. The counts are exact pins, so a gap closing silently fails the gate just as a gap opening does. Closing a gap is a deliberate edit of `budgets.json` plus the matching `KnownGap` test and corpus tag in the same PR.
3. A benchmark above its ceiling in `bench_max_ns_op`, or a budgeted benchmark missing from the output.

Blocks merge: build, vet, any test failure (including a flipped `*_KnownGap` test), race failure, a gate failure, a missing DCO sign-off, an unlabelled test file.
Blocks release: all of the above, the kernel suite on the LTS kernel and kernel 6.1 once Wave 1 §24 lands, and `make verify-evidence` on the demo evidence.

## Flake policy

- Target: under 0.5% of runs flake (ROADMAP §0.8).
- A test that fails and then passes on rerun without a code change is a flake. Open an issue the same day, label it `flake`, and add `t.Skip("flaky: <issue>")` within 24 hours only if it blocks others; fix within 7 days or delete the test.
- Never retry blindly in CI to hide a flake. Reruns are manual and recorded on the issue.
- Tests that need root, BTF or a particular kernel must `t.Skip` with the reason, not fail, and the skip must show up in `scripts/verify-all.sh` output.
- Observed so far: one Go compiler crash and one `-race` runtime crash on the dev laptop, both clean on immediate rerun, cause not established. Not attributed to repo code; watch for recurrence in CI.

## Naming and ownership

- Test names: `Test<Unit>_<Behavior>`; a test that pins a limitation ends in `_KnownGap` and must fail when the gap closes ([CONTRIBUTING.md](../CONTRIBUTING.md#known-gap-discipline)).
- Every detection change ships a positive test, a `_KnownGap` test for what it does not catch, and a corpus scenario.
- Owner of a test is the owner of the package under `.github/CODEOWNERS`.

## Baselines and calibration

Targets in ROADMAP §0.8 are not gates until calibrated. Line coverage per package at the Wave 0 baseline (`go test -cover ./...`, tree `5d9e946`):

| Package | Coverage |
|---|---|
| internal/model | 94.1% |
| internal/alerting | 93.9% |
| internal/failclosed | 81.8% |
| internal/siem | 79.3% |
| internal/corpus | 78.6% |
| internal/engine | 77.2% |
| internal/config | 73.5% |
| internal/bridge | 71.0% |
| internal/reload | 60.6% |
| internal/proxy/http | 60.0% |
| internal/proxy | 51.6% |
| internal/mcpserver | 40.4% |
| internal/observability | 39.4% |
| internal/k8s | 37.4% |
| internal/ebpf | 13.1% (kernel tests skip without root) |
| cmd/demo | 0.0% |

The engine (77.2%) is under the 90% core-crate target; the ratchet rule is: coverage of a package may not drop. Enforcing it needs a per-package floor file, which is not built yet. Test count: 385 top-level `Test*` functions (`go test ./... -list '.*' | grep -c '^Test'`).
