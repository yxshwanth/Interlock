# Wave 2 status and carryover

Scope from [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md): §75, then §83 (start), §84 (Go native fuzzing), §81 (start).

## Done

- [x] **§75** All 96 scenarios moved out of Go into `internal/corpus/data/*.json`. Extraction was proven lossless before the Go builders were deleted (structural equality, identical outcomes and verdicts, identical fixture configs, unchanged published reports). See [`corpus_contract.md`](corpus_contract.md).
- [x] Every `KnownGap` has a machine-readable `gap_tag` from a closed set, enforced by a test.
- [x] A stub Rust loader reads the same files, rejecting unknown fields, and runs in CI.
- [x] **§83 (start)** Generated attacks and benign flows (`generate.go`): 13 documented encodings, four secret families, random noise and sinks, a quarter through the eBPF write path. 10 seeds of 1000 produced no miss and no false EXFIL. A fixed seed runs in every PR; the nightly job uses a fresh one.
- [x] **§83 (start)** A frozen held-out set of 35 scenarios, hash-pinned, with outcomes pinned and published beside the tuned rates: [`heldout_corpus.md`](heldout_corpus.md). Detection is 14/19 (73.7%) there against 100% on the tuned set.
- [x] **§84** 11 Go native fuzz targets across 6 packages (container walker, overlap, decode, taint extraction, evidence chain, tool-call params, config load, ring-buffer decode, SSE, cgroup id). Seeds run in every PR; `scripts/fuzz.sh` and a nightly job explore. A 20 second pass per target found nothing.
- [x] **§81 (start)** Two relations: planted literals survive any surrounding text (fuzzed), and a secret split at every boundary within one call is caught (checked at all 43 offsets and mutation-verified).

## Start gate for §76 (engine port)

| Condition | State |
|---|---|
| §80 merged | In review: PR #56 |
| §83 has a held-out set and generated variants in CI | Yes |
| §84 fuzzers running on the Go parsers | Yes, with one 20 second pass so far; the first nightly runs are the real signal |

## Carryover

- [ ] **Decide the five held-out misses.** Case change, spacing, base32, `\uXXXX` text, and secret halves in two separate calls. Fixing one changes `heldout_expected.json` and must be recorded in `heldout_corpus.md`. Splitting across calls needs no encoding, so it is the one to decide first.
- [ ] §83: 1,000 curated scenarios (96 plus 35 now), privacy-scrubbed captures of real benign agent traffic, a 14 day pipeline from a new MCP CVE to scenarios, contributed red-team scenarios. None of these exist yet, and only the last two reduce author bias.
- [ ] §84: 7 days wall time per target before each minor release, structure-aware grammars for JSON-RPC and Streamable HTTP, DNS wire format, tar/zip/brotli/zstd/lz4 inputs beyond the seeds, Cedar, plugin ABI, sanitizers. OSS-Fuzz application. The nightly job runs 2 minutes per target.
- [ ] §81: `proptest` suites arrive with the Rust crates. The metamorphic relation "adding unrelated calls never removes a catch" passes but could not be made to fail (150 calls did not remove a catch), so it is a regression guard, not evidence.
- [ ] The first nightly runs of the fuzz and generated-corpus jobs, and the first CI run of the Rust stub job, have not happened on GitHub yet.
