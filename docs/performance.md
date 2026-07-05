# Performance

Interlock v0.2 Phase 4 publishes **engine-component microbenchmarks** — not user-visible proxy overhead.

## What these numbers are and are not

**These are engine-component benchmarks.** They measure isolated work inside `internal/engine`: overlap scanning, taint registration, and the worst-case `EvaluateRequest` block path (including evidence emit to the configured sink).

**They are not Interlock's end-to-end overhead.** The number that answers "how much latency does Interlock add to a real tool call?" is **per-request proxy overhead on the HTTP path** — and that is **not yet measured** (see `TestBenchmark_FullHTTPLoad_KnownGap` in `internal/engine/bench_test.go`).

Do **not** quote `BenchmarkEngine_EvaluateRequest_Exfil` (~0.56 ms on the snapshot machine) as "Interlock's overhead." It is one engine function's worst case in isolation, excluding HTTP transport, JSON-RPC framing, MCP server I/O, session management, and concurrent load.

When we publish end-to-end numbers, they will live here with a separate methodology section.

## Methodology

- **Command:** `make bench` (runs `go test -bench=. -benchmem ./internal/engine/...`)
- **Environment:** Linux amd64, Go 1.25, `-benchtime=50ms` unless noted
- **Scope:** engine package only — `CheckOverlap`, taint registration, full `EvaluateRequest` exfil block path
- **Not measured here:** End-to-end per-request proxy latency (HTTP p99), HTTP transport overhead, MCP server I/O, eBPF event loop throughput

Numbers drift across hardware. Treat this table as a **snapshot**, not an SLA.

## Results (representative snapshot)

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| `BenchmarkCanonicalEncodings` | 276 | 576 | 7 | Per-secret transform precompute at registration |
| `BenchmarkCheckOverlap_1Tainted` | 70 | 80 | 1 | Sink scan, 1 tainted value (5 forms) |
| `BenchmarkCheckOverlap_10Tainted` | 517 | 80 | 1 | 10 tainted values |
| `BenchmarkCheckOverlap_50Tainted` | 2146 | 80 | 1 | 50 tainted values |
| `BenchmarkEngine_IngestResult_TaintExtract` | 14860 | 2808 | 39 | Sensitive source result ingest + taint |
| `BenchmarkEngine_EvaluateRequest_Exfil` | 562798 | 432733 | 6296 | Engine worst-case block + evidence emit — **not** end-to-end proxy latency |

### Reading the numbers

- **Overlap check** scales linearly with tainted-value count × 5 canonical forms — acceptable for typical session sizes (single-digit secrets).
- **EvaluateRequest exfil path** includes evidence record construction and sink write; this is the blocking firewall worst case, not steady-state `tools/list` traffic.
- Phase 4 follow-up (if benchmarks regress in production): async evidence emit or sampled overlap — not implemented in v0.2.

## Known gaps

See skip tests in the codebase:

- `TestBenchmark_FullHTTPLoad_KnownGap` — no automated p99 HTTP load benchmark
- eBPF ring-buffer saturation under load — not benchmarked in CI

## Reproduce

```bash
make bench
```

For a longer run:

```bash
go test -bench=. -benchmem -benchtime=1s ./internal/engine/...
```
