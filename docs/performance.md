# Performance

Interlock v0.2 Phase 4 publishes **userspace engine hot-path** numbers. These measure the trifecta evaluation and encoding-overlap cost (post-Phase 3), not end-to-end HTTP latency or eBPF throughput.

## Methodology

- **Command:** `make bench` (runs `go test -bench=. -benchmem ./internal/engine/...`)
- **Environment:** Linux amd64, Go 1.25, `-benchtime=50ms` unless noted
- **Scope:** engine package only — `CheckOverlap`, taint registration, full `EvaluateRequest` exfil block path
- **Not measured here:** HTTP transport overhead, MCP server I/O, eBPF event loop throughput (requires root + kernel load generator)

Numbers drift across hardware. Treat this table as a **snapshot**, not an SLA.

## Results (representative snapshot)

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| `BenchmarkCanonicalEncodings` | 276 | 576 | 7 | Per-secret transform precompute at registration |
| `BenchmarkCheckOverlap_1Tainted` | 70 | 80 | 1 | Sink scan, 1 tainted value (5 forms) |
| `BenchmarkCheckOverlap_10Tainted` | 517 | 80 | 1 | 10 tainted values |
| `BenchmarkCheckOverlap_50Tainted` | 2146 | 80 | 1 | 50 tainted values |
| `BenchmarkEngine_IngestResult_TaintExtract` | 14860 | 2808 | 39 | Sensitive source result ingest + taint |
| `BenchmarkEngine_EvaluateRequest_Exfil` | 562798 | 432733 | 6296 | Full trifecta block + evidence emit (worst case) |

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
