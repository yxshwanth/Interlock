# Performance

Interlock publishes **engine-component microbenchmarks** and **end-to-end HTTP proxy overhead** (v0.2.1+).

## What these numbers are and are not

**Engine benchmarks** measure isolated work inside `internal/engine`: overlap scanning, taint registration, and the worst-case `EvaluateRequest` block path (including evidence emit).

**HTTP benchmarks** measure client-perceived latency through the full Streamable HTTP stack (proxy + STDIO demo backends). The **quotable Interlock number is the engine delta (C)** — not absolute end-to-end latency (A), which is dominated by your backend's response time.

Do **not** quote `BenchmarkEngine_EvaluateRequest_Exfil` (~0.56 ms) as steady-state overhead. Do **not** quote absolute `read_ticket` p99 (~12 ms) as "Interlock's cost" — that is mostly the demo tickets server's I/O.

**Headline (engine delta, snapshot machine):** Interlock adds **sub-millisecond engine overhead** — **~0.5 ms on sensitive reads (typical agent traffic)** and **~0.1 ms on sink checks**. Agents read sensitive data constantly; the common path is the higher number, not the lower.

## End-to-end HTTP overhead

**Methodology:**

- **Command:** `make bench-http` (requires `make build` for demo server binaries)
- **Harness:** `internal/proxy/http/` — `httptest` + real ticket/messenger STDIO backends; SSE responses; `initialize` outside timer
- **A (absolute):** `TestHTTP_OverheadReport_*` + `TestHTTP_ConcurrentLoad_ReadTicket` — 10,000 client-side samples (`OVERHEAD_SAMPLES` env to override; concurrent uses `CONCURRENT_SESSIONS`, default 4); p50/p95/p99/p999 — **fixture context only**, not Interlock isolation
- **C (engine delta):** `BenchmarkHTTP_EngineDelta_*` — same stack, engine on vs passthrough (`engine == nil`); mean ns/op and allocs/op — **the deployer-facing Interlock cost**
- **Environment:** Linux amd64, Go 1.25 — snapshot machine; numbers drift across hardware

### Engine delta (C) — snapshot (`-benchtime=500ms`)

| Benchmark | EngineOn ns/op | Passthrough ns/op | Delta | allocs/op delta |
|---|---:|---:|---:|---:|
| `BenchmarkHTTP_EngineDelta_ReadTicket` | 936,000 | 400,000 | **~536 µs** | +63 | 2 secrets in fixture ticket; see scaling note below |
| `BenchmarkHTTP_EngineDelta_MonitorSinkBenign` | 492,000 | 374,000 | **~118 µs** | +32 |

Passthrough uses `proxy.New(..., nil)` — same HTTP path, no `EvaluateRequest` / `IngestResult`.

### Absolute latency (A) — snapshot (includes backend I/O)

| Scenario | p50 | p99 | p999 | Notes |
|---|---:|---:|---:|---|
| `read_ticket` (block config, benign — no trip) | 5.27 ms | 12.64 ms | 14.80 ms | Dominated by demo **tickets** STDIO backend payload work, not Interlock |
| `send_message` benign (monitor, full eval) | 0.89 ms | 1.85 ms | 2.16 ms | Lighter messenger backend + Interlock; full trifecta + `CheckOverlap`, allow forward |
| `read_ticket` concurrent (4 sessions, block) | 1.04 ms | 3.11 ms | 5.96 ms | `TestHTTP_ConcurrentLoad_ReadTicket` (n=1000); multi-session pool contention + backend I/O — still not Interlock isolation |

Absolute rows differ because the **backends differ** (heavy read vs cheap send), not because Interlock treats them differently. Use **C** for Interlock overhead; use **A** only with the backend caveat above. Concurrent A adds session-pool contention on top of the same backend-dominated path.

### Reading the HTTP numbers

**Why absolute A is not the headline:** `read_ticket` p99 (~12.6 ms) and `send_message` p99 (~1.9 ms) share the same proxy stack but hit different STDIO children. The tickets server returns a real payload; the messenger path is lighter. The gap is fixture I/O, not a 7× Interlock penalty.

**Why C looks backwards at first glance:** `ReadTicket` delta (~536 µs) is **larger** than `MonitorSinkBenign` delta (~118 µs) even though the sink path runs the full trifecta + `CheckOverlap`. That is correct, not a measurement bug:

- **`read_ticket`** is a sensitive source. On the **response path**, the engine runs `IngestResult` — taint extraction and canonical-encoding precompute for every secret in the ticket (~15 µs in isolation; +63 allocs/op in the HTTP delta). `EvaluateRequest` early-returns on non-sink calls, but ingestion still runs.
- **`send_message` (monitor, benign)** does not ingest a sensitive result on that call. It evaluates an already-registered taint set via `CheckOverlap` (~70 ns in isolation; +32 allocs/op). Full trifecta logic, but no new taint registration.

**Insight:** per-call engine overhead is dominated by **taint ingestion on sensitive-source reads** (~0.5 ms on the snapshot fixture), not **overlap checking on sink writes** (~0.1 ms). The naive assumption that "the sink-checking path is expensive" is wrong for benign steady state.

**Read-path scaling:** the ~536 µs / +63 allocs delta is for a demo ticket with **2 tainted values**. `IngestResult` registers each secret plus five canonical encodings — cost scales **linearly with secrets-per-result**. A payload returning 50 secrets would be roughly 25× that ingestion work; "~0.5 ms" means "~0.5 ms for a 2-secret read," not a universal ceiling. Same caveat class as the absolute-latency backend-I/O note: measured on a toy fixture; scaling behavior is documented so you can extrapolate.

**Two optimization levers (different hot spots):**

1. **Block path:** evidence construction (~563 µs / 6.3K allocs on trip with in-memory sink). **Async evidence emit (shipped):** `AsyncEvidenceSink` enqueues under `Emit` so JSONL/SQLite/`evidence.json` I/O no longer runs under `Engine.mu` before `Decision` returns. Construction still dominates allocs; sink I/O is off the hot path. Config: `evidence.backpressure: block | drop`, `evidence.queue_size`.
2. **Read path:** taint ingestion + canonical encodings on sensitive results — the bigger **per-benign-call** contributor (~536 µs delta). **Shipped mechanical opts:** `CanonicalEncodings` writes `[]TaintedVariant` directly (no intermediate `EncodedForm` copy); `HashValue` uses `hex.EncodeToString`; `extractResultText` uses `strings.Builder`. Isolated `IngestResult` microbench ~8.2 µs / 38 allocs (was ~14.9 µs / 39; microbench also fixed to reset tainted slice instead of growing forever). HTTP delta remains backend+proxy dominated — expect modest wall-time change on C.

## Engine microbenchmarks

### Methodology

- **Command:** `make bench`
- **Scope:** `internal/engine` only

### Results (representative snapshot)

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| `BenchmarkCanonicalEncodings` | ~88µs | ~800KB | 39 | Per-secret transforms including depth-2 nests + gzip_base64 (gzip writer dominates B/op) |
| `BenchmarkCheckOverlap_1Tainted` | ~1.2µs | 840 | 14 | Sink scan; may reassemble JSON string leaves; more forms than v0.2 five-form set |
| `BenchmarkCheckOverlap_10Tainted` | 517 | 80 | 1 | 10 tainted values (pre-expansion snapshot; re-run after form growth) |
| `BenchmarkCheckOverlap_50Tainted` | 2146 | 80 | 1 | 50 tainted values |
| `BenchmarkEngine_IngestResult_TaintExtract` | 8163 | 2305 | 38 | Sensitive source result ingest + taint (session legs warmed; tainted reset each iter) |
| `BenchmarkEngine_EvaluateRequest_Exfil` | 562798 | 432733 | 6296 | Worst-case block + evidence **construction** (in-memory test sink) — rare trip only; production disk I/O is async via `AsyncEvidenceSink` |

### Reading the engine numbers

- **Overlap check** scales with tainted count × form count; same-call reassembly adds a JSON walk on miss.
- **CanonicalEncodings** grew after depth-2 + `gzip_base64` — registration cost is higher; gzip allocates a large flate window (expected).
- **IngestResult** cost shows up on sensitive **reads** in the HTTP delta, not on sink overlap checks.
- **EvaluateRequest exfil path** is dominated by evidence **construction** on trip. Disk persistence is async (`AsyncEvidenceSink`); further wins require moving `buildEvidence` off the hot path (deferred).

## Known gaps

Each skip test names a **distinct** gap:

| Test | Package | Gap |
|---|---|---|
| `TestEBPF_RingbufSaturation_UnderLoad` | `internal/ebpf` | Root-gated: CI verifies `DropCount` API (`TestLoader_DropCount_Unloaded`); saturation flood requires root + BTF (`sudo go test`) |
| `TestEventLogger_DiskFull_KnownGap` | `internal/proxy` | Disk-full logging behavior |
| `TestEvidenceStore_CrossSessionQuery_KnownGap` | `internal/engine` | SQLite query API / viewer DB integration |

Concurrent multi-session HTTP load p99 is covered by `TestHTTP_ConcurrentLoad_ReadTicket` (CI smoke: `CONCURRENT_SESSIONS=2 OVERHEAD_SAMPLES=100`).

## Reproduce

```bash
make build
make bench-http
make bench
```

Quick HTTP smoke (100 samples):

```bash
OVERHEAD_SAMPLES=100 go test -run=TestHTTP_OverheadReport ./internal/proxy/http/...
```
