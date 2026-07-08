# Interlock — Task List

**Forward plan:** [`ROADMAP.md`](ROADMAP.md) is the source of truth for what ships next. This file tracks **delivery history** and the **active backlog**.

**Legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked

---

## Current state

- `[x]` **v0.1 — Working proof** (2026-07-04). STDIO transport, trifecta engine, Variant A blocking, eBPF `connect()` tripwire, JSONL evidence, HTML viewer. Tagged **`v0.1.0`**.
- `[x]` **v0.2 — Usable tool** (2026-07-05). HTTP/SSE transport, multi-session concurrency, bounded encoding overlap, engine benchmarks, SQLite evidence (opt-in), backpressure, eBPF drop counter. Tagged **`v0.2.0`**. See [`v0.2_summary.md`](v0.2_summary.md).
- `[x]` **v0.2.1 — HTTP overhead** (2026-07-05). End-to-end HTTP overhead A+C (`TestHTTP_OverheadReport_*`, `BenchmarkHTTP_EngineDelta_*`), `make bench-http`, CI smoke. Tagged **`v0.2.1`**. PR [#17](https://github.com/yxshwanth/Interlock/pull/17).

**Next:** post-v0.2 backlog below — build v0.3 only if v0.2 produces demand ([`ROADMAP.md`](ROADMAP.md)).

---

## v0.2 delivery checklist

| Phase | Status | PR |
|---|---|---|
| 1 — HTTP/SSE transport | `[x]` | [#8](https://github.com/yxshwanth/Interlock/pull/8) |
| 2 — Multi-session concurrency | `[x]` | [#9](https://github.com/yxshwanth/Interlock/pull/9), review [#10](https://github.com/yxshwanth/Interlock/pull/10) |
| 3 — Bounded encoding overlap | `[x]` | [#12](https://github.com/yxshwanth/Interlock/pull/12) |
| 4 — Benchmarks + persistence | `[x]` | [#14](https://github.com/yxshwanth/Interlock/pull/14) |
| Post-release — HTTP overhead A+C | `[x]` | [#17](https://github.com/yxshwanth/Interlock/pull/17) |

---

## Active backlog (post-v0.2)

**Performance & operability**
- `[ ]` **Async evidence emit** — decouple block decision from receipt write (~563 µs trip path)
- `[ ]` **Taint ingestion optimization** — sensitive-read path dominates benign overhead (~536 µs delta on 2-secret fixture)
- `[ ]` **Concurrent HTTP load p99** — `TestHTTP_ConcurrentLoad_KnownGap`
- `[ ]` **eBPF ring-buffer saturation CI** — `TestEBPF_RingbufSaturation_KnownGap`

**Detection**
- `[ ]` eBPF `sendto`/`write` payload capture — Variant B `EXFIL` upgrade (0.95 with payload proof)
- `[ ]` Additional eBPF probes: `openat()` (sensitive paths), DNS resolution
- `[ ]` Cross-server **tool-shadowing** detection

**v0.3 arc** (demand-gated — see ROADMAP)
- `[ ]` Kubernetes DaemonSet deployment
- `[ ]` LSM/KRSI kernel-level blocking (Variant B prevent, not contain)
- `[ ]` Daemon mode, hot-reload config, Prometheus metrics, SIEM export
- `[ ]` Signed releases, threat model, published false-positive corpus

**Launch polish** (optional, not blocking)
- `[x]` README money-shot GIF (`media/ReadmeGif.gif`, viewer screenshots, `make demo-quiet` terminal capture)
- `[ ]` 90-second demo recording
- `[ ]` Launch post draft

---

## Risks & open questions (living)

- `[ ]` **eBPF portability** across kernels — mitigate: target BTF Ubuntu 6.x; CO-RE for v0.3.
- `[ ]` **Value-overlap false pos/neg** — canonical encodings caught; split/compressed/nested missed (known-gap tests).
- `[~]` **Overhead** — engine + single-session HTTP delta published ([`performance.md`](performance.md)); concurrent multi-session load and eBPF saturation still open.
- `[ ]` **False-positive rate on realistic traffic** — v0.3 trust gate; bad FP rate reshapes detection logic.

---

## Archive — v0.1 build sequence (complete)

<details>
<summary>Week 0–4 task breakdown (historical)</summary>

### Week 0 — Strategy & specs `[x]`
Problem validated, v0.1 scoped, docs written.

### Week 1 — Transparent proxy `[x]`
JSON-RPC framing, multi-server proxy, toy servers, demo client, full framer tests.

### Week 2 — Trifecta engine + enforcement `[x]`
State machine, taint extraction, value overlap, hold-before-forward, evidence JSONL, HTML viewer, poisoned fixture.

### Week 3 — eBPF sensor (Variant B) `[x]`
`connect()` probe, PID filter map, ring buffer, `IngestSyscall`, kill-on-detect, exfil fixture, fused timeline.

### Week 4 — Harden, film, write `[~]`
Redaction, fail-open docs, one-command demo, CI/CONTRIBUTING done. GIF, demo video, launch post still open.

</details>
