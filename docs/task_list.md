# Interlock — Task List

**Forward plan:** [`ROADMAP.md`](ROADMAP.md) is the source of truth for what ships next. This file tracks **delivery history** and the **active backlog**.

**Legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked

---

## Current state

- `[x]` **v0.1 — Working proof** (2026-07-04). STDIO transport, trifecta engine, Variant A blocking, eBPF `connect()` tripwire, JSONL evidence, HTML viewer. Tagged **`v0.1.0`**.
- `[x]` **v0.2 — Usable tool** (2026-07-05). HTTP/SSE, multi-session, encoding overlap, benches, SQLite opt-in, backpressure. Tagged **`v0.2.0`** / **`v0.2.1`**.
- `[x]` **Post-v0.2 — Async evidence, Variant B payload paths, bounded overlap, openat/DNS.** See [`SUMMARY.md`](SUMMARY.md).

**Next:** remaining backlog below — build v0.3 only if demand appears ([`ROADMAP.md`](ROADMAP.md)). Full current state: [`SUMMARY.md`](SUMMARY.md).

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
- `[x]` **Async evidence emit** — `AsyncEvidenceSink`; evidence.backpressure block|drop
- `[x]` **Taint ingestion optimization** — direct `TaintedVariant` builder; isolated IngestResult ~8.2 µs / 38 allocs
- `[x]` **Concurrent HTTP load p99** — `TestHTTP_ConcurrentLoad_ReadTicket` (`CONCURRENT_SESSIONS`)
- `[x]` **eBPF ring-buffer saturation** — CI DropCount API; root-gated `TestEBPF_RingbufSaturation_UnderLoad`

**Detection**
- `[x]` eBPF `write()` payload capture — Variant B `EXFIL` upgrade (0.95 with payload proof)
- `[x]` eBPF `sendto()` / UDP payload — self-contained dest+excerpt; dual claim EXFIL/SUSPICIOUS
- `[x]` Same-call JSON reassembly + depth-2 nests + `gzip_base64` (cross-call / depth-3+ still KnownGap)
- `[x]` `openat()` sensitive paths (`sensitive_paths` config) — `SUSPICIOUS` only
- `[x]` DNS via `sendto` port 53 — `SUSPICIOUS` (or EXFIL if payload overlaps)
- `[x]` Cross-server **tool-shadowing** detection (startup first-owner-wins; mid-session re-registration known gap)

**v0.3 arc** (demand-gated — see ROADMAP)
- `[ ]` Kubernetes DaemonSet deployment
- `[ ]` LSM/KRSI kernel-level blocking (Variant B prevent, not contain)
- `[ ]` Daemon mode, hot-reload config, Prometheus metrics, SIEM export
- `[ ]` Signed releases, threat model, published false-positive corpus

**Launch polish** (optional, not blocking)
- `[x]` README money-shot GIF (`media/ReadmeGif.gif`, viewer screenshots, `make demo-quiet` terminal capture)
- `[x]` 90-second demo recording
- `[x]` Launch post draft

---

## Risks & open questions (living)

- `[ ]` **eBPF portability** across kernels — mitigate: target BTF Ubuntu 6.x; CO-RE for v0.3.
- `[ ]` **Value-overlap false pos/neg** — canonical + depth-2 + gzip_base64 + same-call reassembly; cross-call / depth-3+ / other compressors missed (known-gap tests).
- `[x]` **Overhead** — engine + single-session HTTP delta + concurrent multi-session absolute p99 published ([`performance.md`](performance.md)); eBPF DropCount CI + root-gated saturation.
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

### Week 4 — Harden, film, write `[x]`
Redaction, fail-open docs, one-command demo, CI/CONTRIBUTING done. GIF, demo video, and launch post shipped.

</details>
