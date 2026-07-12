# Interlock — Task List

**Forward plan:** [`ROADMAP.md`](ROADMAP.md) is the source of truth for what ships next. This file tracks **delivery history** and the **active backlog**.

**Legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked

---

## Current state

- `[x]` **v0.1 — Working proof** (2026-07-04). STDIO transport, trifecta engine, Variant A blocking, eBPF `connect()` tripwire, JSONL evidence, HTML viewer. Tagged **`v0.1.0`**.
- `[x]` **v0.2 — Usable tool** (2026-07-05). HTTP/SSE, multi-session, encoding overlap, benches, SQLite opt-in, backpressure. Tagged **`v0.2.0`** / **`v0.2.1`**.
- `[x]` **Post-v0.2 — Async evidence, Variant B payload paths, bounded overlap, openat/DNS, tool-shadowing.** Tagged **`v0.2.2`**. See [`SUMMARY.md`](SUMMARY.md).

**Next:** LSM/KRSI (§3) and enterprise readiness (§5). Phase 4 Trust (corpus, threat model, reproducible releases) **met**. Full queue: [`ROADMAP.md`](ROADMAP.md) **Next build order**.

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

**Detection** (gap priorities: [`SUMMARY.md`](SUMMARY.md) — usage-gated)
- `[x]` eBPF `write()` payload capture — Variant B `EXFIL` upgrade (0.95 with payload proof)
- `[x]` eBPF `sendto()` / UDP payload — self-contained dest+excerpt; dual claim EXFIL/SUSPICIOUS
- `[x]` Same-call JSON reassembly + depth-2 nests + `gzip_base64`; cross-call fragment buffer **met**; depth-3 recursive decoder **met**
- `[x]` `openat()` sensitive paths (`sensitive_paths` config) — `SUSPICIOUS` only
- `[x]` DNS via `sendto` port 53 — `SUSPICIOUS` (or EXFIL if payload overlaps)
- `[x]` Cross-server **tool-shadowing** detection (startup first-owner-wins; mid-session re-registration known gap)

**v0.3 arc** (active — see ROADMAP). Ship order follows integrator demand: **Phase 3 before Phase 2**.

| Phase | Status | Focus |
|---|---|---|
| 1 — Kubernetes DaemonSet | `[x]` | Sensor-only; `--mode=sensor`; PID→pod; `deploy/k8s/`; `make demo-k8s` EXFIL |
| 3 — Operability | `[x]` | Metrics/health, webhook, OCSF SIEM — **met**; systemd + SIGHUP cleanup shipped |
| 2 — LSM/KRSI blocking | `[ ]` | After FP remediation — in-kernel prevent; `sendmsg`/`writev`; fail-closed |
| 4 — Trust | `[x]` | FP corpus + threat model + reproducible release path **met** |

**Phase 3 checklist**
- `[x]` Slice 1 — Prometheus `/metrics` + `/healthz` (`observability.listen`); DaemonSet probes + `service-metrics.yaml`
- `[x]` Slice 2 — trip webhook (Slack/PagerDuty/generic) on evidence emit
- `[x]` Slice 3 — SIEM export (OCSF Detection Finding; CEF deferred)
- `[x]` Cleanup — systemd units + SIGHUP hot-reload (allowlist/sensitive_paths/alerting/siem; K8s primary)

**Phase 4 checklist**
- `[x]` Benign/malicious detection corpus (`internal/corpus`) + published report [`docs/fp_corpus.md`](fp_corpus.md); scope write-up [`docs/detection_boundary.md`](detection_boundary.md). `make fp-corpus` regenerates, `go test ./internal/corpus/...` runs it in CI (no root/BTF/kind). Detection rate 100.0% (20/20 EXFIL-tier, non-gap). Operational FP remediated in **Next build order §1** (relevance-aware blocking, content-binding, leg decay).
- `[x]` Least-privilege audit (documented residual caps) + tamper-resistance threat model — [`threat_model.md`](threat_model.md)
- `[x]` Signed, reproducible releases — `make release`, `SHA256SUMS`, release workflow; [`reproducible_builds.md`](reproducible_builds.md)

**Next build order** (source of truth detail: [`ROADMAP.md`](ROADMAP.md) — ship §1 before amplifying enforcement)

1. **Resolve operational FP rate** — **done**
   - `[x]` Relevance-aware blocking — in block mode, `SUSPICIOUS` without value overlap → evidence/alert + `allowed_monitor`; hard `prevented` / `contained_by_kill` only for `EXFIL`
   - `[x]` Leg decay (TTL and/or N-call) for sticky `sensitive_source_touched` / related legs
   - `[x]` Content-binding — require relationship between untrusted content and sink payload before `SUSPICIOUS`
   - `[x]` Re-run corpus; re-pin benign `ExpectTripByDesign`; do not regress 100% EXFIL detection / 0% EXFIL-tier FP

2. **Close "will cover" detection gaps** — **partial**
   - `[x]` Session-level fragment buffer (cross-call secret splits)
   - `[x]` Fat taint-map scaling benches (gate for fragment buffer)
   - `[x]` `PAYLOAD_MAX=1024` + runtime `ebpf.payload_capture_bytes` (default 512); larger/dynamic / `tcp_sendmsg` still longer-term
   - `[x]` Widen `extractResultText` (bounded string-leaf walk)
   - `[x]` Bounded recursive decoder on sink path (depth-3), fast-path + bench within ~0.5 ms budget
   - `[x]` Capabilities-first DaemonSet + PRIVILEGE managed-cluster checklist / EKS+GKE scripts — **EKS validated 2026-07-12** (caps: load+observe; privileged: full EXFIL); GKE still pending `gcloud auth login`

3. **Strengthen Variant B (kernel prevention + coverage)**
   - `[ ]` LSM/KRSI `socket_connect` → `-EPERM` before packet leaves (throwaway VM first)
   - `[ ]` `sendmsg` / `writev` probes (scatter-gather evasion)

4. **Sensor↔proxy taint bridge**
   - `[x]` Unprivileged proxy forwards taint to node sensor (Unix NDJSON socket; `POD_UID` → `k8s:<podUID>`)

5. **Operability & enterprise readiness**
   - `[ ]` `fail_closed: true` — ringbuf drop / sink failure / panic → block monitored egress
   - `[ ]` CEF SIEM export alongside OCSF
   - `[ ]` Cross-session evidence dashboard / query (`session_id`, verdict, `pod_name`)

**Phase 1 checklist**
- `[x]` Multi-stage Dockerfile (Go + eBPF/BTF runtime) — `make image`
- `[x]` `deploy/k8s/` DaemonSet, RBAC, ConfigMap; documented securityContext ([`PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md))
- `[x]` Host/cgroup PID → container → pod attribution (`internal/k8s`) + `pod_context` on evidence
- `[x]` Node-local watch: register/unregister labeled pod PIDs on schedule/terminate
- `[x]` kind demo path — `make demo-k8s` / `scripts/demo-k8s.sh`
- `[x]` Sensor-mode taint seeding via openat + `/proc` read; `make demo-k8s` shows EXFIL 0.95 with redacted payload excerpt
- `[x]` EKS live pass — AL2023/containerd; caps DaemonSet load+`/healthz`+cross-pod connect/write; privileged DaemonSet seed→EXFIL→kill ([`PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md))

**Launch polish** (optional, not blocking)
- `[x]` README money-shot GIF (`media/ReadmeGif.gif`, viewer screenshots, `make demo-quiet` terminal capture)
- `[x]` 90-second demo recording
- `[x]` Launch post draft

---

## Risks & open questions (living)

- `[ ]` **eBPF portability** across kernels — mitigate: target BTF Ubuntu 6.x; CO-RE for v0.3.
- `[ ]` **Value-overlap false pos/neg** — canonical + depth-2 + gzip_base64 + same-call reassembly + depth-3 decoder; other compressors / depth-4+ missed (known-gap tests).
- `[x]` **Overhead** — engine + single-session HTTP delta + concurrent multi-session absolute p99 published ([`performance.md`](performance.md)); eBPF DropCount CI + root-gated saturation.
- `[x]` **False-positive rate on realistic traffic** — measured then remediated: [`docs/fp_corpus.md`](fp_corpus.md). Sticky/content-blind legs previously drove a high any-trip rate; ROADMAP §1 (relevance-aware blocking, content-binding, leg decay) closed that. EXFIL-tier FP remains 0.0%.
- `[x]` **Sticky, content-blind trifecta legs** — fixed in **Next build order §1**. See [`docs/fp_corpus.md`](fp_corpus.md) and [`ROADMAP.md`](ROADMAP.md).
- `[ ]` **Do not ship LSM hard-prevent on top of today's SUSPICIOUS tripwire** — would amplify operational FPs into host-level denials; §1 before Phase 2.

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
