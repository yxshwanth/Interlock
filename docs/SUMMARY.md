# Interlock — Current Summary

**Latest tagged release:** [`v0.2.2`](https://github.com/yxshwanth/Interlock/releases/tag/v0.2.2) (2026-07-10).  
**This tree:** tagged **`v0.3.0`** — Phase 1 (Kubernetes DaemonSet), Phase 3 (metrics, alerting, SIEM, systemd/hot-reload), Phase 4 Trust (FP corpus, threat model, reproducible releases). See [`CHANGELOG.md`](../CHANGELOG.md#030---2026-07-12).

Living docs: [`architecture.md`](architecture.md) · [`ROADMAP.md`](ROADMAP.md) · [`task_list.md`](task_list.md) · [`performance.md`](performance.md) · [`fp_corpus.md`](fp_corpus.md) · [`detection_boundary.md`](detection_boundary.md) · [`project_overview.md`](project_overview.md)

---

## What Interlock is

Runtime MCP exfiltration detection across **two planes**:

| Plane | Role | Verdict when tripped |
|---|---|---|
| **Proxy (Variant A)** | Inspect tool-call chains; block sink calls that carry tainted secrets (encoding-aware) | `EXFIL` 0.95 |
| **eBPF (Variant B)** | Kernel probes on monitored PIDs; contain via SIGKILL | `EXFIL` 0.95 with payload overlap; else `SUSPICIOUS` 0.60 |

Honest asymmetry: Variant A **prevents**; Variant B **detects + contains** (first packet may already have left).

---

## Shipped capabilities (current)

### Transport & sessions
- STDIO (default) and Streamable HTTP/SSE (`2025-11-25`)
- Multi-session HTTP with per-session backend pools + PID→session attribution

### Detection — Variant A
- Trifecta legs + taint extraction on sensitive sources
- Canonical forms: literal, base64, hex, URL-encoding, reversal
- Depth-2 nests (`base64_hex`, `hex_base64`, `base64_url`, `base64_reversed`) + `gzip_base64`
- Same-call JSON string reassembly (secret split across fields in one `tools/call`)
- Evidence records `match_form`; `RedactJSON` scrubs variants
- Cross-server tool-shadowing at registration: first-owner-wins; `tool_shadowing` audit

### Detection — Variant B
- `connect()` (IPv4) tripwire → `SUSPICIOUS` / deferred kill (~100 ms)
- `write()` first-256 bytes correlated to recent non-allowlisted connect/`sendto` → `EXFIL` on overlap
- `sendto()` self-contained dest + first-256 → dual claim; port **53** tagged as `dns`
- `openat()` + config `sensitive_paths` → `SUSPICIOUS` only (open ≠ proven exfil)

### Operability
- Async evidence emit (`AsyncEvidenceSink`, `evidence.backpressure`)
- Evidence posture: **JSONL intentional default**; SQLite opt-in for retention
- Event-log backpressure; eBPF `drop_count`; runtime stats
- Published overhead: [`performance.md`](performance.md) — engine delta ~0.5 ms sensitive reads / ~0.1 ms sink checks; `CheckOverlap` miss-path ~100 µs at 1K tainted (fragment-buffer gate); concurrent HTTP absolute p99 via `TestHTTP_ConcurrentLoad_ReadTicket`

### Demos
- `make demo` / `make demo-ebpf`: Pass 1 literal breach → Pass 2 `gzip_base64` block → Pass 3 payload EXFIL + kill (`INTERLOCK_EXFIL_MODE=local` + `interlock-ebpf-local.yaml`); HTTP variants separate

### v0.3 Phase 1 — Kubernetes DaemonSet (shipped, untagged)
- Sensor-only mode (`--mode=sensor --ebpf`, no MCP proxy) — `internal/k8s` node-local pod watcher, cgroup→container→pod attribution (`interlock.io/monitor=true`)
- `IngestSyscallSensor`: sensitive `openat` seeds taint via `/proc/<pid>/root`; egress connect/write/sendto/DNS contain; payload overlap → **EXFIL 0.95** with redacted excerpt
- Evidence `pod_context` (namespace/pod/uid/node); `Dockerfile` + `make image`; `deploy/k8s/` (DaemonSet privileged + capabilities, RBAC, ConfigMap, metrics Service, `eks/` helpers); `make demo-k8s` on kind; **EKS validated** 2026-07-12 (caps observe / privileged EXFIL) — [`PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md)
- Honest limit: production EXFIL still prefers proxy-plane taint; sensor demo seeds via `openat` + `/proc`

### v0.3 Phase 3 — Operability (shipped, untagged)
- **Metrics/health** (`internal/observability`): `/metrics` + `/healthz` on `observability.listen`; detection/drop/ringbuf/watched-PID gauges and counters; DaemonSet probes + headless metrics Service
- **Trip webhooks** (`internal/alerting`): async POST on evidence emit — `generic` | `slack` | `pagerduty`, `min_verdict` filter, bounded concurrency
- **SIEM export** (`internal/siem`): OCSF 1.3 Detection Finding (`class_uid=2004`) to JSONL file and/or HTTP; CEF deferred
- **Hot-reload** (`internal/reload`): `SIGHUP` live-swaps allowlist/sensitive-paths/alerting/SIEM without a restart; invalid config keeps the previous one; non-reloadable fields (enforcement, transport, observability.listen, evidence backend/path, server count) logged as restart-required
- **systemd units** (`deploy/systemd/`) for bare-metal/VM hosts — Kubernetes remains the primary deploy path

### v0.3 Phase 4 — Trust (corpus + threat model + releases; shipped, untagged)

- FP corpus / detection boundary — see below
- TCB threat model: [`threat_model.md`](threat_model.md)
- Reproducible builds + checksummed GitHub Releases: [`reproducible_builds.md`](reproducible_builds.md)

### v0.3 Phase 4 — Benign/malicious detection corpus (shipped, untagged)
- `internal/corpus`: 55 scenarios (25 malicious incl. 5 documented `KnownGap` misses, 30 benign) drive `internal/engine` directly — no proxy, no kernel; CI-safe via `go test ./internal/corpus/...`
- Detection scope (programmatic vs semantic): [`docs/detection_boundary.md`](detection_boundary.md)
- Published report: [`docs/fp_corpus.md`](fp_corpus.md), regenerated with `make fp-corpus` → `cmd/fp-corpus`
- **Detection rate: 100.0% (20/20, EXFIL-tier, non-gap). Operational FP remediated** (relevance-aware blocking, content-binding, leg decay) — see `docs/fp_corpus.md`. EXFIL-tier FP remains 0.0%. Semantic paraphrase exfil is an intentional KnownGap ([`detection_boundary.md`](detection_boundary.md)).
- Fragment buffer, `PAYLOAD_MAX` / `payload_capture_bytes`, widened `extractResultText`, depth-3 recursive decoder **met**.
- Finding (historical): sticky, content-blind trifecta legs previously drove a high any-trip rate; fixed in ROADMAP §1.

---

## Known gaps (prioritized)

Canonical honesty layer: which gaps matter, which are tractable, which are someone else's problem. Close what real usage reveals; leave the rest named until they stop being theoretical.

### Will cover — real detection value, tractable

| Gap | Trigger / why deferred |
|---|---|
| Cross-call secret splits | Same-call reassembly shipped; needs a session-level fragment buffer across sequential tool/call responses |
| Secrets past capture window | Runtime `ebpf.payload_capture_bytes` (default 512, max compiled 1024); measure ringbuf drops under load (`TestEBPF_RingbufSaturation_UnderLoad`) |
| First-packet prevention (LSM/KRSI) | v0.3 Phase 2; closes Variant B “contained, not prevented”; prototype in a throwaway VM |
| Sensor-only EXFIL-with-overlap | Without proxy taint: seed via sensitive `openat` + `/proc/<pid>/root` read (demo); production bridge still deferred |

### Will cover eventually — diminishing returns, real gaps

| Gap | Trigger / why deferred |
|---|---|
| Depth-3+ / other compressors (zstd, deflate-raw) | Depth-2 + gzip covers common cases; add one-at-a-time when a real bypass shows up |
| IPv6, `sendmsg`/`writev` | AF_INET / `write`/`sendto` only today; weekend plumbing, not architecture |
| Write before suspicious connect | Correlation assumes connect→write; expand window bidirectionally when this false-negative surfaces |
| Tool-shadowing runtime re-registration | Startup detection shipped; most servers declare tools once — build when dynamic mid-session registration is common |

### Probably never / out of scope — wrong trade-off

| Gap | Why |
|---|---|
| **DoH/DoT** | Encrypted DNS is indistinguishable from other TLS without interception; mitigate with **network-layer DNS controls**, not inside Interlock |
| Exotic/custom multi-layer compressors | Attacker has infinite encodings; Variant B raw-byte overlap is encoding-agnostic when payload capture works; Variant A stays bounded to the common set |

A tool that claims no gaps is lying; a tool that names them is honest. Keep the list.

---

## What’s next

**Shipped in `v0.2.2`.** **v0.3 Phase 1 (sensor-only DaemonSet) is implemented** — `--mode=sensor`, PID→pod attribution, `deploy/k8s/`, `make demo-k8s`. **EKS validated 2026-07-12** (AL2023/containerd): capabilities load + cross-pod observe; privileged DaemonSet full EXFIL seed→trip→kill — [`PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md).

**Now:** LSM/KRSI + enterprise readiness (fail-closed, CEF, cross-session query). Phase 4 Trust **met**. Queue: [`ROADMAP.md`](ROADMAP.md) **Next build order**.  
**Then:** Phase 2 LSM/KRSI (hard prevent only on EXFIL-tier signals after §1).

Details: [`task_list.md`](task_list.md), [`ROADMAP.md`](ROADMAP.md), [`deploy/k8s/PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md).

---

## Reproduce

```bash
make build && make test
make demo                  # proxy-only
sudo make demo-ebpf GO=$(which go)
make bench && make bench-http
make image && make demo-k8s   # sensor DaemonSet on kind (docker/kind/kubectl + BTF)
# EKS: deploy/k8s/eks/ — see PRIVILEGE.md (validated AL2023/containerd 2026-07-12)
```

eBPF needs root + BTF kernel. CI covers unit/race + DropCount API; live probe load is local/`sudo`. Managed-cluster EXFIL without privileged `/proc` seed uses the sensor↔proxy taint bridge (`taint_bridge`); openat seed remains privileged-demo fallback.

---

## Milestone history (short)

| Tag | What |
|---|---|
| `v0.1.0` | STDIO proof: trifecta, Variant A block, connect tripwire, JSONL evidence |
| `v0.2.0` | HTTP/SSE, multi-session, encoding overlap, benches, SQLite opt-in, backpressure |
| `v0.2.1` | End-to-end HTTP overhead A+C |
| `v0.2.2` | Async evidence; write/sendto/openat/DNS; bounded overlap expansion; tool-shadowing; concurrent load + ringbuf tests |
