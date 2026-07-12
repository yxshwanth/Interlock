# Interlock — Roadmap

Interlock v0.1 is a working proof: it catches the lethal trifecta at runtime across two planes (a userspace MCP proxy and a kernel-level eBPF sensor), blocks the chained-tool exfil, contains the server side-channel, and produces a forensic receipt for each. It is deliberately scoped — STDIO transport, `connect()`-only eBPF, single session, heuristic value-overlap.

This roadmap is the path from *proof* to *product*. It's organized in two arcs:

- **v0.2 — Usable Tool.** It touches real MCP, detects things that can't be trivially bypassed, survives concurrency, and has a published performance story.
- **v0.3 — Adoptable Product.** A team can deploy it across a fleet, operate it, integrate it into their existing security stack, and trust it.

**A note on how to read this.** This is a map, not a commitment. Priorities follow dependency and risk; integrator feedback can reorder within an arc. **v0.3 is active** — external demand for fleet deploy / integration cleared the gate that held this arc until after v0.2.

The discipline that made v0.1 credible carries forward: **every detection feature ships with explicit known-gap tests naming what it does *not* catch.** "I catch these, not those, and here's the test proving I know the difference" is the standard, not the exception.

---

## v0.2 — Usable Tool

Closes the five gaps that separate an impressive demo from something someone can actually run against a real agent: real transport, concurrency, non-trivial detection, performance numbers, persistent evidence.

### Phase 1 — HTTP/SSE Transport Interception

The biggest coverage gap. STDIO was the demo; production MCP is HTTP/SSE. Everything else in v0.2 is worth less if the tool only works on toy transport.

- Interpose on HTTP MCP: proxy the JSON-RPC-over-HTTP path; parse request/response bodies into the existing `InterceptedEvent` model.
- Handle SSE streaming — responses arrive as a token stream, not one body, so the framer needs a streaming-aware path.
- Unify the event model so HTTP and STDIO events flow into the *same* engine.

**Done when:** the full trifecta demo runs against an HTTP MCP server, not just STDIO.

**Watch out:**
- SSE plus a proxy creates a buffering hazard. Inspect-then-forward is safe but adds latency; forward-then-inspect is fast but may forward bytes before they're judged — a correctness problem for a *blocking* firewall. This trade-off is the phase's real design decision, not the plumbing. Decide it deliberately and document it.
- HTTP means auth headers, TLS, and connection reuse. Credentials now transit the proxy — the redaction discipline extends here, and TLS termination raises a trust-boundary question (MITM, or sit inside the boundary?).

### Phase 2 — Multi-Session Concurrency and Attribution

STDIO single-session was a demo simplification. Real deployment means many concurrent agents. The schema already carries `session_id`; the logic has to become real.

- Real PID→session mapping under concurrency: a syscall arrives from PID X — which of N active sessions owns it?
- Per-session state isolation in the engine and session store.
- Session lifecycle: creation, expiry, cleanup, and processes that fork children.

**Done when:** two poisoned sessions run concurrently, each correctly attributed, neither leaking state into the other. — **Met** (PR #9, review hardening #10).

- **Shipped:** Per-session backend server pools (spawn on HTTP `initialize`); `SessionManager` with idle expiry; `PIDRegistry` (PID + `/proc` start time); eBPF `RemovePID` + dynamic watch/unwatch; `IngestSyscall` requires explicit `SessionID` (no `FirstSessionID` guess); race CI; unattributed syscall audit trail; `TestConcurrentDualSession_VariantA_Block`; `make demo-http-concurrent`
- **STDIO unchanged:** single session on stdin/stdout as before

**Watch out:**
- The PID→session map is a shared, concurrently-mutated structure — written by the proxy on spawn/exit, read by the eBPF event loop on every syscall. Classic race surface. A syscall can arrive for a PID *after* the process died but *before* cleanup, and the OS can recycle a PID to a different session. **PID reuse is a real correctness bug here** — the key may need to be PID + process-start-time, not PID alone.
- This is where concurrency bugs hide. Run `go test -race` continuously; the demo never surfaces these, only load does.

### Phase 3 — Real Dataflow Taint

Closes the detection-credibility gap for Variant A: encoded exfil in sink args is now caught.

- **Shipped (encoding overlap):** canonical transforms at taint registration — base64, hex, URL-encoding, reversal; depth-2 nests; `gzip_base64`; same-call JSON string reassembly; `CheckOverlap` / `CheckOverlapPayload`; evidence records `match_form`; `RedactJSON` scrubs encoded variants
- **Known gaps (skip tests):** cross-call splits (**met** via fragment buffer), depth-3 nests (**met** via recursive decoder), non-gzip compressors — priority tiers in [`SUMMARY.md`](SUMMARY.md)
- **Shipped (post-v0.2):** eBPF `write()` + `sendto()` first-256 → Variant B `EXFIL` on overlap; connect/DNS/`openat` without overlap → `SUSPICIOUS`. DNS = sendto port 53; openat uses `sensitive_paths`

**Done when:** `TestCheckOverlap_EncodedExfil_KnownGap` passes — **met**.

**Watch out:**
- Full dataflow taint is a research-grade problem with no natural finish line. Scope it hard: cover the common encodings, declare the exotic ones still out of scope, and **keep a known-gap test for them.**
- Performance. Checking every sink payload against every tainted value through N transformations is expensive — Phase 4 benchmarks will quantify this.

### Phase 4 — Performance, Benchmarks, and Persistent Evidence

The "is this operable" gate — **shipped**.

- **Benchmarks:** engine hot-path suite + [`performance.md`](performance.md) with published snapshot (`make bench`)
- **Evidence posture:** JSONL append is the **intentional default** (demo/dev-friendly). SQLite is **opt-in** (`evidence.backend: sqlite` + `max_records`) for bounded restart-safe retention — not a deferred half-feature
- **Backpressure:** `logging.backpressure: block | drop` with runtime stats at shutdown
- **eBPF drops:** kernel `drop_count` map when ring buffer reserve fails; surfaced via `Sensor.DropCount()`

**Done when:** published overhead numbers + evidence always persists; bounded growth available via SQLite — **met** (JSONL default by design; SQLite opt-in).

**Deferred:** Prometheus metrics (v0.3), SQLite for `events.jsonl`

**Post-v0.2 performance (prioritized):**

1. **End-to-end HTTP overhead (A + C)** — **met** (v0.2.1): `TestHTTP_OverheadReport_*`, `BenchmarkHTTP_EngineDelta_*`, `make bench-http`, [`performance.md`](performance.md) snapshot. Passthrough via `proxy.New(..., nil)`. Concurrent multi-session p99 — **met**: `TestHTTP_ConcurrentLoad_ReadTicket` (`CONCURRENT_SESSIONS`, CI smoke).
2. **Async evidence emit** — **met**: `AsyncEvidenceSink` decorator; `evidence.backpressure: block | drop`; trip path no longer waits on JSONL/SQLite I/O under `Engine.mu`. Construction still dominates allocs.
3. **Taint ingestion on sensitive reads** — **met** (mechanical): direct `TaintedVariant` builder, cheaper `HashValue`, `strings.Builder` in `extractResultText`; isolated `IngestResult` ~8.2 µs / 38 allocs. HTTP delta still ~0.5 ms class (backend+proxy); further encoding/extract opts if sub-ms must shrink more.
4. **eBPF ringbuf drop observability** — **met**: CI `TestLoader_DropCount_Unloaded`; root-gated idle + saturation flood (`TestEBPF_RingbufSaturation_UnderLoad`).

**Post-v0.2 detection:**

5. **eBPF write payload capture** — **met**: `sys_enter_write` first-256 bytes; deferred kill ~100 ms; `CheckOverlapPayload` → Variant B `EXFIL` 0.95 when overlap hits. Connect-only stays `SUSPICIOUS` 0.60.
6. **eBPF sendto + openat + DNS** — **met**: self-contained `sendto` (IPv4); DNS via port 53; `openat` + `sensitive_paths` → `SUSPICIOUS` only.

**v0.2 exit state:** works on HTTP/SSE, handles concurrent sessions, catches encoded exfil, has published overhead numbers, persists evidence (JSONL default intentional; SQLite opt-in for retention). **All four phases merged**. Tagged **`v0.2.0`** / **`v0.2.1`**. Current product state (including post-v0.2): [`SUMMARY.md`](SUMMARY.md).

---

## v0.3 — Adoptable Product

Turns the tool into something a team deploys, operates, and trusts at scale. **Active** — integration demand cleared the post-v0.2 gate.

### Phase 1 — Kubernetes-Native Deployment (DaemonSet) `[x]`

**Sensor-only DaemonSet** — no MCP proxy in the privileged pod. Integrators keep their own proxy/sidecar; Interlock supplies kernel visibility.

**Shipped:**
- `--mode=sensor --ebpf` — no proxy; `IngestSyscallSensor` (openat seeds taint; egress contain; EXFIL on overlap)
- `internal/k8s` — cgroup→container ID, `/proc` scan, `PodAttribution`, node-local informer (`interlock.io/monitor=true`)
- Evidence `pod_context` (`namespace`, `pod_name`, `pod_uid`, `node_name`); session id `k8s:<podUID>`
- `Dockerfile` + `make image`; `deploy/k8s/` DaemonSet/RBAC/ConfigMap; [`PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md)
- `make demo-k8s` — kind load, apply, labeled exfil pod, assert **EXFIL** + redacted excerpt

**Honest limit:** production EXFIL still prefers proxy-plane taint; sensor demo seeds via sensitive `openat` + `/proc/<pid>/root`. On EKS, that seed path needs `privileged: true` today (capabilities observe-only). Full trifecta fusion remains proxy+sensor.

**Done when:** deploys to kind and catches egress from a labeled agent pod with pod attribution in evidence — **met**.

**Watch out:**
- **Container PID namespaces.** Solved pragmatically with `hostPID: true` + cgroup matching (not in-container PIDs).
- Privileged surface: try caps + hostPath BTF/tracefs first; EKS validated that caps load/observe but `/proc/<pid>/root` seed needs `privileged: true` (or future taint bridge) — see PRIVILEGE.md.

**Demand reorder:** integrators asked for observability first. **Phase 3 ships before Phase 2.** Phase numbers stay; build order follows demand.

### Phase 3 — Operability: Metrics, Alerting, SIEM `[x]`

The unglamorous layer that decides whether a team keeps it running. **Done when** met: exports metrics and fires a real alert on detection (DaemonSet is the managed deploy path).

**Shipped:**
- **Slice 1:** Prometheus `/metrics` + `/healthz` via `observability.listen` (`internal/observability`); detection counter on async evidence emit; live eBPF `drop_count` + filter gauges; DaemonSet probes + headless `interlock-sensor-metrics` Service. See [`deploy/k8s/README.md`](../deploy/k8s/README.md).
- **Slice 2:** Trip webhooks (`alerting.webhook`) — `generic` | `slack` | `pagerduty`; fan-out via `MultiEmitObserver` after evidence persist.
- **Slice 3:** OCSF Detection Finding export (`siem`, class_uid 2004) to JSONL file and/or HTTP. CEF deferred.

**Cleanup (shipped):** hot-reload via SIGHUP (`egress_allowlist`, `sensitive_paths`, `alerting`, `siem`); systemd units in [`deploy/systemd/`](../deploy/systemd/) for bare-metal hosts (K8s remains the primary deploy path).

**Watch out:**
- SIEM format compliance is finicky and boring, but it is *the* enterprise integration. Get the schema wrong and it won't ingest. Follow the OCSF spec exactly; don't invent fields.

### Phase 2 — Kernel-Level Blocking (LSM/KRSI) and Graceful Enforcement

Upgrades detection from detect-and-kill to actual prevention, closing the honest v0.1 limitation ("contained, not prevented" for Variant B). **Build after the operational FP remediation** (Next build order §1) and when deployment demand requires in-kernel prevention — Phase 3 operability is already met. Detail under **Next build order §3**.

- LSM/KRSI hook on `socket_connect` → `-EPERM` (or equivalent) before the packet leaves; kernel 5.7+.
- Graceful responses beyond SIGKILL: block-the-call, quarantine-the-session, alert-only — configurable per verdict tier (pairs with relevance-aware blocking in §1).
- Fail-closed option (v0.1 was fail-open for the demo; production wants the choice — also listed under Next build order §5).
- Companion: `sendmsg` / `writev` probes so scatter-gather I/O cannot bypass `write`/`sendto`.

**Done when:** Variant B is upgraded — the packet never leaves, and the record reads `prevented`, not `contained_by_kill`.

**Watch out:**
- This is the **highest-risk work in either arc.** Kernel-level blocking via LSM/KRSI is more constrained than tracepoints, more kernel-version-sensitive, and a bug can break the host's networking or deadlock processes. Prototype in a throwaway VM you can destroy, not your main machine.
- **The blast radius inverts.** Once you block in-kernel, you're in the critical path of every connection. A bug no longer means a missed attack — it means broken legitimate traffic, or a downed host. Testing rigor has to level up at exactly this boundary.
- **Do not ship hard in-kernel prevent on top of soft `SUSPICIOUS` signals** — hard prevent belongs on EXFIL-tier (value-overlap) only; §1 made that the enforcement rule.

### Phase 4 — Trust: Self-Security, Validation Corpus, Hardening

What makes senior engineers willing to run privileged kernel code in production.

- [x] Least-privilege audit (documented residual caps) + tamper-resistance threat model for Interlock itself — [`threat_model.md`](threat_model.md)
- [x] Signed, reproducible releases — signed tags (since v0.2.0) + `make release` / checksummed GitHub Release assets — [`reproducible_builds.md`](reproducible_builds.md)
- [x] A real attack-scenario corpus (dozens of trifecta and evasion variants, not one fixture) and a **published false-positive rate** on realistic benign traffic — [`internal/corpus`](../internal/corpus), run in CI via `go test ./internal/corpus/...`, published at [`docs/fp_corpus.md`](fp_corpus.md). **Detection rate 100.0%** (EXFIL-tier, non-gap). Operational any-trip FP remediated in Next build order §1; EXFIL-tier FP stays 0.0%. Detection scope (incl. semantic paraphrase gap): [`detection_boundary.md`](detection_boundary.md).

**Done when:** there's a signed release, a documented threat model, and detection/false-positive numbers on a corpus rather than a single demo. — **met** (corpus + threat model + checksummed release artifacts; cut a signed `v*` tag to publish assets via `.github/workflows/release.yml`).

**Watch out:**
- The **false-positive rate** is where the product lives or dies. A tool that kills legitimate processes gets uninstalled on day one. If the FP rate on realistic traffic is bad, that is the single most important finding in the project, and it should reshape the detection logic — not get buried to protect a launch narrative. This is the v0.1 honesty discipline at product scale.
- **It was bad, and the corpus found it — then §1 fixed it.** The any-trip (operational) false-positive rate previously came back at 46.7%, driven by sticky content-blind legs. Relevance-aware blocking, content-binding, and leg decay closed that. The EXFIL-tier (value-overlap proven) false-positive rate remains 0.0%. See [`docs/fp_corpus.md`](fp_corpus.md).

**v0.3 exit state:** deploys as a Kubernetes DaemonSet, runs as an operable service with metrics and SIEM integration, and ships signed with a threat model and a published false-positive rate. In-kernel prevention (LSM/KRSI) ships when deployment demand requires it — not a hard gate on closing the milestone. An adoptable product.

---

## Next build order (post-corpus)

Ship order after the FP corpus. **§1 (operational FP) is done.** Remaining items must not regress the 0.0% EXFIL-tier false-positive rate or the published engine-overhead class (~0.5 ms / ~0.1 ms).

### 1. Resolve the operational false-positive rate `[x]` — **done**

The corpus finding: sticky, content-blind trifecta legs. Three complementary fixes (shipped together; re-run `make fp-corpus`):

- **Relevance-aware blocking** — decouple the `SUSPICIOUS` tripwire from hard enforcement. In `enforcement: block`, if all legs are lit but `CheckOverlap` / `CheckOverlapPayload` finds no value match, keep verdict `SUSPICIOUS` and emit evidence/alerts, but downgrade action from `prevented` / `contained_by_kill` to `allowed_monitor`. Reserve hard block/kill exclusively for `EXFIL` (0.95).
- **Leg decay (TTL)** — configurable time-to-live and/or N-call decay for `sensitive_source_touched` (and related sticky legs). If a sensitive read is followed by N unrelated tool calls or T minutes with no egress, dim the leg so a poisoned session does not forever treat every external sink as suspicious.
- **Content-binding for legs** — require `untrusted_content_present` to share a byte-level relationship with the `external_sink_invoked` payload before tripping `SUSPICIOUS` (beyond the always-on EXFIL overlap path).

**Done when:** operational any-trip FP rate on the published corpus drops materially (target: well below uninstall-risk), EXFIL-tier detection stays 100% on non-gap malicious, EXFIL-tier FP stays 0.0%, and the seven `ExpectTripByDesign` scenarios are re-pinned honestly.

### 2. Close "will cover" detection gaps `[x]` — **done**

Catalogued in [`SUMMARY.md`](SUMMARY.md) and pinned by `*_KnownGap` / corpus known-gap scenarios:

- **Session-level fragment buffer** — **met**: rolling FIFO (`trifecta.fragment_max_chunks` / `fragment_max_bytes`); reassembly-first taint registration; `malicious_proxy_a_cross_call_split` is detection (not KnownGap).
- **Fat taint-map scaling benches** — **met**: `BenchmarkCheckOverlap_MissPath` at 100/1K/10K; ~100 µs miss-path at 1K ([`performance.md`](performance.md)) — gated simple concat before fragment buffer.
- **eBPF payload capture window** — **met (short-term)**: compiled `PAYLOAD_MAX=1024`; runtime `ebpf.payload_capture_bytes` (default 512, clamped `[64,1024]`). Longer-term: larger/dynamic capture or `tcp_sendmsg` before segmentation.
- **Widen `extractResultText` beyond `content[].text`** — **met**: bounded string-leaf walk; `malicious_proxy_a_secret_outside_content_text` is detection; benign nested-metadata TN re-pinned (unrelated sink).
- **Bounded recursive / dynamic decoder** — **met**: sink-path base64/hex unwrap up to depth-3 after fast-path miss; `MatchForm` `decoded_*`; benches gate miss-path (~100 µs at 1K) and decode-miss (~0.3 ms); `malicious_proxy_a_depth3_nested` is detection.
- **Intra-server write-shaped tools (optional hardening)** — today operators must tag every egress/write tool as `external_sink` (`malicious_gap_untagged_tool_on_sensitive_server`). Future: optional config so write-shaped tools on a `sensitive_source` server inherit sink suspicion unless explicitly allowlisted — more robust, more config surface; not required while the KnownGap stays pinned.

Managed-K8s readiness (capabilities DaemonSet + PRIVILEGE checklist + EKS/GKE scripts) — **EKS validated 2026-07-12** (AL2023/containerd: caps load+observe; privileged full EXFIL). GKE still optional/unvalidated.

### 3. Strengthen Variant B — kernel prevention + syscall coverage `[ ]`

- **LSM/KRSI blocking** (Phase 2) — upgrade from tracepoints to LSM BPF (`socket_connect` → `-EPERM` before the packet forms). Verdict/action becomes true `prevented`, not `contained_by_kill`. Kernel 5.7+, throwaway-VM prototype first.
- **`sendmsg` / `writev` probes** — close scatter-gather egress evasion (today: `write` / `sendto` only).

### 4. Sensor↔proxy taint bridge (K8s) `[x]` — **done**

Sensor-only `openat` + `/proc/<pid>/root` seeding is brittle (misses env, stdin, REST; on EKS capabilities posture the root read is permission-denied). **Shipped:** unprivileged MCP proxy forwards `TaintedValue` (value+variants on the node-local Unix socket; evidence still hash+preview) to the DaemonSet sensor via `taint_bridge` (`internal/bridge`, `Engine.RegisterRemoteTaint`, session `k8s:<podUID>` from `POD_UID`). openat `/proc` seed remains as privileged-demo fallback. See [`deploy/k8s/PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md) and [`proxy-taint-bridge-example.yaml`](../deploy/k8s/proxy-taint-bridge-example.yaml).

### 5. Operability & enterprise readiness `[ ]`

- **Fail-closed mode** — config `fail_closed: true`: ringbuf drops, async sink failure, or engine panic → block egress from monitored pods rather than fail-open with `[SECURITY]` warnings.
- **CEF SIEM export** — extend `internal/siem` beyond OCSF for Splunk/QRadar/ArcSight-class ingest.
- **Cross-session evidence dashboard / query** — beyond the single-record HTML viewer: query by `session_id`, verdict, `pod_name` (SQLite or JSONL index; closes `TestEvidenceStore_CrossSessionQuery_KnownGap`).

**Also still open under Phase 4 Trust:** (none for the Trust “done when” gate — threat model + reproducible release path **met**). Remaining enterprise items live under Next build order §5 (fail-closed, CEF, cross-session query). Capability drop post-attach and bridge peer-auth remain documented residual risks in [`threat_model.md`](threat_model.md).

---

## Cross-Cutting Hazards

Four things span both arcs and are the most likely to cause real damage:

- **Concurrency and races** (v0.2 Phase 2, v0.3 Phase 1) — PID reuse, namespace translation, shared-map mutation. `go test -race` is not optional. Demos never surface these; load does.
- **Performance vs detection depth** — every detection feature (taint, payload inspection, per-session tracking) taxes the hot path. Benchmark continuously, not once, or the tool becomes too expensive to run.
- **Scope-infinity** on taint and validation — both are bottomless. Bound them with explicit known-gap tests. Naming what you don't catch is the signature discipline; keep making that move.
- **The blast-radius inversion** (v0.3 Phase 2) — the moment enforcement moves from observing to blocking in-kernel, a bug stops meaning "missed detection" and starts meaning "broke the host."

---

## Backlog (Beyond v0.3)

Pulled forward into **Next build order** above (do not duplicate as "someday"): operational FP remediation; cross-call fragment buffer; `PAYLOAD_MAX` / deeper capture; depth-3 decoder; LSM/KRSI; `sendmsg`/`writev`; proxy↔sensor taint bridge; fail-closed; CEF; cross-session evidence query.

Still deferred until demand justifies them: IPv6; Unix-socket and file-based exfil paths; role-based access and operator audit logs; ARM support and cross-distro/CO-RE portability; a managed cloud offering; third-party security audit and red-team results; comparison benchmarks against static scanners.

**Out of scope (not backlog):** DoH/DoT — mitigate with network-layer DNS controls; see [`SUMMARY.md`](SUMMARY.md).

Detection gap priorities also live in [`SUMMARY.md`](SUMMARY.md); the Next build order is the execution queue.
