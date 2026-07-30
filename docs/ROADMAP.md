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
- **Known gaps (skip tests):** custom ciphers remain open; ZIP/xlsx **whole-file** (§18) and extracted/sink container descent (§20) are **met**; cross-call splits / depth nests / compressors met earlier — priority tiers in [`architecture.md`](architecture.md) §13 and [`INTERLOCK.md`](INTERLOCK.md) §16
- **Shipped (post-v0.2):** eBPF `write()` + `sendto()` payload capture (runtime `payload_capture_bytes`, default **1024** / max 1024 — raised in ROADMAP §16) → Variant B `EXFIL` on overlap; connect/DNS/`openat` without overlap → `SUSPICIOUS`. DNS = sendto port 53; openat uses `sensitive_paths`

**Done when:** `TestCheckOverlap_EncodedExfil_KnownGap` passes — **met**.

**Watch out:**
- Full dataflow taint is a research-grade problem with no natural finish line. Scope it hard: cover the common encodings, declare the exotic ones still out of scope, and **keep a known-gap test for them.**
- Performance. Checking every sink payload against every tainted value through N transformations is expensive — Phase 4 benchmarks will quantify this.

### Phase 4 — Performance, Benchmarks, and Persistent Evidence

The "is this operable" gate — **shipped**.

- **Benchmarks:** engine hot-path suite + [`performance.md`](performance.md) with published snapshot (`make bench`)
- **Evidence posture:** JSONL append is the **intentional default** (demo/dev-friendly). SQLite is **opt-in** (`evidence.backend: sqlite` + `max_records`) for bounded restart-safe retention — not a deferred half-feature
- **Backpressure:** `logging.backpressure: block | drop` with runtime stats at shutdown
- **eBPF drops:** dual kernel maps — `drop_count` (routine: connect/openat) and `critical_drop_count` (write/sendto/lsm_deny); surfaced via `Sensor.DropCount()` / `Sensor.CriticalDropCount()`

**Done when:** published overhead numbers + evidence always persists; bounded growth available via SQLite — **met** (JSONL default by design; SQLite opt-in).

**Deferred:** Prometheus metrics (v0.3), SQLite for `events.jsonl`

**Post-v0.2 performance (prioritized):**

1. **End-to-end HTTP overhead (A + C)** — **met** (v0.2.1): `TestHTTP_OverheadReport_*`, `BenchmarkHTTP_EngineDelta_*`, `make bench-http`, [`performance.md`](performance.md) snapshot. Passthrough via `proxy.New(..., nil)`. Concurrent multi-session p99 — **met**: `TestHTTP_ConcurrentLoad_ReadTicket` (`CONCURRENT_SESSIONS`, CI smoke).
2. **Async evidence emit** — **met**: `AsyncEvidenceSink` decorator; `evidence.backpressure: block | drop`; trip path no longer waits on JSONL/SQLite I/O under `Engine.mu`. Construction still dominates allocs.
3. **Taint ingestion on sensitive reads** — **met** (mechanical): direct `TaintedVariant` builder, cheaper `HashValue`, `strings.Builder` in `extractResultText`; isolated `IngestResult` ~8.2 µs / 38 allocs. HTTP delta still ~0.5 ms class (backend+proxy); further encoding/extract opts if sub-ms must shrink more.
4. **eBPF ringbuf drop observability** — **met**: CI unloaded DropCount/CriticalDropCount; root-gated idle + segregated saturation floods (`TestEBPF_RingbufSaturation_UnderLoad`); dual rings so connect floods cannot starve EXFIL/`lsm_deny` (`TestLSM_DenySurvivesConnectFlood`).

**Post-v0.2 detection:**

5. **eBPF write payload capture** — **met**: `sys_enter_write` / `sendto` payload excerpts; `CheckOverlapPayload` → Variant B `EXFIL` 0.95 when overlap hits, killed immediately (no deferred window — the pre-§1 "wait then kill on suspicion" design was retired; see §1 below). Runtime `ebpf.payload_capture_bytes` (default **1024** = compiled max; raised in §16 from 512). Connect-only stays `SUSPICIOUS` 0.60 on a proxy-tied session — sensor-only mode has no untrusted-content leg and can only reach `EXFIL`.
6. **eBPF sendto + openat + DNS** — **met**: self-contained `sendto` (IPv4); DNS via port 53; `openat` + `sensitive_paths` → `SUSPICIOUS` only.

**v0.2 exit state:** works on HTTP/SSE, handles concurrent sessions, catches encoded exfil, has published overhead numbers, persists evidence (JSONL default intentional; SQLite opt-in for retention). **All four phases merged**. Tagged **`v0.2.0`** / **`v0.2.1`**. Status / next work: [`ROADMAP.md`](ROADMAP.md) (this file) **Next build order**; gap tiers: [`architecture.md`](architecture.md) §13.

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
- **Slice 1:** Prometheus `/metrics` + `/healthz` via `observability.listen` (`internal/observability`); detection counter on async evidence emit; live eBPF routine + critical ringbuf drop gauges + filter gauges; DaemonSet probes + headless `interlock-sensor-metrics` Service. See [`deploy/k8s/README.md`](../deploy/k8s/README.md).
- **Slice 2:** Trip webhooks (`alerting.webhook`) — `generic` | `slack` | `pagerduty`; fan-out via `MultiEmitObserver` after evidence persist.
- **Slice 3:** OCSF Detection Finding export (`siem`, class_uid 2004) to JSONL file and/or HTTP. CEF deferred.

**Cleanup (shipped):** hot-reload via SIGHUP (`egress_allowlist`, `sensitive_paths`, `alerting`, `siem`); systemd units in [`deploy/systemd/`](../deploy/systemd/) for bare-metal hosts (K8s remains the primary deploy path).

**Watch out:**
- SIEM format compliance is finicky and boring, but it is *the* enterprise integration. Get the schema wrong and it won't ingest. Follow the OCSF spec exactly; don't invent fields.

### Phase 2 — Kernel-Level Blocking (LSM/KRSI) and Graceful Enforcement

Upgrades detection from detect-and-kill to actual prevention, closing the honest v0.1 limitation ("contained, not prevented" for Variant B).

**Slice 1 — shipped, opt-in (`ebpf.lsm_enforce`, default `false`):**
- `BPF_PROG_TYPE_LSM` hook on `security_socket_connect` (`SEC("lsm/socket_connect")`, `internal/ebpf/bpf/connect.c`) → `-EPERM` before the socket forms. Validated on kernel 6.8 (Ubuntu 24.04) on a throwaway EC2 VM.
- **Honest scope:** `connect()` carries no payload, so this hook cannot decide EXFIL itself — it enforces a quarantine flag that userspace sets *only after* the existing write/`sendto` payload-overlap path has already confirmed EXFIL for a PID/cgroup. Concretely: the *first* EXFIL-carrying packet is still `contained_by_kill` (unchanged, no regression risk); any *further* `connect()` from that PID/cgroup — a forked child sharing the cgroup, a kill that races, or a respawned process — is denied in-kernel and recorded as `prevented`.
- Fails soft: missing `CONFIG_BPF_LSM` / `"bpf"` LSM / capabilities → logged `[SECURITY]` warning, sensor keeps running tracepoint-only (never blocks startup).
- Dual-keyed (PID + cgroup) `lsm_blocklist`, cleared on `RemovePID`/`RemoveCgroupID` to avoid a PID-reuse hazard.

**Still open (separate follow-ups, unchanged scope from before Slice 1):**
- Graceful responses beyond SIGKILL: block-the-call, quarantine-the-session, alert-only — configurable per verdict tier (pairs with relevance-aware blocking in §1).
- Larger/dynamic payload capture or pre-segmentation `tcp_sendmsg` (first-iov `writev`/`sendmsg` + IPv6 dest layout are shipped).

**Shipped elsewhere (do not re-open here):** fail-closed (`fail_closed.enabled`, Next build order §5); dual ringbufs (routine vs critical, §5); evidence hash chain (§6).

**Done when:** Variant B is upgraded — the packet never leaves, and the record reads `prevented`, not `contained_by_kill`. **Partially met:** true for *repeat* connection attempts after an EXFIL trip (Slice 1); the *first* EXFIL-carrying packet remains `contained_by_kill` by construction (connect() precedes the payload that proves EXFIL) — not a target for a future slice, an architectural boundary.

**Watch out:**
- This is the **highest-risk work in either arc.** Kernel-level blocking via LSM/KRSI is more constrained than tracepoints, more kernel-version-sensitive, and a bug can break the host's networking or deadlock processes. Prototype in a throwaway VM you can destroy, not your main machine. (Slice 1 followed this discipline — see [`deploy/ec2/README.md`](../deploy/ec2/README.md).)
- **The blast radius inverts.** Once you block in-kernel, you're in the critical path of every connection. A bug no longer means a missed attack — it means broken legitimate traffic, or a downed host. Testing rigor has to level up at exactly this boundary.
- **Do not ship hard in-kernel prevent on top of soft `SUSPICIOUS` signals** — hard prevent belongs on EXFIL-tier (value-overlap) only; §1 made that the enforcement rule. Slice 1 honors this: the quarantine flag is only ever set after an EXFIL confirmation, never on a bare `SUSPICIOUS` connect.

### Phase 4 — Trust: Self-Security, Validation Corpus, Hardening

What makes senior engineers willing to run privileged kernel code in production.

- [x] Least-privilege audit (documented residual caps) + tamper-resistance threat model for Interlock itself — [`threat_model.md`](threat_model.md)
- [x] Signed, reproducible releases — signed tags (since v0.2.0) + `make release` / checksummed GitHub Release assets — [`reproducible_builds.md`](reproducible_builds.md)
- [x] A real attack-scenario corpus (dozens of trifecta and evasion variants, not one fixture) and a **published false-positive rate** on realistic benign traffic — [`internal/corpus`](../internal/corpus), run in CI via `go test ./internal/corpus/...`, published at [`docs/fp_corpus.md`](fp_corpus.md). **Detection rate 100.0%** (EXFIL-tier, non-gap). Operational any-trip FP remediated in Next build order §1; EXFIL-tier FP stays 0.0%. Detection scope (incl. semantic paraphrase gap): [`detection_boundary.md`](detection_boundary.md).
- [x] **A second corpus reconstructed from published, third-party-disclosed MCP CVEs** (not self-authored) — [`internal/corpus/scenarios_cve.go`](../internal/corpus/scenarios_cve.go), run in CI via `go test ./internal/corpus/... -run TestCVECorpus`, published at [`docs/cve_corpus.md`](cve_corpus.md). **7 CVE families reconstructed** (`mcp-server-git`, Figma MCP, GPT Researcher, Fetch MCP, Apache Doris MCP, excel-mcp-server, Anthropic Filesystem MCP) — **15 genuine reconstructions** (Filesystem contributes 3 catching: JSON exfil + PEM proxy + PEM eBPF chunk catch via ROADMAP §8; other families ≤2), five escape full-misses (git wire protocol, unregistered ZIP compression, recursive-decode-depth exhaustion, blind-SQLi taint gap, sensor-mode structural gap), one soft-catch (DNS-fragmented exfil), plus one fix-demonstration scenario explicitly excluded from the count. Reported per-family, not as a single rate — the denominator (which families/variants got authored) is itself a choice, and the report says so plainly; still smaller than Endor Labs/CSA's catalogued shapes, so it keeps growing rather than being treated as settled. A separately-tallied out-of-scope list (7 disclosure groups) of CVEs whose mechanism (spawn-time config injection, transport downgrade, registry poisoning, browser-reachable dev tooling) sits entirely outside a post-session behavioral monitor's remit. This is the credibility move the self-authored 100.0% number can't make on its own, and it partially answers the still-deferred "third-party security audit and red-team results" backlog item without needing a red-team budget.
- **It found a live bug on the first run, same shape as §1's 46.7% finding — and a second, deeper, still-open one alongside it.** The corpus's connect-only reverse-shell reconstruction (`cve_2025_53967_figma_reverse_shell_connect_only_gap`) proved that §1's content-binding fix had an unintended side effect: `CheckContentBind` rejects an empty sink string before any comparison, so a bare `connect()` — the exact case Variant B exists for — could never reach `SUSPICIOUS` at all on a proxy-tied session, regardless of how many legs were genuinely lit. Fixed: `classifyTrip` (`internal/engine/engine.go`) now distinguishes "no payload channel at all" from "payload channel present but unrelated," restoring the soft tripwire without reopening any hard-block-on-suspicion path; the independently-dead ~100 ms deferred-kill subsystem (`scheduleContain`/`scheduleKill`/`flushDeferredKills`/`killLoop`, `internal/ebpf/sensor.go`) was removed rather than left describing a mechanism that could never fire post-§1. `TestEngine_IngestSyscall_ConnectOnly_AllLit_Suspicious` pins it. **But the fix does not change the CVE reconstruction's own outcome**, because that reconstruction is faithfully sensor-only (matching the CVE's own shape, and the DaemonSet's deploy shape) — and sensor-only mode (`IngestSyscallSensor`) never lights `untrusted_content_present` at all, so `AllLit()` is permanently false there regardless. **The entire soft-`SUSPICIOUS` tier is inert on the sensor-only DaemonSet path** — a second, deeper, catalogued-not-fixed gap (`docs/architecture.md` §13, `TestEngine_IngestSyscallSensor_NeverReachesSuspicious_KnownGap`) found while investigating the first. Three further consequences, all disclosed rather than absorbed quietly: the fix creates **double emission** on the connect-then-write EXFIL path (no session-level dedup exists; `min_verdict` defaults to `SUSPICIOUS` so both records pass through by default — a PagerDuty-specific mitigation shipped, session-scoped `dedup_key` merges an escalating verdict into the same still-open incident instead of opening a second one; the general session+PID dedup design remains a tracked follow-up, not fixed here); it **measurably widened** the operational FP rate (13.3% → 18.8% from the restored connect-only tripwire, then → **21.2% (7/33)** from the PEM-header universal-collision pin the PEM taint fix created — measured, not assumed); and the published rate itself **understates real per-incident alert volume** — a chatty benign session making several different non-allowlisted connects trips the soft tripwire independently on each one (measured: one scenario, 5 connects, 5 evidence records — `fp_corpus.md`'s false-positive table now reports a verdict count per row, not just a tripped/not-tripped flag). Full writeup, including a published correction to this report's own first-draft gap note: [`docs/cve_corpus.md`](cve_corpus.md).

**Done when:** there's a signed release, a documented threat model, and detection/false-positive numbers on a corpus rather than a single demo. — **met** (corpus + threat model + checksummed release artifacts; cut a signed `v*` tag to publish assets via `.github/workflows/release.yml`).

**Watch out:**
- The **false-positive rate** is where the product lives or dies. A tool that kills legitimate processes gets uninstalled on day one. If the FP rate on realistic traffic is bad, that is the single most important finding in the project, and it should reshape the detection logic — not get buried to protect a launch narrative. This is the v0.1 honesty discipline at product scale.
- **It was bad, and the corpus found it — then §1 fixed it.** The any-trip (operational) false-positive rate previously came back at 46.7%, driven by sticky content-blind legs. Relevance-aware blocking, content-binding, and leg decay closed that. The EXFIL-tier (value-overlap proven) false-positive rate remains 0.0%. See [`docs/fp_corpus.md`](fp_corpus.md). **Update:** restoring the connect-only tripwire moved the any-trip rate from 13.3% to 18.8%; the PEM taint fix's header-collision pin moved it to 21.2% (7/33); adding a long-secret chunk TN (`benign_proxy_a_near_chunk_no_exfil`) moved the published rate to **20.6% (7/34)**; vault dummy-everywhere TN (`benign_proxy_a_vault_dummy_everywhere`) moved it to **20.0% (7/35)** — measured, not assumed unchanged. Still soft (`detected_only`, never a hard block/kill), so still not an uninstall-risk regression, but the number is real and published, not rounded away.

**v0.3 exit state:** deploys as a Kubernetes DaemonSet, runs as an operable service with metrics and SIEM integration, and ships signed with a threat model and a published false-positive rate. In-kernel prevention (LSM/KRSI) shipped opt-in as Phase 2 Slice 1 (repeat-connect quarantine). Fail-closed, dual ringbufs, taint bridge, and evidence hash chain shipped under Next build order §4–§6. An adoptable product.

---

## Next build order (post-corpus)

Ship order after the FP corpus. **§1–§11 and §14–§22 are done** except operability leftovers in §5 (CEF, cross-session query) and open Tier 2 items §12–§13. Remaining items must not regress the 0.0% EXFIL-tier false-positive rate or the published engine-overhead class (~0.5 ms / ~0.1 ms).

**Suggested execution:** §12 dark against the corpus, then §13 least-privilege closeout. Protocol dissectors (§21) stay Named until demand; do not queue them as silent backlog.

### 1. Resolve the operational false-positive rate `[x]` — **done**

The corpus finding: sticky, content-blind trifecta legs. Three complementary fixes (shipped together; re-run `make fp-corpus`):

- **Relevance-aware blocking** — decouple the `SUSPICIOUS` tripwire from hard enforcement. In `enforcement: block`, if all legs are lit but `CheckOverlap` / `CheckOverlapPayload` finds no value match, keep verdict `SUSPICIOUS` and emit evidence/alerts, but downgrade action from `prevented` / `contained_by_kill` to `allowed_monitor`. Reserve hard block/kill exclusively for `EXFIL` (0.95).
- **Leg decay (TTL)** — configurable time-to-live and/or N-call decay for `sensitive_source_touched` (and related sticky legs). If a sensitive read is followed by N unrelated tool calls or T minutes with no egress, dim the leg so a poisoned session does not forever treat every external sink as suspicious.
- **Content-binding for legs** — require `untrusted_content_present` to share a byte-level relationship with the `external_sink_invoked` payload before tripping `SUSPICIOUS` (beyond the always-on EXFIL overlap path).

**Done when:** operational any-trip FP rate on the published corpus drops materially (target: well below uninstall-risk), EXFIL-tier detection stays 100% on non-gap malicious, EXFIL-tier FP stays 0.0%, and the seven `ExpectTripByDesign` scenarios are re-pinned honestly.

### 2. Close "will cover" detection gaps `[x]` — **done**

Catalogued in [`architecture.md`](architecture.md) §13 and pinned by `*_KnownGap` / corpus known-gap scenarios:

- **Session-level fragment buffer** — **met**: rolling FIFO (`trifecta.fragment_max_chunks` / `fragment_max_bytes`); reassembly-first taint registration; `malicious_proxy_a_cross_call_split` is detection (not KnownGap).
- **Fat taint-map scaling benches** — **met**: `BenchmarkCheckOverlap_MissPath` at 100/1K/10K; ~100 µs miss-path at 1K ([`performance.md`](performance.md)) — gated simple concat before fragment buffer.
- **eBPF payload capture window** — **met (short-term + §16)**: compiled `PAYLOAD_MAX=1024`; runtime `ebpf.payload_capture_bytes` (default **1024**, clamped `[64,1024]`). Secrets entirely past the window remain a permanent KnownGap. Longer-term: `tcp_sendmsg` / larger compiled max deferred.
- **Widen `extractResultText` beyond `content[].text`** — **met**: bounded string-leaf walk; `malicious_proxy_a_secret_outside_content_text` is detection; benign nested-metadata TN re-pinned (unrelated sink).
- **Bounded recursive / dynamic decoder** — **met**: sink-path base64/hex unwrap up to depth-3 after fast-path miss; `MatchForm` `decoded_*`; benches gate miss-path (~100 µs at 1K) and decode-miss (~0.3 ms); `malicious_proxy_a_depth3_nested` is detection.
- **Intra-server write-shaped tools (optional hardening)** — **met via ROADMAP §14:** opt-in `server_defaults.inherit_sink_suspicion` treats tools on a `sensitive_source` server as sinks unless allowlisted; default off preserves explicit-tag Option C.

Managed-K8s readiness (capabilities DaemonSet + PRIVILEGE checklist + EKS/GKE scripts) — **EKS validated 2026-07-12** (AL2023/containerd: caps load+observe; privileged full EXFIL). GKE still optional/unvalidated.

### 3. Strengthen Variant B — kernel prevention + syscall coverage `[x]` — **done**

- **LSM/KRSI blocking** (Phase 2 Slice 1) `[x]` — **done, opt-in** (`ebpf.lsm_enforce`): LSM BPF hook on `socket_connect` → `-EPERM` before the packet forms, for *repeat* connects after an EXFIL confirmation. Verdict/action for those repeats reads true `prevented`, not `contained_by_kill`. Validated on a throwaway-VM prototype (kernel 6.8). The *first* EXFIL packet remains `contained_by_kill` — see Phase 2 above.
- **`sendmsg` / `writev` probes** `[x]` — **done:** `sys_enter_writev` / `sys_enter_sendmsg` on the critical ring (first iovec; named sendmsg carries dest); correlate unnamed sendmsg like write.
- **IPv6 dest layout** `[x]` — **done:** family + 16-byte addr + port on connect/sendto/named-sendmsg; `AF_INET` / `AF_INET6`.

### 4. Sensor↔proxy taint bridge (K8s) `[x]` — **done**

Sensor-only `openat` + `/proc/<pid>/root` seeding is brittle (misses env, stdin, REST; on EKS capabilities posture the root read is permission-denied). **Shipped:** unprivileged MCP proxy forwards `TaintedValue` (value+variants on the node-local Unix socket; evidence still hash+preview) to the DaemonSet sensor via `taint_bridge` (`internal/bridge`, `Engine.RegisterRemoteTaint`, session `k8s:<podUID>` from `POD_UID`). **SO_PEERCRED:** when enabled, `allowed_uids` and/or `allowed_gids` required; optional `socket_gid` + dir `0750` for non-root dialers. openat `/proc` seed remains as privileged-demo fallback. See [`deploy/k8s/PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md) and [`proxy-taint-bridge-example.yaml`](../deploy/k8s/proxy-taint-bridge-example.yaml).

### 5. Operability & enterprise readiness `[~]` — fail-closed done; CEF / dashboard open

- **Fail-closed mode** `[x]` — **done:** config `fail_closed.enabled` with hysteresis / min-trip / recovery / flap backoff (`internal/failclosed`). Routine or critical ringbuf drop rate, async sink failure, or engine/sensor panic → block monitored egress (sensor: LSM quarantine of **all** watched PIDs/cgroups — named limitation: drop counters are severity-class globals, not per-pod; proxy: deny `tools/call` before EvaluateRequest). Sensor mode requires `ebpf.lsm_enforce`. Validated on throwaway EC2 VM (`TestSensor_FailClosedQuarantineAll`).
- **Ring-buffer event segregation** `[x]` — **done:** routine (`events`/`drop_count`: connect/openat) vs critical (`critical_events`/`critical_drop_count`: write/writev/sendto/sendmsg/lsm_deny); dual drain loops; fail-closed watches both rates; metrics `interlock_ebpf_critical_ringbuf_drops_total`. Residual: critical-ring flood (KnownGap).
- **CEF SIEM export** `[ ]` — extend `internal/siem` beyond OCSF for Splunk/QRadar/ArcSight-class ingest.
- **Cross-session evidence dashboard / query** `[ ]` — beyond the single-record HTML viewer: query by `session_id`, verdict, `pod_name` (SQLite or JSONL index; closes `TestEvidenceStore_CrossSessionQuery_KnownGap`).

### 6. Tamper-evident evidence `[x]` — **done**

- **Hash-chained evidence records** — each `EvidenceRecord` includes `chain_seq` / `prev_hash` / `hash` (hex SHA-256); JSONL and SQLite sinks seal on emit; chain tip survives restart; `cmd/verify-evidence` / `make verify-evidence` detects mid-chain edit/delete. Complements SIEM/webhook off-node durability (threat model T5). No WORM / external signing — full-file forge with node root remains a residual risk.

**Also still open under Phase 4 Trust:** (none for the Trust “done when” gate — threat model + reproducible release path **met**). Remaining enterprise items live under Next build order §5 (CEF, cross-session query). Capability drop post-attach is tracked as §13 (today a residual in [`threat_model.md`](threat_model.md)); bridge peer-auth is SO_PEERCRED allowlists (T2 residual: node root / shared GID / forged `pod_uid`).

### 7. Zero-route network namespace for spawned children (proxy mode) `[x]` — **done**

Highest-value Tier 1 item — prevents Variant B's side-channel by construction when Interlock controls spawning.

- **Shipped:** `sandbox.netns` (default `false`) → `CLONE_NEWNET` in `StartServer` `SysProcAttr` alongside `Setpgid`; Linux-only (`sandbox_linux.go` / reject on `!linux`); SessionManager plumbs `sm.cfg.Sandbox.NetNS`; SIGHUP treats change as non-reloadable.
- Loopback-only namespace; no route to the host NIC; **no DNS resolver** (sensitive STDIO sources don't need it).
- **Architecture / PRIVILEGE:** trust-boundary table in [`architecture.md`](architecture.md) §2 — proxy+netns **prevents** Variant B side-channel; eBPF Variant B remains the **sensor-only** mechanism. [`PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md) documents proxy `CAP_SYS_ADMIN` requirement; DaemonSet does not claim this prevention.
- **Pin:** `TestStartServer_NetNS_ConnectENETUNREACH` (linux; skips without `CAP_SYS_ADMIN`) — child dial to `203.0.113.1:9` exits with unreachable errno.

**Done when:** a benign corpus scenario where a netns'd child `connect()`s to a non-loopback dest gets `ENETUNREACH`, pinned; architecture/trust-boundary and PRIVILEGE docs updated; default remains off. — **met** (integration pin + docs; default off).

### 8. Chunk / substring matching for long secrets `[x]` — **done**

Lowest-risk detection win on the list. Closes the "secret split across TCP segments / exceeds capture window" gap for long secrets (PEM keys, long tokens) when the excerpt still holds ≥N body bytes.

- **Shipped:** `trifecta.chunk_match_bytes` (default 32) + `chunk_match_min_value_len` (default 64); `TaintedValue.Chunks` separate from `CanonicalEncodings` (still 10 forms); PEM/PuTTY armor stripped before chunking; `matchTaintedValue` searches chunks after full-variant miss (`match_form=chunk_N`).
- **Pins:** unit tests for minLen / PEM-header skip / unrelated-32B TN; corpus `malicious_ebpf_b_long_secret_chunk_overlap` + `benign_proxy_a_near_chunk_no_exfil`; CVE `cve_2025_53109_filesystem_escaperoute_pem_ebpf_capture_ceiling_gap` promoted to EXFIL.
- **Still open:** secret entirely past capture window (`malicious_gap_payload_truncated`); egress multi-write reassembly (Tier 3 rejected).

**Done when:** long-secret chunk overlap reaches `EXFIL` on a malicious pin; benign near-chunk TN stays clean; chunk size documented as tunable; EXFIL-tier FP stays 0.0%. — **met**.

### 9. Standard compressors as canonical forms (brotli, zstd, lz4) `[x]` — **done**

Straightforward extension of existing encoding machinery alongside `gzip_base64` at taint registration.

- **Shipped:** `brotli_base64` / `zstd_base64` / `lz4_base64` (compress then std base64) in `CanonicalEncodings`; independent corpus encoders; unit hit pins; `malicious_proxy_a_{brotli,zstd,lz4}_base64` detection; XOR stand-in reclassified as `malicious_gap_custom_cipher` KnownGap.
- **Perf:** miss-path ~121 µs @ 1K and decode-miss ~380 µs stay inside the ~0.5 ms class — forms ship **always-on** (no config gate). Registration ~640 µs/secret (compressor-dominated) published in [`performance.md`](performance.md).
- **Non-claims:** ZIP/xlsx **whole-file** relay met (§18); extracted-cell / sink ZIP/zlib on inspected bytes met (§20); git pack wire outside ToolArgs remains Named/demand-gated (§21). Container/wire ≠ token compressor forms.

**Done when:** compressor scenario is detection (not KnownGap); miss-path / decode-miss benches published in [`performance.md`](performance.md); overhead stays in class or the gate is documented. — **met**.

### 10. Token vaulting — no-detokenization-by-default `[x]` — **done**

Biggest Tier 1 item; done after §9 — it interacts with overlap ordering.

- **Shipped:** opt-in `vault.enabled` (default `false`); on sensitive `IngestResult`, mint `ilk.vault.<16hex>` dummies into a per-session map; proxy rewrites agent-visible frames via `VaultRewriteFrame` before delivery; `vault.authorize` lists sink tools that may receive real secrets.
- **Ordering:** authorized sink → detokenize args → `CheckOverlap` on detokenized → on allow, `ForwardArgs` + `replaceToolCallArguments` before `WriteFrame`; on block, never forward real.
- **Pins:** `benign_proxy_a_vault_dummy_everywhere`, `malicious_proxy_a_vault_authorized_wrong_dest`; engine vault unit tests; SIGHUP reloads vault/trifecta via `Engine.Configure`.
- **Boundary:** authorized-sink path still rehydrates the real secret when the detector allows — vaulting narrows passive memory scrape, does not eliminate authorized-sink exfil.

**Done when:** default path never puts real secrets in agent/child-visible payloads; authorized-sink path detokenizes then overlap-scans in that order; boundary documented; corpus pins cover dummy-everywhere + authorized-sink wrong-dest EXFIL. — **met**.

**Watch out:** vaulting hides the secret from the detector unless ordering is exact — `vault → detokenize-at-authorized-sink → scan detokenized`. Get that wrong and you either miss EXFIL or leak the real value into the wrong place.

### 11. Considered and rejected — write into detection_boundary `[x]` — **done**

Tier 3. Do **not** build. Writing session — high value for security reviewers. Shipped as "considered and rejected" in [`detection_boundary.md`](detection_boundary.md):

- **Sockmap / `sk_skb` inline first-packet prevention** — converts Interlock into an inline kernel data-path proxy; maximal blast-radius inversion; runs the overlap engine synchronously per-SKB, breaking the async-off-ringbuf design and the sub-millisecond performance story. "Fixable" only by becoming a different, riskier product. The first-packet limit is an architectural boundary already pinned — keep it pinned.
- **SOCKS5 egress stream scanning** — inline data-path interception on unstructured TCP (message-boundary problem + TLS MITM), trading structured-payload sub-millisecond performance for the hardest problem in the space, to solve egress scanning already done at the tool-call layer. Netns (§7) severs uncontrolled egress; controlled egress is the JSON-RPC path already inspected.
- **Unbounded egress fragment reassembly (slow-trickle DNS)** — any finite time-window is defeated by going slower than the window. Bounded sliding buffer per dest shipped as §19; slow-trickle past the window remains a NamedGap (`malicious_gap_egress_slow_trickle`). Honest output is a named boundary, not a claim of closure.
- **Blind side-channel / query-pattern EXFIL** — also rejected here and named as §22 (wrong observation model).

**Done when:** rejected items appear under "considered and rejected" in `detection_boundary.md`; slow-trickle remains a named KnownGap. — **met**.

### 12. Shannon entropy detector — monitor-mode research only `[ ]`

Tier 2. Research spike that must run **dark** against the corpus first. Deliverable is a **measurement**, not a shipped alert.

- Implement "sensitive read, then high-entropy blob that fails standard decoding egresses" as a signal.
- **Do not wire it to any alert tier.** Run in monitor mode; record what it would fire on; measure against the full benign corpus.
- Failure mode: entropy describes half of all benign binary traffic (compressed media, encrypted payloads, protobuf, hashes). If it lights up benign scenarios, it never graduates past monitor mode — a fine outcome (learned it's an FP machine before it cost the 0% EXFIL FP).

**Done when:** measurement published in [`fp_corpus.md`](fp_corpus.md). Only if the FP surface is clean does it earn a SUSPICIOUS-tier discussion.

### 13. Capability drop post-attach (least-privilege closeout) `[ ]`

Tier 2. Polish-tier, but the exact reassurance the run-as-root audience (Pallas, security teams) asks for.

- After probes load and attach, drop every capability not needed at runtime; keep `KILL` for containment.
- Determine the true minimum per kernel version — `BPF`/`PERFMON` may need to stay if re-attach on reload; `SYS_ADMIN` may be droppable on newer kernels only.
- Deliverable: a **before/after cap set** in [`PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md), verified. Converts "trust me, minimal privilege" into "here's the audit."

**Done when:** before/after caps documented and verified on at least one supported kernel; residual caps (if any) named with why.

### 14. Inherit sink suspicion on sensitive servers `[x]` — **done**

Tier 1 — cheapest of the remaining closeable gaps. Pure config-discipline hole: an untagged write tool on a `sensitive_source` server (`internal_note` with empty `tool_tags`) bypasses `EvaluateRequest` entirely.

- **Shipped:** opt-in `server_defaults.inherit_sink_suspicion` (default `false`) + `sink_suspicion_allowlist`; `Tagger.IsExternalSink` consults server `provides_tags` even when an empty per-tool override shadows `TagsFor`; restart-required (tagger not SIGHUP-rebuilt).
- **Exemption is singular:** with inherit on, `tool_tags: {internal_note: []}` still inherits. Operators who want a true opt-out must list the tool in `sink_suspicion_allowlist` — that is the only escape hatch (documented in architecture §7 / `interlock.yaml`).
- **Pins:** `malicious_proxy_a_untagged_inherit_sink` (detection); `malicious_gap_untagged_tool_on_sensitive_server` remains KnownGap under default-off Option C; `benign_proxy_a_inherit_allowlisted_note` TN.

**Done when:** inherit-on flips the untagged `internal_note` scenario to EXFIL detection; default-off preserves Option C; allowlisted TN stays clean; EXFIL-tier FP stays 0.0%. — **met**.

### 15. Configurable recursive decode depth `[x]` — **done**

Tier 1. Decoder was hard-coded `maxDecodeDepth=3`; Fetch CVE depth-5 nest needed depth ≥4–5.

- **Shipped:** `trifecta.max_decode_depth` clamp `[3,5]`; live budget via `SetMaxDecodeDepth` / `Engine.Configure`.
- **Default raised 3→5 (FP-driven):** `TestCorpus_DecodeDepthFPCurve` measured EXFIL FP **0.0%** and unchanged any-trip at depths 3/4/5; decode-miss latency flat (~380–390 µs). Latency did not justify keeping 3; FP did not rise, so default is **5**. Fetch five-layer nest promoted to detection (`cve_2025_65513_fetch_ssrf_cloud_metadata_depth5_nest`). Operators may lower to 3/4 to reduce decode aggressiveness.
- **Pins / benches:** `malicious_proxy_a_depth4_nested`; decode-miss curve in [`performance.md`](performance.md).

**Done when:** depth-4/5 nests EXFIL under default; FP curve published and drives the default; EXFIL FP stays 0.0%. — **met**.

### 16. Raise default payload capture window `[x]` — **done**

Tier 2 — improve, do not claim full close. Chunk matching (§8) closed “excerpt holds some body bytes.” Remaining gap: secret entirely past the window (zero bytes captured).

- **Shipped:** runtime default `ebpf.payload_capture_bytes` **512 → 1024** (`PAYLOAD_MAX`); clamp stays `[64,1024]`; BPF `DEFAULT_PAYLOAD_CAP` synced (userspace still sets the map at load).
- **Knob direction:** default now equals the compiled ceiling, so `payload_capture_bytes` only **reduces** capture (ring-buffer pressure). Raising above 1024 requires rebuilding BPF with a higher `PAYLOAD_MAX` (eBPF stack / verifier limits).
- **Permanent KnownGap:** `malicious_gap_payload_truncated` (secret past even 1024). `tcp_sendmsg` / larger compiled max deferred. Saturation already measured at 1024.

**Done when:** default is 1024; docs state improve-not-close and ceiling-only-reduces; past-window KnownGap remains pinned. — **met**.

### 17. Spawn-time / pre-session launch interception `[x]` — **done**

Tier 1 — cheap TCB self-hardening that narrows the largest out-of-scope CVE family without over-claiming scope closure.

- **Shipped:** `servers[].command` resolved and pinned at config load (`ResolvedSpawnCommands`); `StartServer` rejects `..` traversal and executables that do not match the pinned path for that server ID; optional `sandbox.spawn_allowlist` for helpers; pairs with existing `sandbox.netns` (`CLONE_NEWNET`).
- **Honest boundary:** pre-Interlock host config/UI poisoning remains out of scope; [`cve_corpus.md`](cve_corpus.md) out-of-scope spawn family note narrowed accordingly.
- **Pins:** `internal/proxy/spawn_test.go`; existing `TestStartServer_NetNS_ConnectENETUNREACH`.

**Done when:** out-of-scope note narrowed; launch-path tests pin canonicalization + allowlist reject; netns launch still fails non-loopback `connect()`. — **met**.

### 18. Path-driven / read-context taint seeding `[x]` — **done**

Tier 1 — structural detection upgrade: close observation gaps that content-shape regexes cannot ever see (binary containers / non-text secrets).

- **Shipped:** `internal/engine/path_taint.go` — `IsSensitiveResourcePath`, `ExtractPathsFromToolArgs`, `TaintPathDrivenContent`; proxy stash/consume on sensitive-source `EvaluateRequest`→`IngestResult`; sensor `seedSensorSensitiveOpen` + eBPF openat matching extended to extension heuristics.
- **Promotion:** `cve_2026_40576_excel_path_traversal_binary_container_exfil` — **whole-file** container relay (path-driven taint of the opaque `.xlsx` blob + overlap on the same bytes). Extracted-from-container cell exfil closed later by ROADMAP §20 (`malicious_proxy_a_extracted_from_xlsx_container`).
- **FP pin:** `benign_proxy_a_path_driven_xlsx_partial_relay` — whole-blob taint + short public cell relay must not EXFIL.
- **Overlap gates unchanged** — EXFIL still requires sink/payload overlap; EXFIL-tier benign FP stays 0.0%.

**Done when:** binary-container CVE promoted (whole-file shape); docs split content-driven vs path-driven taint; extracted-cell residual named; EXFIL-tier FP 0.0%. — **met**.

### 19. Egress flow reassembly `[x]` — **done**

Tier 1 — EXFIL-tier close of normal-speed DNS tunneling and same-dest chunked-write splitting (ingress fragment-buffer analog on the eBPF egress path).

- **Shipped:** bounded per-(pid, destination) rolling payload buffers (`SessionState.EgressFlows`); on each payload-bearing `write`/`writev`/`sendto`/`sendmsg`/`dns` event, append then `CheckOverlapPayload` on the concatenated window (not a single excerpt). DNS left-most label normalization for query-shaped payloads.
- **Knobs (default on):** `trifecta.egress_reassembly_enabled`, `egress_fragment_max_chunks` (16), `egress_fragment_max_bytes` (4096), `egress_fragment_max_age` (10s), `egress_max_destinations_per_session` (32).
- **Promotion:** `cve_2025_65720_gpt_researcher_dns_fragmented_exfil` → EXFIL.
- **Honest KnownGaps (narrower than “all fragmentation”):** slow-trickle past `egress_fragment_max_age` (`malicious_gap_egress_slow_trickle`); cross-destination split (`malicious_gap_egress_cross_destination_split`). Unbounded trickle / sockmap stream scan remain rejected (§11).
- **Pins:** `internal/engine/egress_reassembly_test.go`; EXFIL-tier benign FP stays 0.0%.

**Done when:** same-dest DNS/write fragments EXFIL under default window; slow-trickle and cross-dest remain NamedGaps; FP unchanged. — **met**.

### 20. Bounded container / archive descent `[x]` — **done**

Tier 1 — close extracted-cell and sink/egress-wrapped secrets inside ZIP/gzip/zlib/tar under hard caps (limits-first).

- **Shipped:** `internal/engine/container.go` — magic sniff + `InspectContainer` under `trifecta.container_*` caps (default on: 10 MiB / depth 2 / 100 parts / 50 ms). Registration-side: `taintFromContainer` runs `ExtractTaintedValues` on interiors only (FP-safe). Overlap-side: after decode miss, inspect JSON leaves / payloads (incl. single-layer base64 unwrap for binary-in-JSON). Abort → no EXFIL; soft `SUSPICIOUS` with reason `container_inspect_limit` when AllLit.
- **Promotions:** `malicious_proxy_a_extracted_from_xlsx_container` (real minimal ZIP, base64-packaged in MCP text); `malicious_proxy_a_sink_zip_contains_secret`; `malicious_ebpf_b_zlib_wrapped_secret` (packfile-adjacent flat zlib — not git pack wire).
- **NamedGaps:** `malicious_gap_container_inspect_bomb` (cap abort); `cve_2025_68143_mcp_git_push_wire_protocol_gap` remains (bytes never in ToolArgs; Named §21 — demand-gated).
- **FP pin:** `benign_proxy_a_path_driven_xlsx_partial_relay` stays EXFIL-clean (real ZIP interiors without secretPatterns).

**Done when:** extracted-xlsx + sink-zip + zlib-egress EXFIL; bomb / git pack remain KnownGaps; EXFIL-tier FP 0.0%. — **met**.

### 21. Protocol-aware egress parsers — Named / demand-gated `[x]` — **done (Named boundary)**

Tier 3 documentation closeout — **no dissector shipped**. The git-packfile gap is "the secret moves inside a structured protocol Interlock doesn't parse." Closing it would mean lightweight egress dissectors (recognize the frame, extract the payload region, then reuse §20's bounded walker + overlap) — git pkt-line / smart HTTP or SSH receive-pack, HTTP body + `Content-Encoding`, SMTP DATA.

- **What it would close:** git push pack wire (`cve_2025_68143_mcp_git_push_wire_protocol_gap`), HTTP-body exfil with content-encoding, structured-protocol exfil generally — family-at-a-time coverage.
- **Why not now:** each protocol is real dissector work; dissectors are a rich vulnerability source (Wireshark's CVE history is mostly dissectors). Adding parsing of untrusted structured input grows the TCB — exactly the surface [`threat_model.md`](threat_model.md) tries to minimize. Worst effort-to-gap ratio on the list.
- **Gate:** build a git (or other) dissector **only** if a deployment shows that MCP family in production; otherwise leave the NamedGap.
- **Non-claim / §20 split:** packfile-**adjacent** flat zlib/gzip/ZIP on bytes that *do* appear in ToolArgs or PayloadExcerpt is already closed (`malicious_ebpf_b_zlib_wrapped_secret`). §21 is framing **outside** those surfaces.
- **Pin:** `cve_2025_68143_mcp_git_push_wire_protocol_gap` remains KnownGap / Missed.

**Done when:** Named boundary documented in ROADMAP + detection_boundary + architecture §13; CVE pin still Missed; no engine code. — **met**.

### 22. Blind side-channel / query-pattern detection — Reject EXFIL `[x]` — **done (rejected)**

Tier 3. **Do not build as EXFIL.** Blind SQL injection is unobservable to byte-overlap because the secret is never transmitted — it is inferred from booleans. The only system that touches it is behavioral pattern detection (bursts of near-identical queries, timing probes, binary-search access patterns) — a different detector (anomaly on request sequences), and an FP minefield (legitimate agents burst similar queries constantly).

- **Structural fact:** proof requires the bytes; blind extraction is defined by the bytes never existing on the wire → EXFIL is unreachable by construction.
- **Corpus SoT:** `cve_2025_66335_doris_blind_sql_injection_exfil_gap` — sharpest structural boundary in the CVE corpus.
- **If ever researched:** SUSPICIOUS-dark measurement only (mirror §12); never wire to EXFIL.
- **Honest product call:** a post-session byte-overlap monitor is the wrong tool; name the boundary and leave it.

**Done when:** rejected for EXFIL in detection_boundary + architecture §13; GapNote sharpened; no detector code. — **met**.

---

## Cross-Cutting Hazards

Four things span both arcs and are the most likely to cause real damage:

- **Concurrency and races** (v0.2 Phase 2, v0.3 Phase 1) — PID reuse, namespace translation, shared-map mutation. `go test -race` is not optional. Demos never surface these; load does.
- **Performance vs detection depth** — every detection feature (taint, payload inspection, per-session tracking) taxes the hot path. Benchmark continuously, not once, or the tool becomes too expensive to run.
- **Scope-infinity** on taint and validation — both are bottomless. Bound them with explicit known-gap tests. Naming what you don't catch is the signature discipline; keep making that move.
- **The blast-radius inversion** (v0.3 Phase 2) — the moment enforcement moves from observing to blocking in-kernel, a bug stops meaning "missed detection" and starts meaning "broke the host."

---

## Backlog (Beyond v0.3)

Pulled forward into **Next build order** above (do not duplicate as "someday"): operational FP remediation; cross-call fragment buffer; `PAYLOAD_MAX` / deeper capture; depth-3 decoder; LSM/KRSI (Slice 1 shipped opt-in); `sendmsg`/`writev`/IPv6 (**met**); proxy↔sensor taint bridge + SO_PEERCRED (**met**); fail-closed (**met**); tamper-evident hash chain (**met**); CEF; cross-session evidence query; zero-route netns (§7); chunk matching (§8); standard compressors (§9); token vaulting (§10); considered-and-rejected boundary writeup (**met**, §11); Shannon entropy monitor spike (§12); capability drop post-attach (§13); inherit sink suspicion (§14); configurable decode depth (§15); raise default payload capture (§16); spawn-time launch interception (**met**, §17); path-driven taint seeding (**met**, §18); egress flow reassembly (**met**, §19); bounded container descent (**met**, §20); protocol-aware egress parsers (**Named / demand-gated**, §21); blind side-channel EXFIL (**rejected**, §22).

Still deferred until demand justifies them: Unix-socket and file-based exfil paths; role-based access and operator audit logs; ARM support and cross-distro/CO-RE portability; a managed cloud offering; third-party security audit and red-team results; comparison benchmarks against static scanners. Protocol dissectors (git pkt-line, HTTP CE, SMTP DATA) stay demand-gated under §21 — not a silent "someday" queue.

**Out of scope (not backlog):** DoH/DoT — mitigate with network-layer DNS controls; see [`architecture.md`](architecture.md) §13. Sockmap / SOCKS5 stream scanning / unbounded slow-trickle reassembly — considered and rejected (§11 → [`detection_boundary.md`](detection_boundary.md)). Blind side-channel / query-pattern EXFIL — rejected (§22). Protocol-aware egress parsers — Named boundary until demand (§21).

Detection gap priorities live in [`architecture.md`](architecture.md) §13; the Next build order is the execution queue.
