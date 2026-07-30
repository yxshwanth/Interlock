# Threat model — Interlock as TCB

This document describes threats **against Interlock itself**: how a compromised
agent, MCP server, or co-resident process on a monitored node might blind,
poison, crash, or bypass the monitor. It is distinct from
[`detection_boundary.md`](detection_boundary.md), which scopes attack classes
Interlock *detects*.

Audience: security teams evaluating privileged eBPF + an MCP proxy before
deploying it.

Related: [`SECURITY.md`](../SECURITY.md) (reporting),
[`deploy/k8s/PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md) (caps / hostPath),
[`architecture.md`](architecture.md) §12 (fail-open),
[`fp_corpus.md`](fp_corpus.md) (detection / FP rates),
[`reproducible_builds.md`](reproducible_builds.md) (artifact provenance).

---

## Trust boundaries and TCB

| Component | Trust role |
|---|---|
| **MCP proxy** (`--mode=proxy`) | Parses tool traffic; extracts taint; Variant A block; optional bridge client |
| **Sensor DaemonSet** (`--mode=sensor --ebpf`) | Loads probes; correlates egress; Variant B kill; bridge server; evidence |
| **eBPF programs** (`internal/ebpf/bpf/connect.c`) | Kernel TCB: PID/cgroup filter; dual ringbufs (`events` + `critical_events`); `drop_count` / `critical_drop_count`; opt-in `lsm/socket_connect` quarantine (`ebpf.lsm_enforce`) |
| **Taint bridge socket** (`/var/run/interlock/taint.sock`) | Node-local IPC; carries raw `Value`/`Variants` for overlap matching (`register_taint`), and an "untrusted content observed" signal with no raw content (`register_untrusted`) |
| **Evidence store** (JSONL / SQLite) | Forensic record with append-only hash chain (`chain_seq`/`prev_hash`/`hash`); not a WORM / externally signed ledger |
| **Host kernel BTF / maps / tracefs** | Required to load and attach; assumed not attacker-controlled |
| **K8s RBAC + label** | Sensor watches pods with `interlock.io/monitor=true` |

**Out of TCB:** demo MCP servers under `servers/`; integrator-owned agent
runtimes; network DLP / DNS firewalls complementary to Interlock.

---

## Assumptions

1. The **host kernel** is not under attacker control (no malicious rootkit rewriting
   Interlock’s maps or BTF).
2. **Node-local hostPath** directories (`/var/run/interlock`, BTF, bpf, cgroup) are a
   trust boundary: anyone who can write the socket directory can talk to the bridge.
3. Default posture is **fail-open** with loud `[SECURITY]` warnings
   ([`architecture.md`](architecture.md) §12). Opt-in `fail_closed.enabled`
   (with `ebpf.lsm_enforce` in sensor mode) blocks monitored egress on ringbuf
   drop rate / sink failure / panic — see T1/T3.
4. Operators can scrape **metrics** (`interlock_ebpf_ringbuf_drops_total`,
   `interlock_ebpf_critical_ringbuf_drops_total`, `interlock_fail_closed_active`,
   evidence / event drop counters) and alert on `[SECURITY]` / trip webhooks.

---

## Threat scenarios

Each scenario: **attacker**, **goal**, **mechanism**, **current mitigations**,
**residual risk**, **operator guidance**.

### T1 — Blind the sensor (ring-buffer flood)

| | |
|---|---|
| **Attacker** | Compromised agent / workload on a monitored pod (or any process whose events pass the PID/cgroup filter) |
| **Goal** | Cause `bpf_ringbuf_reserve` failures so egress events are dropped → detection gap without an EXFIL trip |
| **Mechanism** | Flood syscalls faster than userspace drains the ring buffers. **Routine** path (`events`, 256 KiB): `connect` / `openat`. **Critical** path (`critical_events`, 256 KiB): `write` / `sendto` / `lsm_deny`. Reserve failures increment `drop_count` or `critical_drop_count` respectively. |
| **Mitigations** | Dual ringbufs so a connect storm cannot starve EXFIL payload carriers or `lsm_deny` evidence. Routine: `drop_count` + `Sensor.DropCount()` + Prometheus `interlock_ebpf_ringbuf_drops_total`. Critical: `critical_drop_count` + `Sensor.CriticalDropCount()` + `interlock_ebpf_critical_ringbuf_drops_total`. `[SECURITY]` / shutdown stats report both. Kernel `-EPERM` on LSM deny is not evidence-dependent (deny still happens if critical reserve fails). **Opt-in `fail_closed.enabled`:** trips on **either** routine or critical drop *rate* (same hysteresis thresholds); sensor mode quarantines **all** currently watched PIDs/cgroups via LSM `socket_connect` (`-EPERM`); proxy denies `tools/call` before `EvaluateRequest`. Counters remain severity-class globals (not per-pod). Flap prevention: hysteresis band, `min_trip_duration`, `recovery_window`, exponential backoff (`internal/failclosed`). |
| **Residual risk** | Default remains fail-open (observe + warn). An attacker who floods **write/sendto** (not connect) can still pressure the critical ring — harder than a connect storm, does not fill the routine counter used as the primary cheap signal, and is accepted (KnownGap discipline) rather than pretended away. `openat` under a connect flood can still drop — acceptable because openat never proves EXFIL. Fail-closed denies **`connect()` only**. Process crash / kubelet restart still leaves a window until probes re-attach. |
| **Guidance** | Enable `fail_closed` + `ebpf.lsm_enforce` on sensor DaemonSets when silent fail-open is unacceptable; alert on `interlock_fail_closed_active` and both ringbuf drop metrics; investigate noisy pods |

### T2 — Poison the taint bridge

| | |
|---|---|
| **Attacker** | Node root; process whose UID/GID is in the bridge allowlist; peer that shares `socket_gid` after compromise |
| **Goal** | Inject fake `register_taint` entries → false EXFIL (trust erosion) or drown operators in trips; optionally register secrets the attacker already has to frame another session. **Since `register_untrusted` shipped (see below), also: flood an arbitrary `pod_uid`'s session with soft `SUSPICIOUS` trips on its ordinary egress, with no knowledge of any real secret required.** |
| **Mechanism** | NDJSON `register_taint` with attacker-chosen `pod_uid` / `value` / `variants`, **or `register_untrusted` with attacker-chosen `pod_uid` / `source`**, after dialing the Unix socket |
| **New surface, `register_untrusted` (this pass):** `Engine.RegisterRemoteUntrusted` lets an allowlisted bridge peer light `untrusted_content_present` for **any** `pod_uid` directly — no secret value, no matching payload, no correlation with real MCP traffic required. This is a different kind of poisoning than `register_taint`'s, not just more of it: a fake `register_taint` only produces a false `EXFIL` if the attacker *also* gets their chosen value to appear in an observed egress payload — a real constraint. `register_untrusted` needs no such match. Combined with the fact that the sensor already seeds `sensitive_source_touched` itself on any sensitive `openat` (routine, legitimate pod activity), one injected `register_untrusted` message plus the pod's ordinary non-allowlisted egress produces soft `SUSPICIOUS` on **every subsequent connect** in that session — an alert-flood primitive requiring no knowledge of any real secret. **Bounded:** it forwards no excerpt text, so it cannot produce a false `EXFIL` or a false content-bound `SUSPICIOUS` on a payload-bearing write — the ceiling is alert volume, not fabricated proof of exfiltration. |
| **Mitigations** | **SO_PEERCRED** on accept: peer UID/GID must match `taint_bridge.allowed_uids` / `allowed_gids` (config requires at least one list when enabled). Optional `socket_gid` + dir `0750` / socket `0660` so non-root proxies can dial without world-writable sockets. Size limits (`maxLineBytes` / `maxValueBytes`, `maxSourceBytes` for `register_untrusted`); empty `pod_uid` rejected; evidence still hash+preview only. Same allowlist gates both message types — there is no separate, tighter policy for `register_untrusted` today. |
| **Residual risk** | Node root can still forge peers; shared-GID compromise lets any process in that group talk; an **allowed** peer can still forge `pod_uid` (no pod-identity binding on the wire) for *either* message type. Not mTLS / SPIFFE. An allowlisted peer that is compromised (not just a stranger who forged credentials) can now cheaply flood alerts fleet-wide via `register_untrusted` without needing to know or guess any tainted value first. |
| **Guidance** | Keep allowlists tight (proxy/sensor UIDs or a dedicated shared GID); set `fsGroup` / `supplementalGroups` only on trusted pods; do not mount the socket into untrusted namespaces; monitor unexpected `remote taint:` / `remote untrusted:` / peercred reject log volume — a spike in `remote untrusted:` with no matching legitimate proxy traffic is the `register_untrusted` flood signature specifically |

### T3 — Crash or DoS the monitor (fail-open window)

| | |
|---|---|
| **Attacker** | Compromised agent or MCP server; resource exhaustion against proxy/sensor |
| **Goal** | Stop evaluation / sensor loop so egress proceeds without Interlock |
| **Mechanism** | Panic in evaluation path; kill proxy/sensor process; fill evidence/event queues under `backpressure: drop` |
| **Mitigations** | Panic paths log `[SECURITY]`; DaemonSet restart via kubelet; drop counters for evidence/events; healthz for sensor. **Opt-in `fail_closed.enabled`:** engine/sensor panic and consecutive evidence sink write failures trip the same breaker as ringbuf drop rate — sensor quarantines all watched PIDs/cgroups (requires `ebpf.lsm_enforce`); proxy denies further `tools/call`. Sensor handler dispatch is `recover()`-wrapped so a panic no longer kills the DaemonSet process (which would reopen a fail-open window until kubelet restarts it). |
| **Residual risk** | Default remains fail-open. The *in-flight* panicked call still fails open once (honest); the breaker stops the next ones. Full process kill (OOM, SIGKILL) still leaves a restart gap — pair with network policy. Sensor-mode fail-closed cannot start without `ebpf.lsm_enforce` (config validation). |
| **Guidance** | Prefer `backpressure: block` where latency allows; enable `fail_closed` in production; alert on process restarts, `interlock_fail_closed_transitions_total`, and drop metrics |

### T4 — Manipulate PID / session attribution

| | |
|---|---|
| **Attacker** | Local process racing PID reuse; mis-labeled pods; forged cgroup identity (hard without kernel compromise) |
| **Goal** | Attribute a syscall to the wrong session → miss EXFIL or trip the wrong workload |
| **Mechanism** | PID reuse between unregister and new process; missing `SessionID` on eBPF events |
| **Mitigations** | Proxy: PID registry keyed with **start time** (not PID alone). Sensor: cgroup → container → pod (`k8s:<podUID>`). **Unattributed syscalls are not guessed** — audit event + allow (fail-safe). With `ebpf.lsm_enforce`, `RemovePID`/`RemoveCgroupID` also clear any matching `lsm_blocklist` entry on process/pod exit, so a recycled PID cannot inherit a stale kernel-level quarantine. |
| **Residual risk** | Narrow race windows remain under extreme churn; unattributed path is fail-open by design (no kill without attribution). The quarantine cleanup above closes the *stale-quarantine* PID-reuse case, but relies on `OnUnwatch`/`OnUnwatchCgroups` actually firing — a sensor crash between kill and cleanup could theoretically leave a quarantine entry orphaned until the PID/cgroup is reused and independently re-registered. |
| **Guidance** | Alert on `unattributed_syscall` audit volume; keep label discipline (`interlock.io/monitor`); prefer cgroup filter path over lone BPF PID |

### T5 — Tamper with evidence

| | |
|---|---|
| **Attacker** | Root on node, or process with write access to evidence path / volume |
| **Goal** | Delete or rewrite JSONL/SQLite to cover tracks after a trip |
| **Mechanism** | Truncate/edit `evidence.jsonl`, replace SQLite file, or disable SIEM/webhook delivery |
| **Mitigations** | Evidence is append-oriented; redaction keeps secrets out of files; optional webhook/OCSF fan-out to an external sink; metrics count detections. **Hash chain:** each `EvidenceRecord` carries `chain_seq` / `prev_hash` / `hash` (hex SHA-256 of the prior record); `make verify-evidence` detects mid-chain edit/delete. Chain tip survives process restart (JSONL tail-scan / SQLite tip query). |
| **Residual risk** | No append-only WORM volume and no external signing/timestamping. Local FS integrity still equals host integrity for *silent* overwrite of the entire file with a freshly forged genesis chain — operators must ship SIEM/webhook off-node for durability. Pre-upgrade SQLite rows are not retroactively chained. |
| **Guidance** | Run `make verify-evidence` in CI/ops; ship SIEM/webhook to an immutable external store; restrict volume mounts; treat local evidence as convenient *and* self-checking, not sole source of truth |

### T6 — Bypass via unmonitored channels

| | |
|---|---|
| **Attacker** | Compromised agent that knows Interlock’s probe set |
| **Goal** | Exfiltrate without lighting Variant A/B paths Interlock monitors |
| **Mechanism** | Aggregate of documented gaps: **Unix-domain sockets**, **file-based exfil**, **DoH/DoT**, **semantic / paraphrased** content without byte overlap, untagged write tools (default Option C; closed under opt-in inherit — ROADMAP §14), custom ciphers, encrypted archives / zip-bombs / depth>2 container nests (ROADMAP §20 NamedGaps), depth-6+ nests beyond clamp `[3,5]` (§15), secrets entirely past `PAYLOAD_MAX` (permanent; default capture raised to 1024 — §16), **git-wire / structured-protocol framing** outside ToolArgs/PayloadExcerpt (Named §21 — demand-gated; not a silent queue), **blind side-channel / boolean inference** (structural reject §22 — bytes never on the wire). **No longer bypass channels — closed:** IPv6 (family+16B addr+port on connect/sendto/named-sendmsg), `sendmsg`/`writev` (probed on the critical ring; unnamed `sendmsg` correlates like `write`), token-shaped brotli/zstd/lz4_base64 (ROADMAP §9), ZIP/xlsx **whole-file** relay (§18) and extracted-cell / flat zlib/ZIP on inspected bytes (§20) — see [`architecture.md`](architecture.md) §5/§7, ROADMAP §3/§9/§18/§20. **Proxy-mode uncontrolled TCP egress:** closed when `sandbox.netns: true` (zero-route `CLONE_NEWNET` at spawn — ROADMAP §7); sensor-only deployments still rely on eBPF. |
| **Mitigations** | Honest known-gap tests + corpus pins; detection_boundary (incl. considered-and-rejected §11/§22); operators tag every egress tool; network-layer DNS / egress controls for DoH; opt-in `sandbox.netns` in proxy mode |
| **Residual risk** | Interlock is not a universal DLP. Named/demand-gated and structural boundaries remain (§21/§22); complementary controls cover the rest. Netns does not apply to sensor-only workloads Interlock did not spawn. |
| **Guidance** | Read [`detection_boundary.md`](detection_boundary.md); combine with CNI egress policy, DNS allowlists, and host file-integrity monitoring; enable `sandbox.netns` when Interlock spawns children and holds `CAP_SYS_ADMIN`; do not expect EXFIL proof for blind side-channels |

---

## Least-privilege audit (documentation)

Capabilities DaemonSet ([`daemonset-capabilities.yaml`](../deploy/k8s/daemonset-capabilities.yaml)):

| Capability | Why held today | Droppable post-load? |
|---|---|---|
| `BPF` | Load/attach BPF programs | Not while probes must stay loaded/reattachable |
| `PERFMON` | Tracepoint / perf-related attach on modern kernels | Required with `BPF` on many distros |
| `SYS_ADMIN` | Historical BPF/cgroup needs on some kernels | **Residual over-privilege** — preferred target to eliminate when kernel/runtime allows; not dropped today |
| `KILL` | Variant B `contained_by_kill` | Required for containment action |

Other surface:

| Setting | Necessity |
|---|---|
| `hostPID: true` | Host PIDs for eBPF + `/proc` attribution |
| hostPath BTF / bpf / tracefs / cgroup | CO-RE load and attach |
| hostPath `/var/run/interlock` | Taint bridge (production EXFIL under caps) |
| `privileged: true` | Demo / openat `/proc/<pid>/root` seed only — prefer caps + bridge |

**Accepted:** Interlock does not yet drop capabilities after attach. Least-privilege
hardening beyond the caps-first manifest remains iterative (see PRIVILEGE.md).

---

## Accepted risks (summary)

1. Taint bridge peers must match SO_PEERCRED allowlists; residual is node root / shared-GID compromise / allowed peer forging `pod_uid`, plus (new) an allowlisted peer cheaply flooding soft `SUSPICIOUS` alerts via `register_untrusted` with no secret knowledge required — bounded to alert volume, not fake `EXFIL` (T2).
2. Default is fail-open; opt-in `fail_closed` blocks all watched egress (scope=all; `connect()`-only via LSM) on **routine or critical** ringbuf drop rate / sink failure / panic — process kill restart gap remains (T1, T3). Connect floods no longer starve critical-path evidence (dual rings); write/sendto flood against the critical ring remains a named residual.
3. Evidence hash-chaining detects mid-chain edit/delete; no WORM / external signing (T5). Full-file forge still possible with node root.
4. Unmonitored exfil channels remain (T6).
5. `SYS_ADMIN` may still be required depending on kernel (least-privilege residual).
6. `ebpf.lsm_enforce` (opt-in, default off) cannot prevent the *first* EXFIL-carrying packet — `connect()` precedes the payload that proves EXFIL, so kernel quarantine only stops *repeat* attempts (T4); attach failure fails soft, matching default fail-open unless `fail_closed` also requires a live LSM attach in sensor mode.
7. **Token vaulting** (`vault.enabled`, opt-in): when a sink appears in `vault.authorize`, Interlock rehydrates the real secret after allow. A false allow still forwards the secret — vaulting closes the default agent/child memory-scrape channel, not the authorized-sink path. Vaulting is proxy-plane only (does not change eBPF/bridge in-memory taint).

---

## What this model does not cover

- Compromised kernel or malicious cluster admin with full node root (assumed trusted operator).
- Supply-chain compromise of the build pipeline (see [`reproducible_builds.md`](reproducible_builds.md) for verification of released artifacts).
- Social engineering of operators to disable monitoring labels.
