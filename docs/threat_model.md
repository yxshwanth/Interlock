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
| **eBPF programs** (`internal/ebpf/bpf/connect.c`) | Kernel TCB: PID/cgroup filter, ring buffer, `drop_count` |
| **Taint bridge socket** (`/var/run/interlock/taint.sock`) | Node-local IPC; carries raw `Value`/`Variants` for overlap matching |
| **Evidence store** (JSONL / SQLite) | Forensic record; not an authenticated ledger |
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
   ([`architecture.md`](architecture.md) §12). `fail_closed: true` is roadmap §5 —
   not shipped.
4. Operators can scrape **metrics** (`interlock_ebpf_ringbuf_drops_total`, evidence /
   event drop counters) and alert on `[SECURITY]` / trip webhooks.

---

## Threat scenarios

Each scenario: **attacker**, **goal**, **mechanism**, **current mitigations**,
**residual risk**, **operator guidance**.

### T1 — Blind the sensor (ring-buffer flood)

| | |
|---|---|
| **Attacker** | Compromised agent / workload on a monitored pod (or any process whose events pass the PID/cgroup filter) |
| **Goal** | Cause `bpf_ringbuf_reserve` failures so egress events are dropped → detection gap without an EXFIL trip |
| **Mechanism** | Flood `connect` / `write` / `sendto` / `openat` faster than userspace drains the 256 KiB ring buffer; kernel increments `drop_count` |
| **Mitigations** | `drop_count` map + `Sensor.DropCount()`; Prometheus `interlock_ebpf_ringbuf_drops_total`; `[SECURITY]` / shutdown stats |
| **Residual risk** | Drops are **observed, not prevented**. Fail-open: traffic continues while events are lost. No automatic fail-closed on rising drop rate. |
| **Guidance** | Alert on non-zero / rising ringbuf drops; investigate noisy pods; treat sustained drops as a security incident, not only capacity |

### T2 — Poison the taint bridge

| | |
|---|---|
| **Attacker** | Any process on the node that can open `/var/run/interlock/taint.sock` (wrong hostPath permissions, compromised peer pod, local root) |
| **Goal** | Inject fake `register_taint` entries → false EXFIL (trust erosion) or drown operators in trips; optionally register secrets the attacker already has to frame another session |
| **Mechanism** | NDJSON `register_taint` with attacker-chosen `pod_uid` / `value` / `variants`; sensor calls `RegisterRemoteTaint` with **no peer authentication** beyond filesystem access |
| **Mitigations** | Socket dir `0700`, socket mode `0660` at create time; size limits (`maxLineBytes` / `maxValueBytes`); empty `pod_uid` rejected; evidence still hash+preview only |
| **Residual risk** | **Accepted:** no SO_PEERCRED / mTLS / token on the bridge. HostPath sharing is the entire auth model. |
| **Guidance** | Restrict which pods mount `/var/run/interlock`; run sensor as dedicated UID; monitor unexpected `remote taint:` logs; do not mount the socket into untrusted namespaces |

### T3 — Crash or DoS the monitor (fail-open window)

| | |
|---|---|
| **Attacker** | Compromised agent or MCP server; resource exhaustion against proxy/sensor |
| **Goal** | Stop evaluation / sensor loop so egress proceeds without Interlock |
| **Mechanism** | Panic in evaluation path; kill proxy/sensor process; fill evidence/event queues under `backpressure: drop` |
| **Mitigations** | Panic paths log `[SECURITY]` and fail-open (proxy); DaemonSet restart via kubelet; drop counters for evidence/events; healthz for sensor |
| **Residual risk** | **Accepted:** fail-open during crash/restart. Planned `fail_closed` (ROADMAP §5) would block monitored egress on ringbuf drop / sink failure / panic — not implemented. |
| **Guidance** | Prefer `backpressure: block` where latency allows; alert on process restarts and drop metrics; pair with network policy so a dead sensor is not silent allow |

### T4 — Manipulate PID / session attribution

| | |
|---|---|
| **Attacker** | Local process racing PID reuse; mis-labeled pods; forged cgroup identity (hard without kernel compromise) |
| **Goal** | Attribute a syscall to the wrong session → miss EXFIL or trip the wrong workload |
| **Mechanism** | PID reuse between unregister and new process; missing `SessionID` on eBPF events |
| **Mitigations** | Proxy: PID registry keyed with **start time** (not PID alone). Sensor: cgroup → container → pod (`k8s:<podUID>`). **Unattributed syscalls are not guessed** — audit event + allow (fail-safe). |
| **Residual risk** | Narrow race windows remain under extreme churn; unattributed path is fail-open by design (no kill without attribution). |
| **Guidance** | Alert on `unattributed_syscall` audit volume; keep label discipline (`interlock.io/monitor`); prefer cgroup filter path over lone BPF PID |

### T5 — Tamper with evidence

| | |
|---|---|
| **Attacker** | Root on node, or process with write access to evidence path / volume |
| **Goal** | Delete or rewrite JSONL/SQLite to cover tracks after a trip |
| **Mechanism** | Truncate/edit `evidence.jsonl`, replace SQLite file, or disable SIEM/webhook delivery |
| **Mitigations** | Evidence is append-oriented; redaction keeps secrets out of files; optional webhook/OCSF fan-out to an external sink; metrics count detections |
| **Residual risk** | **Accepted:** no append-only WORM, signing, or hash-chaining of evidence records. Local FS integrity = host integrity. |
| **Guidance** | Ship SIEM/webhook to an immutable external store; restrict volume mounts; treat local evidence as convenient, not sole source of truth |

### T6 — Bypass via unmonitored channels

| | |
|---|---|
| **Attacker** | Compromised agent that knows Interlock’s probe set |
| **Goal** | Exfiltrate without lighting Variant A/B paths Interlock monitors |
| **Mechanism** | Aggregate of documented gaps: **Unix-domain sockets**, **file-based exfil**, **IPv6**, **`sendmsg`/`writev`**, **DoH/DoT**, **semantic / paraphrased** content without byte overlap, untagged write tools, non-gzip compressors, depth-4+ nests |
| **Mitigations** | Honest known-gap tests + corpus pins; detection_boundary; operators tag every egress tool; network-layer DNS / egress controls for DoH |
| **Residual risk** | Interlock is not a universal DLP. Bypass channels remain until ROADMAP backlog items ship (or complementary controls). |
| **Guidance** | Read [`detection_boundary.md`](detection_boundary.md); combine with CNI egress policy, DNS allowlists, and host file-integrity monitoring |

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

1. Taint bridge auth = filesystem permissions only (T2).
2. Fail-open on panic, restart, and ringbuf/evidence drops (T1, T3); `fail_closed` not shipped.
3. Evidence is not cryptographically integrity-protected (T5).
4. Unmonitored exfil channels remain (T6).
5. `SYS_ADMIN` may still be required depending on kernel (least-privilege residual).

---

## What this model does not cover

- Compromised kernel or malicious cluster admin with full node root (assumed trusted operator).
- Supply-chain compromise of the build pipeline (see [`reproducible_builds.md`](reproducible_builds.md) for verification of released artifacts).
- Social engineering of operators to disable monitoring labels.
