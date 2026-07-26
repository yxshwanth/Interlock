# Interlock

[![CI](https://github.com/yxshwanth/Interlock/actions/workflows/ci.yml/badge.svg)](https://github.com/yxshwanth/Interlock/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/yxshwanth/Interlock)](https://github.com/yxshwanth/Interlock/releases)
[![License: MIT](https://img.shields.io/github/license/yxshwanth/Interlock)](LICENSE)
[![Go 1.25+](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![eBPF](https://img.shields.io/badge/eBPF-cilium--ebpf-111111?logo=linux&logoColor=white)](internal/ebpf/bpf/connect.c)
[![MCP](https://img.shields.io/badge/MCP-Streamable%20HTTP-5A67D8)](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports/streamable-http)
[![Platform](https://img.shields.io/badge/platform-Linux%20%2B%20BTF-FCC624?logo=linux&logoColor=black)](#quickstart)

**A runtime firewall that catches AI agents exfiltrating your data — through tool-call chains the proxy sees, and side channels it can't.**

<p align="center">
  <img src="media/ReadmeGif.gif" alt="Firewall off: breach. Firewall on: blocked at the tool call, or detected and contained at the kernel." width="720" />
</p>

<p align="center"><em>Firewall off: breach. Firewall on: blocked at the tool call, or detected and contained at the kernel.</em></p>

---

## The problem

AI agents wired to MCP tools can read private data, ingest attacker-controlled instructions, and reach the outside world — Simon Willison's **lethal trifecta** — while MCP implementations have faced a steady stream of high-severity CVEs through early 2026 ([OX Security](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/), [Cloud Security Alliance research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-by-design-rce-ox-security-20260420-csa/)). Static scanners check what a tool *claims* before approval; they miss the attack that matters in production: a sequence of individually authorized calls that chains into exfiltration. [Threat framing →](docs/project_overview.md) · [Detection boundary →](docs/detection_boundary.md)

---

## What it does

Interlock sits between an agent and its MCP servers on **two observation planes** — with **asymmetric intelligence**:

- **Plane 1 — proxy (Variant A): dataflow-aware prevention.** The proxy inspects tool-call chains, tracks tainted values through common encodings (base64, hex, URL-encoding, reversal), and **refuses to forward** sink calls that carry secrets. Verdict: `EXFIL` at 0.95 when overlap hits. This plane does real analysis.

- **Plane 2 — eBPF (Variant B): connect() tripwire + write/writev/sendto/sendmsg payload proof.** A malicious server subprocess can open its own TCP socket — invisible to JSON-RPC inspection. The kernel probe fires on `connect()` from a monitored PID; if a correlated `write()`/`writev()` or self-contained `sendto()`/`sendmsg()` carries a tainted secret in the captured payload excerpt (default **512** bytes, max 1024), verdict is `EXFIL` at 0.95, and the process is killed immediately — no waiting window. Connect-only (no overlapping write, all three legs otherwise lit) is `SUSPICIOUS` at 0.60 — a soft tripwire (evidence/alert, `detected_only`), never a hard block; this tier requires a proxy-tied session (`IngestSyscall`) — pure sensor-only DaemonSet mode has no untrusted-content leg and can only ever reach `EXFIL`. Opt-in `ebpf.lsm_enforce` denies *further* connects after EXFIL.

| | Variant A (proxy) | Variant B (eBPF) |
|---|---|---|
| Capability | Encoding-aware overlap on sink args | `connect()` + `write()`/`writev()`/`sendto()`/`sendmsg()` payload overlap (default 512 B) |
| Confidence when tripped | 0.95 (`EXFIL`) with overlap | 0.95 (`EXFIL`) with payload overlap; 0.60 (`SUSPICIOUS`) connect-only, proxy-tied sessions only |
| Role | Detector + preventer | Tripwire (soft) and immediate payload-backed containment (+ opt-in LSM quarantine) |

```mermaid
flowchart TB
    Agent[AI Agent]
    Proxy[MCP Proxy]
    Servers["MCP servers<br/>tickets · messenger · exfil"]

    subgraph tcb [Interlock]
        direction TB
        Engine[Correlation Engine]
        Ebpf[eBPF Sensor]
        Sink[Evidence Sink]
    end

    Attacker[Attacker host]

    Agent <-->|JSON-RPC| Proxy
    Proxy <-->|stdio / HTTP| Servers
    Proxy -->|InterceptedEvent| Engine
    Ebpf -->|SyscallEvent| Engine
    Engine -->|Decision| Proxy
    Engine -->|EvidenceRecord| Sink
    Ebpf -.->|PID watch| Proxy
    Ebpf -.->|connect / write| Servers
    Servers -.->|TCP bypasses proxy| Attacker
```

---

## Quickstart

```bash
git clone https://github.com/yxshwanth/Interlock.git
cd Interlock
sudo make demo-quiet-ebpf GO=$(which go)
```

Requires **Go 1.25+** and **Linux with BTF** (`ls /sys/kernel/btf/vmlinux` should succeed; Ubuntu 6.x works). The eBPF path does not build or run on macOS/Windows. The demo runs three passes — monitor (literal secret breach), block (**gzip_base64** prevented), eBPF (**payload EXFIL** contained) — and prints a comparison table at the end.

No root? The proxy-only demo skips Variant B:

```bash
make demo-quiet
```

<p align="center">
  <img src="media/demo-quiet.jpeg" alt="make demo-quiet terminal output — literal breach, gzip_base64 prevented, payload EXFIL contained" width="640" />
</p>

For verbose protocol output instead of curated narrative beats:

```bash
sudo make demo-ebpf GO=$(which go)   # full demo, verbose
make demo                             # proxy-only, verbose
```

---

> **Why `sudo`?** Variant B loads eBPF probes on `connect()`, `write()`, `writev()`, `sendto()`, `sendmsg()`, and `openat()` to watch the monitored process subtree. That requires root (`CAP_BPF`). The demo money-shot uses local dial + `write()` payload overlap (`INTERLOCK_EXFIL_MODE=local`). Here's precisely what it does: traces those syscalls from PIDs in a filter map, reads destination (IPv4/IPv6) and payload excerpts (default 512 bytes, max 1024), and pushes events to **dual** ring buffers — routine (connect/openat) and critical (write/writev/sendto/sendmsg/`lsm_deny`). Nothing else — no network traffic sent, no files modified, no data leaves the box. The probe source is in [`internal/ebpf/bpf/connect.c`](internal/ebpf/bpf/connect.c). Read the thing you're being asked to trust.
>
> **Why `GO=$(which go)`?** `sudo` resets `PATH`, so the Makefile can't find your Go binary unless you pass it explicitly.

---

## Honest limitations

These are design boundaries, not bugs. Naming them first is the point. Full detection-scope write-up: [`docs/detection_boundary.md`](docs/detection_boundary.md).

1. **Value-overlap covers a closed transform set, not full dataflow analysis.** At taint registration: literal, base64, hex, URL-encoding, reversal, depth-2 nests (`base64_hex`, etc.), and `gzip_base64`. Same-call JSON string reassembly and a session-level fragment buffer catch secrets split across fields in one `tools/call` or across separate calls; a bounded recursive decoder catches depth-3 nests on the sink path (`malicious_proxy_a_cross_call_split`, `malicious_proxy_a_depth3_nested` — both detection, not known-gap; see ROADMAP §2). Still misses **other compressors** (only `gzip_base64` is a precomputed canonical form) and secrets that travel over a protocol other than the tool call's own JSON — e.g. as git objects inside a `git push`'s wire protocol, never inline in the args ([`docs/cve_corpus.md`](docs/cve_corpus.md)). Can false-positive on legitimate echoes of encoded forms.

2. **Semantic / paraphrased exfil is out of scope for EXFIL.** If the agent describes or rewrites a secret in natural language without any registered byte/encoding form, Interlock will not prove EXFIL (`malicious_gap_semantic_paraphrase_exfil`). Soft SUSPICIOUS may still fire on long *literal* shared substrings with untrusted content — that is byte-bind, not understanding. Pair with outbound DLP / human review for meaning-level leaks.

3. **Variant B is connect/sendto/sendmsg/write/writev/openat/DNS, not full stream inspection.** Connect-only or DNS without overlap → soft `SUSPICIOUS` on a proxy-tied session (no hard kill, ever — that's ROADMAP §1's doctrine, not a tier that degrades over time). Pure sensor-only DaemonSet mode never lights `untrusted_content_present`, so it can only ever reach `EXFIL`, not `SUSPICIOUS`. Correlated `write()`/`writev()` or self-contained `sendto`/`sendmsg` whose excerpt overlaps taint → `EXFIL` at 0.95. Secrets past the capture window (`ebpf.payload_capture_bytes`, default 512 / max 1024) and writes before a suspicious connect are known gaps. **DoH/DoT is out of scope** — mitigate with network-layer DNS controls. Prioritized gap list: [`docs/architecture.md`](docs/architecture.md) §13.

4. **eBPF containment is kill-on-connect, not first-packet prevention — but it is immediate, not deferred.** Variant A truly prevents on EXFIL. Variant B kills the instant a payload-carrying `write()`/`sendto()`/`sendmsg()`/`writev()` proves overlap — there is no waiting window; a bare `SUSPICIOUS` connect never escalates to a kill on its own, by design (hard containment is reserved for `EXFIL`, per ROADMAP §1). Opt-in `ebpf.lsm_enforce` upgrades *repeat* `connect()` attempts after EXFIL to in-kernel `prevented`; the first EXFIL-carrying packet remains `contained_by_kill` by construction.

5. **Redaction is pattern-matched, not total.** Event logs scrub known secret patterns (API keys, bearer tokens) and encoded taint variants; HTTP `Authorization` / `Cookie` headers are redacted in request metadata. JWTs, private URLs with embedded tokens, and customer PII in tool bodies still pass through. Treat `events.jsonl` as a sensitive artifact — never commit runtime evidence files.

6. **HTTP multi-session spawns a full backend pool per `initialize`.** Each new MCP session starts dedicated tickets/messenger/exfil child processes until idle expiry (`sessions.idle_timeout`, default 30m) or `max_concurrent` (default 32) is hit. An adversary who can open HTTP sessions can exhaust host process table slots — bounded, but real. Mitigate with network ACLs in front of Interlock, lower `max_concurrent`, and shorter idle timeouts. Not a substitute for authenticating who may open sessions.

7. **Performance numbers include HTTP overhead (v0.2.1+).** [`docs/performance.md`](docs/performance.md) publishes engine-on vs passthrough delta: **~0.5 ms on sensitive reads (typical)** and **~0.1 ms on sink checks** — sub-millisecond. Read-path cost scales with secrets-per-result (snapshot uses a 2-secret fixture). Absolute end-to-end p99 is backend-dominated — do not quote ~12 ms `read_ticket` as Interlock's cost. Concurrent multi-session absolute latency is published via `TestHTTP_ConcurrentLoad_ReadTicket`.

8. **Tool shadowing is checked at registration time only.** Cross-server duplicate tool names use first-owner-wins: the first server keeps the route, the duplicate is omitted from aggregated `tools/list`, and a `tool_shadowing` security audit is emitted. A server that dynamically adds tools mid-session is not re-checked — see `TestToolShadowing_RuntimeReregistration_KnownGap`.

---

## How it works

### The trifecta state machine

One state machine per session tracks three legs:

| Leg | Lights when |
|---|---|
| `sensitive_source_touched` | A tool tagged *sensitive* returns data |
| `untrusted_content_present` | Content enters from an attacker-controllable origin (v0.1: all tool results). **Never lights in pure sensor-only DaemonSet mode** (`IngestSyscallSensor`) — no MCP proxy in that mode means no untrusted-content plane to observe. |
| `external_sink_invoked` | A tool tagged *external sink* is called, or eBPF sees a non-allowlisted `connect()` |

Because `untrusted_content_present` can never light in sensor-only mode, **`SUSPICIOUS` is entirely unreachable there** — only a proxy-tied session (`IngestSyscall`) can produce it. See [`docs/architecture.md`](docs/architecture.md) §13 and [`docs/cve_corpus.md`](docs/cve_corpus.md).

When all three are lit at sink time, the engine trips. **Verdict** (what was concluded) and **action** (what was done) are separate:

| Condition at sink time | Verdict | Confidence |
|---|---|---|
| All three legs + tainted value in sink args | `EXFIL` | 0.95 |
| All three legs; sink event carries a payload/args channel and it byte-shares content with untrusted input | `SUSPICIOUS` | 0.60 |
| All three legs; sink event has **no** payload channel at all (a bare `connect()`) | `SUSPICIOUS` | 0.60 |

Hard containment (`prevented` / `contained_by_kill`) is reserved for `EXFIL` only — a bare `SUSPICIOUS` trip never blocks or kills, on either plane:

| Action | When | Effect |
|---|---|---|
| `prevented` | Variant A, `EXFIL`, block mode | Call never forwarded |
| `contained_by_kill` | Variant B, `EXFIL` | Offending child killed immediately (no delay) |
| `allowed_monitor` | Variant A, `SUSPICIOUS`, or monitor mode | Logged, evidence emitted, call forwarded |
| `detected_only` | Variant B, `SUSPICIOUS` | Logged, evidence emitted, nothing killed |

### Fused timeline

Events from the proxy (userspace) and eBPF (kernel) use different clocks — Go's `CLOCK_MONOTONIC` vs `bpf_ktime_get_ns()`. The evidence receipt orders events by engine-assigned `timeline_seq`, not raw nanosecond timestamps, so the causal story is correct across planes.

Each trip emits an `EvidenceRecord` — session ID, verdict, action, variant, the three legs with trigger details, the sink call (tool name or syscall), optional value-overlap hit, and the full ordered timeline. The local HTML viewer at [`web/viewer.html`](web/viewer.html) renders it: verdict badge, trifecta legs, and the fused timeline.

| Variant A — `EXFIL` prevented (proxy) | Variant B — side channel contained (eBPF) |
|:---:|:---:|
| <img src="media/VariantA.jpeg" alt="Variant A evidence receipt — EXFIL prevented at send_message" width="420" /> | <img src="media/VariantB.jpeg" alt="Variant B evidence receipt — connect syscall fused with sensitive read" width="420" /> |

Full architecture spec: [`docs/architecture.md`](docs/architecture.md)

---

## Project status — v0.3 + robustness (this tree)

**Latest tagged release:** [`v0.3.0`](https://github.com/yxshwanth/Interlock/releases/tag/v0.3.0) (DaemonSet, operability, Trust). **This tree** additionally ships LSM Slice 1, taint bridge, fail-closed, dual ringbufs, and evidence hash chain — see [`CHANGELOG.md`](CHANGELOG.md#unreleased). Versioning follows SemVer under `0.x` — the API is unstable and minor bumps may break things until v1.0.

**Shipped (highlights):**

- Streamable HTTP MCP transport (STDIO still default); multi-session concurrency with PID→session attribution
- Encoding-aware value overlap (depth-3 recursive decoder, fragment buffer, `gzip_base64`, same-call JSON reassembly)
- Engine microbenchmarks + end-to-end HTTP overhead ([`docs/performance.md`](docs/performance.md))
- JSONL evidence by default (intentional); opt-in SQLite; async emit; **hash-chained** records (`make verify-evidence`)
- eBPF `write()`/`writev()`/`sendto()`/`sendmsg()` payload capture (default 512 B; IPv4/IPv6 dest); Variant B `EXFIL` on overlap kills immediately, no waiting window
- Dual ringbufs (routine connect/openat + critical write/writev/sendto/sendmsg/`lsm_deny`); fail-closed watches both drop rates
- Opt-in `ebpf.lsm_enforce` (repeat-connect kernel quarantine) + opt-in `fail_closed.enabled`
- Sensor↔proxy `taint_bridge` with SO_PEERCRED allowlists for managed-cluster EXFIL without privileged `/proc` seed
- **v0.3 Phase 1:** sensor-only Kubernetes DaemonSet; **EKS validated** — [`deploy/k8s/PRIVILEGE.md`](deploy/k8s/PRIVILEGE.md)
- **v0.3 Phase 3–4:** Prometheus metrics/health; webhooks; OCSF SIEM; SIGHUP reload; systemd; FP corpus; threat model; reproducible releases

**Roadmap** ([`docs/ROADMAP.md`](docs/ROADMAP.md)):

- **Known gaps:** [`docs/architecture.md`](docs/architecture.md) §13
- **Next:** CEF SIEM, cross-session evidence query

### Kubernetes (sensor DaemonSet)

Label agent/tool-server pods with `interlock.io/monitor: "true"`. Deploy the sensor (no proxy in the DaemonSet):

```bash
make image
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/daemonset.yaml          # privileged — kind / full EXFIL
# or: deploy/k8s/daemonset-capabilities.yaml        # managed try-first + taint_bridge
# or: make demo-k8s
# EKS: deploy/k8s/eks/push-image.sh → apply /tmp/interlock-daemonset*.yaml
```

Integrators keep their own MCP proxy/sidecar. The DaemonSet loads eBPF, attributes host PIDs to pods, and contains non-allowlisted egress. On EKS, capabilities posture observes `connect`/`write`; production **EXFIL** under capabilities uses the **taint bridge** (proxy → `/var/run/interlock/taint.sock`); privileged DaemonSet remains for openat-seed demos. **The taint bridge is a prerequisite for soft `SUSPICIOUS` detection, not an enhancement:** without an unprivileged proxy sidecar forwarding both taint *and* untrusted-content signals over it, a proxy-less sensor-only DaemonSet can only ever reach `EXFIL` — there is no MCP untrusted-content plane inside the privileged pod for `SUSPICIOUS` to light from, by construction (see [`docs/architecture.md`](docs/architecture.md) §13's "Sensor-only DaemonSet" section). Metrics, webhooks, OCSF SIEM, and SIGHUP reload are available. Details: [`deploy/k8s/README.md`](deploy/k8s/README.md), [`deploy/k8s/PRIVILEGE.md`](deploy/k8s/PRIVILEGE.md), [`deploy/systemd/README.md`](deploy/systemd/README.md).

Every detection feature ships with explicit known-gap tests naming what it does *not* catch. That discipline carries forward.

---

## Tests

**CI + unit tests** cover engine, proxy, config, k8s attribution, observability, alerting, SIEM, hot-reload, fail-closed breaker, evidence hash chain, HTTP integration, overhead benchmarks, async sink, backpressure, concurrent load. CI runs `test` + `race` jobs on every push to `main`; concurrent-load smoke uses `CONCURRENT_SESSIONS=2 OVERHEAD_SAMPLES=100`. eBPF probe load requires root and a BTF-enabled kernel — DropCount/CriticalDropCount APIs are CI-tested; live saturation and LSM tests are root/BPF-LSM-gated (`sudo` or `deploy/ec2/`). Kind DaemonSet demo (`make demo-k8s`) is manual (needs docker/kind/BTF).

```bash
make test
go test -race ./...
```

---

## License

MIT — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pick up work from [`docs/ROADMAP.md`](docs/ROADMAP.md) or open an issue first. New detection features should ship with known-gap tests that name what they do *not* catch — that's the project's signature standard.

## Security

Interlock runs privileged and loads kernel probes. Do not report vulnerabilities in public issues — see [SECURITY.md](SECURITY.md).

## Documentation

- [Project overview & threat framing](docs/project_overview.md)
- [Detection boundary — what we catch / do not](docs/detection_boundary.md)
- [FP corpus report](docs/fp_corpus.md) (self-authored scenarios) · [CVE corpus report](docs/cve_corpus.md) (reconstructed from published, third-party-disclosed MCP CVEs — 7 CVE families, 7/7 caught in their exfil-shaped variant, two live detection bugs found and fixed along the way)
- [Architecture spec](docs/architecture.md) (known gaps §13)
- [Roadmap](docs/ROADMAP.md)
- [Performance](docs/performance.md)
- [Changelog](CHANGELOG.md)

## Credits

- **Threat framing:** Simon Willison's ["lethal trifecta"](https://simonwillison.net/) — the three-capability model for agent danger.
- **Prior art:** [AgentSight](https://arxiv.org/abs/2508.02736) (arXiv 2508.02736) — names the same semantic gap (intent vs. action) and uses eBPF; Interlock is the enforcement-capable product take.
- **Threat data:** [OX Security MCP disclosure](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/), [Cloud Security Alliance research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-by-design-rce-ox-security-20260420-csa/), [Endor Labs MCP AppSec research](https://www.endorlabs.com/learn/classic-vulnerabilities-meet-ai-infrastructure-why-mcp-needs-appsec).
