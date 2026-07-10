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

AI agents wired to MCP tools can read private data, ingest attacker-controlled instructions, and reach the outside world — Simon Willison's **lethal trifecta** — while MCP implementations have faced a steady stream of high-severity CVEs through early 2026 ([OX Security](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/), [Cloud Security Alliance research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-by-design-rce-ox-security-20260420-csa/)). Static scanners check what a tool *claims* before approval; they miss the attack that matters in production: a sequence of individually authorized calls that chains into exfiltration. [Read the full threat model →](docs/project_overview.md)

---

## What it does

Interlock sits between an agent and its MCP servers on **two observation planes** — with **asymmetric intelligence**:

- **Plane 1 — proxy (Variant A): dataflow-aware prevention.** The proxy inspects tool-call chains, tracks tainted values through common encodings (base64, hex, URL-encoding, reversal), and **refuses to forward** sink calls that carry secrets. Verdict: `EXFIL` at 0.95 when overlap hits. This plane does real analysis.

- **Plane 2 — eBPF (Variant B): connect() tripwire + write() payload proof.** A malicious server subprocess can open its own TCP socket — invisible to JSON-RPC inspection. The kernel probe fires on `connect()` from a monitored PID; if a correlated `write()` carries a tainted secret in the first 256 bytes, verdict is `EXFIL` at 0.95. Connect-only (no overlapping write) remains `SUSPICIOUS` at 0.60 — tripwire, not proven exfil. Containment is **deferred ~100 ms** after connect so a write can land, then `SIGKILL`.

| | Variant A (proxy) | Variant B (eBPF) |
|---|---|---|
| Capability | Encoding-aware overlap on sink args | `connect()` + optional `write()` first-256-byte overlap |
| Confidence when tripped | 0.95 (`EXFIL`) with overlap | 0.95 (`EXFIL`) with payload overlap; 0.60 (`SUSPICIOUS`) connect-only |
| Role | Detector + preventer | Tripwire and/or payload-backed containment |

```mermaid
flowchart TB
    Agent["AI Agent"]

    subgraph TCB["Interlock"]
      direction TB
      Proxy["MCP Proxy — intercept + enforce"]
      Engine["Correlation Engine — trifecta state machine"]
      eBPF["eBPF Sensor — connect + write probes"]
      Sink["Evidence Sink — JSONL default, SQLite opt-in"]
    end

    subgraph Untrusted["Untrusted zone"]
      T["tickets server — sensitive source"]
      M["messenger server — external sink"]
      E["exfil server — malicious side channel"]
    end

    Attacker["Attacker host"]

    Agent <-->|"MCP JSON-RPC"| Proxy
    Proxy <-->|"spawns + pipes"| T
    Proxy <-->|"spawns + pipes"| M
    Proxy <-->|"spawns + pipes"| E
    Proxy -->|"InterceptedEvent"| Engine
    eBPF -->|"SyscallEvent"| Engine
    eBPF -.->|"watches PID subtree"| Proxy
    eBPF -.->|"connect syscall"| E
    E -.->|"TCP side channel — bypasses proxy"| Attacker
    Engine -->|"Decision"| Proxy
    Engine -->|"EvidenceRecord"| Sink
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

> **Why `sudo`?** Variant B loads eBPF probes on `connect()`, `write()`, and `sendto()` to watch the monitored process subtree. That requires root (`CAP_BPF`). The demo money-shot uses local dial + `write()` payload overlap (`INTERLOCK_EXFIL_MODE=local`). Here's precisely what it does: traces those syscalls from PIDs in a filter map, reads destination IP/port and first-256-byte write excerpts, and pushes events to a ring buffer. Nothing else — no network traffic sent, no files modified, no data leaves the box. The probe source is in [`internal/ebpf/bpf/connect.c`](internal/ebpf/bpf/connect.c). Read the thing you're being asked to trust.
>
> **Why `GO=$(which go)`?** `sudo` resets `PATH`, so the Makefile can't find your Go binary unless you pass it explicitly.

---

## Honest limitations

These are design boundaries, not bugs. Naming them first is the point.

1. **Value-overlap covers a closed transform set, not full dataflow analysis.** At taint registration: literal, base64, hex, URL-encoding, reversal, depth-2 nests (`base64_hex`, etc.), and `gzip_base64`. Same-call JSON string reassembly catches secrets split across fields in one `tools/call`. Still misses **cross-call** splits, depth-3+ nests, and other compressors — see known-gap skips in [`overlap_test.go`](internal/engine/overlap_test.go). Can false-positive on legitimate echoes of encoded forms.

2. **Variant B is connect/sendto/write/openat/DNS, not full stream inspection.** Connect-only or DNS without overlap → `SUSPICIOUS` at 0.60. Correlated `write()` or self-contained `sendto` whose excerpt overlaps taint → `EXFIL` at 0.95. Openat of `sensitive_paths` → `SUSPICIOUS` only. Secrets past byte 256, IPv6, `sendmsg`, DoH/DoT, and writes before a suspicious connect are known gaps. Kill is deferred ~100 ms after connect/`sendto` SUSPICIOUS so a write can land.

3. **eBPF containment is kill-after-connect (with deferred window), not first-packet prevention.** Variant A truly prevents; Variant B severs the channel after a short wait for payload proof. *v0.3: LSM/KRSI for in-kernel blocking before the packet leaves.*

4. **Redaction is pattern-matched, not total.** Event logs scrub known secret patterns (API keys, bearer tokens) and encoded taint variants; HTTP `Authorization` / `Cookie` headers are redacted in request metadata. JWTs, private URLs with embedded tokens, and customer PII in tool bodies still pass through. Treat `events.jsonl` as a sensitive artifact — never commit runtime evidence files.

5. **HTTP multi-session spawns a full backend pool per `initialize`.** Each new MCP session starts dedicated tickets/messenger/exfil child processes until idle expiry (`sessions.idle_timeout`, default 30m) or `max_concurrent` (default 32) is hit. An adversary who can open HTTP sessions can exhaust host process table slots — bounded, but real. Mitigate with network ACLs in front of Interlock, lower `max_concurrent`, and shorter idle timeouts. Not a substitute for authenticating who may open sessions.

6. **Performance numbers include HTTP overhead (v0.2.1+).** [`docs/performance.md`](docs/performance.md) publishes engine-on vs passthrough delta: **~0.5 ms on sensitive reads (typical)** and **~0.1 ms on sink checks** — sub-millisecond. Read-path cost scales with secrets-per-result (snapshot uses a 2-secret fixture). Absolute end-to-end p99 is backend-dominated — do not quote ~12 ms `read_ticket` as Interlock's cost. Concurrent multi-session absolute latency is published via `TestHTTP_ConcurrentLoad_ReadTicket`.

7. **Tool shadowing is checked at registration time only.** Cross-server duplicate tool names use first-owner-wins: the first server keeps the route, the duplicate is omitted from aggregated `tools/list`, and a `tool_shadowing` security audit is emitted. A server that dynamically adds tools mid-session is not re-checked — see `TestToolShadowing_RuntimeReregistration_KnownGap`.

---

## How it works

### The trifecta state machine

One state machine per session tracks three legs:

| Leg | Lights when |
|---|---|
| `sensitive_source_touched` | A tool tagged *sensitive* returns data |
| `untrusted_content_present` | Content enters from an attacker-controllable origin (v0.1: all tool results) |
| `external_sink_invoked` | A tool tagged *external sink* is called, or eBPF sees a non-allowlisted `connect()` |

When all three are lit at sink time, the engine trips. **Verdict** (what was concluded) and **action** (what was done) are separate:

| Condition at sink time | Verdict | Confidence |
|---|---|---|
| All three legs + tainted value in sink args | `EXFIL` | 0.95 |
| All three legs, no value overlap | `SUSPICIOUS` | 0.60 |

| Action | When | Effect |
|---|---|---|
| `prevented` | Variant A, block mode | Call never forwarded |
| `contained_by_kill` | Variant B, eBPF | Offending child killed |
| `allowed_monitor` | Monitor mode | Logged, not blocked |

### Fused timeline

Events from the proxy (userspace) and eBPF (kernel) use different clocks — Go's `CLOCK_MONOTONIC` vs `bpf_ktime_get_ns()`. The evidence receipt orders events by engine-assigned `timeline_seq`, not raw nanosecond timestamps, so the causal story is correct across planes.

Each trip emits an `EvidenceRecord` — session ID, verdict, action, variant, the three legs with trigger details, the sink call (tool name or syscall), optional value-overlap hit, and the full ordered timeline. The local HTML viewer at [`web/viewer.html`](web/viewer.html) renders it: verdict badge, trifecta legs, and the fused timeline.

| Variant A — `EXFIL` prevented (proxy) | Variant B — side channel contained (eBPF) |
|:---:|:---:|
| <img src="media/VariantA.jpeg" alt="Variant A evidence receipt — EXFIL prevented at send_message" width="420" /> | <img src="media/VariantB.jpeg" alt="Variant B evidence receipt — connect syscall fused with sensitive read" width="420" /> |

Full architecture spec: [`docs/architecture.md`](docs/architecture.md)

---

## Project status — v0.2

**Latest release:** [`v0.2.2`](https://github.com/yxshwanth/Interlock/releases/tag/v0.2.2) — usable-tool milestone plus post-v0.2 detection/operability. Versioning follows SemVer under `0.x` — the API is unstable and minor bumps may break things until v1.0.

v0.2 extends the v0.1 proof with real MCP transport, concurrency, and operability. `v0.2.2` adds async evidence emit, Variant B payload-backed `EXFIL` (connect-only remains `SUSPICIOUS`), bounded overlap expansion, tool-shadowing, and the performance/operability backlog (concurrent HTTP p99, ringbuf DropCount tests, taint-registration opts). Evidence default is **JSONL by intention**; SQLite is opt-in for retention.

**Shipped in v0.2 / v0.2.2:**

- Streamable HTTP MCP transport (STDIO still default); multi-session concurrency with PID→session attribution
- Encoding-aware value overlap on Variant A (base64, hex, URL-encoding, reversal; depth-2 nests, `gzip_base64`, same-call JSON reassembly)
- Engine microbenchmarks + end-to-end HTTP overhead ([`docs/performance.md`](docs/performance.md), `make bench`, `make bench-http`)
- JSONL evidence by default (intentional); opt-in SQLite for retention; async evidence emit; event log backpressure; eBPF ring-buffer drop counter
- Trifecta state machine, proxy blocking, eBPF containment; both demo variants; HTML evidence viewer
- eBPF `write()`/`sendto()` first-256-byte capture + ~100 ms deferred kill; Variant B `EXFIL` on payload overlap, `SUSPICIOUS` on connect-only / DNS / `openat`
- Local exfil fixture (`INTERLOCK_EXFIL_MODE=local`, `interlock-ebpf-local.yaml`)
- Concurrent multi-session absolute latency (`TestHTTP_ConcurrentLoad_ReadTicket`); eBPF DropCount CI + root-gated ringbuf saturation
- Startup tool-shadowing detection (first-owner-wins); mid-session re-registration remains a known gap

**Roadmap** ([`docs/ROADMAP.md`](docs/ROADMAP.md)):

- **Current state:** [`docs/SUMMARY.md`](docs/SUMMARY.md)
- **v0.3 — Adoptable product:** Kubernetes DaemonSet deployment, LSM/KRSI kernel blocking, daemon/metrics/SIEM integration, signed releases and published false-positive rates

Every detection feature ships with explicit known-gap tests naming what it does *not* catch. That discipline carries forward.

---

## Tests

**117 tests passing**, 10 known-gap skips — engine, proxy, config, HTTP integration, overhead benchmarks, evidence, async sink, backpressure, concurrent load. CI runs `test` + `race` jobs on every push to `main`; concurrent-load smoke uses `CONCURRENT_SESSIONS=2 OVERHEAD_SAMPLES=100`. eBPF probe load requires root and a BTF-enabled kernel — DropCount API is CI-tested; live saturation is root-gated locally.

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

- [Current summary](docs/SUMMARY.md)
- [Project overview & threat model](docs/project_overview.md)
- [Architecture spec](docs/architecture.md)
- [Roadmap](docs/ROADMAP.md)
- [Task list](docs/task_list.md)
- [Performance](docs/performance.md)
- [Changelog](CHANGELOG.md)

## Credits

- **Threat framing:** Simon Willison's ["lethal trifecta"](https://simonwillison.net/) — the three-capability model for agent danger.
- **Prior art:** [AgentSight](https://arxiv.org/abs/2508.02736) (arXiv 2508.02736) — names the same semantic gap (intent vs. action) and uses eBPF; Interlock is the enforcement-capable product take.
- **Threat data:** [OX Security MCP disclosure](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/), [Cloud Security Alliance research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-by-design-rce-ox-security-20260420-csa/), [Endor Labs MCP AppSec research](https://www.endorlabs.com/learn/classic-vulnerabilities-meet-ai-infrastructure-why-mcp-needs-appsec).
