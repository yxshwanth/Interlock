# Interlock — Project Overview

## One line

Interlock is a **runtime behavioral firewall for AI agents**. It watches what an agent *does* across its tool calls and severs the connection the instant a benign-looking sequence turns into a data exfiltration.

---

## The problem

MCP became the default way agents talk to tools in under 18 months, and security did not keep up. MCP implementations have faced a steady stream of high-severity CVEs through early 2026 — [OX Security's April 2026 disclosure](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/) alone produced 10+ Critical/High CVEs from one architectural flaw in the STDIO transport; [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-by-design-rce-ox-security-20260420-csa/) and [Endor Labs](https://www.endorlabs.com/learn/classic-vulnerabilities-meet-ai-infrastructure-why-mcp-needs-appsec) catalogued the broader pattern across thousands of implementations.

The entire defensive market is aimed at the wrong moment. **Static scanners check tool *definitions* before an agent is allowed to use them.** They cannot see the attack that matters most in production: a **sequence** of individually-authorized tool calls that chains into an exfiltration pipeline. The defenders themselves named this as the open gap — behavioral monitoring of what an agent does *after* approval.

Interlock lives in that gap.

### Threat model — the lethal trifecta

The framing is Simon Willison's **"lethal trifecta."** An agent is dangerous when three things are true at once:

1. **Access to private data**
2. **Exposure to untrusted content**
3. **The ability to communicate externally**

Any one leg is safe. All three, live in one session, is how data walks out — usually via **tool poisoning**: an attacker hides instructions inside a tool's *result*, which the agent reads as trusted context. The mid-2025 Supabase/Cursor breach was exactly this shape: privileged data access + attacker-supplied input + an external channel.

Interlock detects that combination **at runtime** and cuts the third leg before data leaves.

---

## Who it's for

**Primary persona — the AI Platform Engineer ("ships the agent").**
Deploys agents wired to many MCP servers. Wants a guardrail they can drop *in front of* an existing agent without rewriting it. Cares about: zero-code integration, low overhead, not breaking legitimate calls.

**Primary persona — the Security / AppSec Engineer ("owns the blast radius").**
Already treats agents as privileged identities. Wants runtime detection plus an evidence trail for incident response — not just a pre-deploy scan report. Cares about: detection fidelity, forensic receipts, containment.

**Secondary persona — the MCP Server Developer ("builds the tools").**
Wants to test their own server against poisoning and exfil paths before shipping it to a registry. Cares about: a repeatable attack harness and a clear pass/fail.

**Buyer context — Eng leadership / CISO.**
The one-line pitch they instantly understand: *"Scanners check what tools claim. Interlock watches what agents do."*

---

## Value proposition — why it's different

- **Runtime, not static.** Detection happens as the agent acts, not before it starts.
- **Sequence-level, not per-call.** The unit of detection is the trifecta pattern across a session, which no per-call scanner models.
- **Two observation planes.** A userspace MCP proxy *and* a kernel-level eBPF sensor, so it catches both chained-tool exfil and out-of-band side channels the proxy can't see.
- **Evidence-first.** Every trip produces a receipt — the injected instruction, the sensitive read, the attempted send — down to the syscall.

---

## Core tech stack (v0.2.1)

| Layer | Choice |
|---|---|
| Language (proxy, engine, control plane) | **Go** |
| Kernel sensor | **eBPF** via `cilium/ebpf` (ebpf-go); `connect()` probe only |
| Transport intercepted | **MCP over STDIO** (default) or **Streamable HTTP** (`2025-11-25`); backend servers remain STDIO children |
| Demo agent | **Claude Agent SDK** (scripted demo client) |
| Evidence UI | Self-contained **local HTML** (read-only) |
| Dev platform | **Ubuntu 6.x + BTF** (CO-RE-friendly) |
| Session state | In-memory per `session_id`; HTTP multi-session via `SessionManager` + `PIDRegistry` |
| Evidence persistence | **JSONL** intentional default; opt-in **SQLite** with `max_records` retention |

---

## Shipped vs deferred (v0.2.1)

**Shipped in v0.2:**

- Streamable HTTP MCP transport; multi-session concurrency with PID→session attribution
- Bounded encoding overlap on Variant A (base64, hex, URL-encoding, reversal)
- Engine microbenchmarks + end-to-end HTTP overhead story ([`performance.md`](performance.md))
- Opt-in SQLite evidence (JSONL remains intentional default), event log backpressure, eBPF ring-buffer drop counter

**Still out of scope** (see [`ROADMAP.md`](ROADMAP.md)):

- eBPF `sendto`/`write` payload capture (Variant B remains a `connect()` tripwire)
- Full byte-level dataflow taint (split/compressed/nested encoding — known-gap tests)
- Kernel-level blocking (LSM/KRSI), Kubernetes DaemonSet deployment
- Dashboard beyond the read-only viewer, cross-session query API, SIEM/metrics layer
- Multi-agent orchestration, policy config UX, managed platform

---

## Positioning vs the field

- **Static MCP scanners** (Cisco `mcp-scanner`, Snyk `agent-scan`, Backslash): pre-approval, tool-definition-level. Interlock is post-approval, behavior-level. **Complementary, not competitive** — run both.
- **MCP gateways:** traffic and auth layer (who can call what). Interlock adds behavioral detection and forensic evidence on top of whatever gateway exists.
- **AgentSight** (arXiv 2508.02736): the closest prior art. It names the same semantic gap (intent vs. action) and also uses eBPF — but it's a research framework and a paper, not a deployable product with enforcement and a demo-grade receipt. Interlock is the productized, enforcement-capable take.

**The moat is a moment, not permanent.** First working, well-documented, enforcement-capable tool wins the ~6–12 month window.

---

## Success criteria

**v0.1 (met — tagged `v0.1.0`):** both attack variants demo on STDIO; one-command reproduce; syscall-level evidence receipt.

**v0.2 (met — tagged `v0.2.0` + `v0.2.1`):** works on HTTP/SSE, handles concurrent sessions, catches encoded exfil on Variant A, publishes scoped overhead numbers, persists evidence (JSONL default intentional; SQLite opt-in for retention). Full audit: [`v0.2_summary.md`](v0.2_summary.md).

**Leading indicators of traction:** GitHub stars, maintainer engagement, and at least one "the next MCP CVE — Interlock would have caught it, here's the trace" moment.
