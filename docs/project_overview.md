# Interlock — Project Overview

## One line

Interlock is a **runtime behavioral firewall for AI agents**. It watches what an agent *does* across its tool calls and severs the connection the instant a benign-looking sequence turns into a data exfiltration.

---

## The problem

MCP became the default way agents talk to tools in under 18 months, and security did not keep up. The first half of 2026 produced 40+ CVEs against MCP implementations (roughly one every four days, hitting tools with ~150M combined downloads), a May 2026 disclosure estimating up to ~200,000 vulnerable MCP instances, and 88% of organizations reporting a confirmed or suspected AI agent incident in the prior year. Only ~8.5% of MCP implementations use OAuth.

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

## Core tech stack

| Layer | Choice |
|---|---|
| Language (proxy, engine, control plane) | **Go** |
| Kernel sensor | **eBPF** via `cilium/ebpf` (ebpf-go); probes prototyped in **bpftrace** first |
| Transport intercepted (v0.1) | **MCP over STDIO** |
| Demo agent | **Claude Agent SDK** |
| Evidence UI | Self-contained **local HTML** (read-only) |
| Dev platform | **Ubuntu 6.x + BTF** (CO-RE-friendly) |
| Data (v0.1) | In-memory session state + **JSONL evidence log**; no external DB |

---

## Non-goals (v0.1)

Explicitly out of scope, on purpose: HTTP/SSE transport, byte-level dataflow taint tracking, kernel-level *blocking* (LSM/KRSI), any dashboard beyond the timeline, multi-agent orchestration, config UX, and anything resembling "a platform." These are tracked in the backlog for v0.2/v0.3.

---

## Positioning vs the field

- **Static MCP scanners** (Cisco `mcp-scanner`, Snyk `agent-scan`, Backslash): pre-approval, tool-definition-level. Interlock is post-approval, behavior-level. **Complementary, not competitive** — run both.
- **MCP gateways:** traffic and auth layer (who can call what). Interlock adds behavioral detection and forensic evidence on top of whatever gateway exists.
- **AgentSight** (arXiv 2508.02736): the closest prior art. It names the same semantic gap (intent vs. action) and also uses eBPF — but it's a research framework and a paper, not a deployable product with enforcement and a demo-grade receipt. Interlock is the productized, enforcement-capable take.

**The moat is a moment, not permanent.** First working, well-documented, enforcement-capable tool wins the ~6–12 month window.

---

## Success criteria for v0.1

- **The demo lands:** firewall-off breach vs. firewall-on block, on camera, with a syscall-level timeline as the receipt.
- **Both variants work:** A (proxy-blocked) and B (eBPF-detected + contained).
- **A clean OSS repo** anyone can clone and reproduce with one command, plus a launch post that credits Willison and AgentSight.
- **Leading indicators of traction:** GitHub stars, a maintainer or two engaging, and at least one "the next MCP CVE — Interlock would have caught it, here's the trace" moment.
