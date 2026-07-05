# Interlock — Roadmap

Interlock v0.1 is a working proof: it catches the lethal trifecta at runtime across two planes (a userspace MCP proxy and a kernel-level eBPF sensor), blocks the chained-tool exfil, contains the server side-channel, and produces a forensic receipt for each. It is deliberately scoped — STDIO transport, `connect()`-only eBPF, single session, heuristic value-overlap.

This roadmap is the path from *proof* to *product*. It's organized in two arcs:

- **v0.2 — Usable Tool.** It touches real MCP, detects things that can't be trivially bypassed, survives concurrency, and has a published performance story.
- **v0.3 — Adoptable Product.** A team can deploy it across a fleet, operate it, integrate it into their existing security stack, and trust it.

**A note on how to read this.** This is a map, not a commitment. The priorities below are reasoned from dependency and risk, but the *real* roadmap will be written by the people who use v0.1 — the issues they open and the questions they ask. Where user demand contradicts this document, user demand wins. v0.3 in particular should only be built if v0.2 produced demand for it; building the product layer for zero users is a well-known way to waste a year.

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

**Status (Phase 1 landed — PR #8, Issue #4):**

- **Shipped:** Streamable HTTP [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports/streamable-http) agent transport (`POST /mcp`, `Mcp-Session-Id`, JSON + SSE); inspect-then-forward documented in `docs/architecture.md` §4.1; shared `HandleAgentRequest` dispatch for STDIO and HTTP; `make demo-http`; auth-header redaction helpers; localhost bind (`127.0.0.1` only, no TLS termination in Phase 1).
- **Backend servers stay STDIO** — eBPF PID watching unchanged. HTTP is the *agent-facing* transport only.
- **Still deferred within v0.2 transport work:** HTTP upstream backends (remote MCP server URLs), TLS termination / MITM mode, multi-session concurrent HTTP clients (→ Phase 2), GET `/mcp` listen streams, [2026-07-28 stateless protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) migration.

**Watch out:**
- SSE plus a proxy creates a buffering hazard. Inspect-then-forward is safe but adds latency; forward-then-inspect is fast but may forward bytes before they're judged — a correctness problem for a *blocking* firewall. This trade-off is the phase's real design decision, not the plumbing. Decide it deliberately and document it.
- HTTP means auth headers, TLS, and connection reuse. Credentials now transit the proxy — the redaction discipline extends here, and TLS termination raises a trust-boundary question (MITM, or sit inside the boundary?).

### Phase 2 — Multi-Session Concurrency and Attribution

STDIO single-session was a demo simplification. Real deployment means many concurrent agents. The schema already carries `session_id`; the logic has to become real.

- Real PID→session mapping under concurrency: a syscall arrives from PID X — which of N active sessions owns it?
- Per-session state isolation in the engine and session store.
- Session lifecycle: creation, expiry, cleanup, and processes that fork children.

**Done when:** two poisoned sessions run concurrently, each correctly attributed, neither leaking state into the other.

**Watch out:**
- The PID→session map is a shared, concurrently-mutated structure — written by the proxy on spawn/exit, read by the eBPF event loop on every syscall. Classic race surface. A syscall can arrive for a PID *after* the process died but *before* cleanup, and the OS can recycle a PID to a different session. **PID reuse is a real correctness bug here** — the key may need to be PID + process-start-time, not PID alone.
- This is where concurrency bugs hide. Run `go test -race` continuously; the demo never surfaces these, only load does.

### Phase 3 — Real Dataflow Taint

Closes the detection-credibility gap. The `TestCheckOverlap_EncodedExfil_KnownGap` skip test documents exactly what's broken today; this makes it pass.

- Track tainted values through transformations, not just literal presence: base64, hex, URL-encoding, reversal, common obfuscations.
- Taint propagation where feasible: a tainted value that is concatenated, embedded, or transformed stays tainted.
- Pull in `sendto`/`write` payload capture on the eBPF side, so a confirmed secret in an outbound payload upgrades Variant B from `SUSPICIOUS` to `EXFIL`.

**Done when:** the encoded-exfil test that currently skips now *passes* — a base64'd token in the sink is caught.

**Watch out:**
- Full dataflow taint is a research-grade problem with no natural finish line. Scope it hard: cover the common encodings, declare the exotic ones (custom ciphers, split-across-calls, steganographic) still out of scope, and **keep a known-gap test for them.** "I do taint tracking now" invites a skeptic to find the encoding you missed — bound the claim to what you actually cover.
- Performance. Checking every sink payload against every tainted value through N transformations is expensive, and it collides directly with Phase 4. Sequencing taint *before* the benchmark phase is deliberate, so the numbers reflect the real system.

### Phase 4 — Performance, Benchmarks, and Persistent Evidence

The "is this operable" gate. A security tool with no performance numbers and file-based JSONL storage is a non-starter for anyone serious — and there are currently zero numbers.

- Benchmark suite: proxy-path overhead per request, eBPF event throughput, the event rate at which it drops or degrades, memory under sustained load.
- Publish the numbers honestly. "Adds X ms p99 per tool call" is a real, quotable stat.
- Replace JSONL evidence with a persistent store — embedded first (SQLite), not a server database. Don't over-build.
- Backpressure: define what happens when events arrive faster than they're processed. Today this is unknown, and unbounded growth or silent drops are both plausible.

**Done when:** there's a published overhead number, and evidence survives restart without growing unbounded.

**Watch out:**
- The eBPF ring buffer may **drop events under load** — invisible in a 4-event demo, critical in production, because a dropped `connect()` is a missed exfil. Instrument drop counts explicitly and surface them.
- The Phase 3 taint work is the likely bottleneck. If benchmarks are bad, deep taint-checking may need to be async or sampled rather than inline-blocking.

**v0.2 exit state:** works on HTTP/SSE *(Phase 1 ✓)*, handles concurrent sessions *(Phase 2 — next)*, catches encoded exfil, has published overhead numbers, persists evidence. A usable tool — someone can point it at a real agent.

---

## v0.3 — Adoptable Product

Turns the tool into something a team deploys, operates, and trusts at scale. Build this arc only if v0.2's release produced demand for it.

### Phase 1 — Kubernetes-Native Deployment (DaemonSet)

Where the market actually is: agent infrastructure runs in Kubernetes, and eBPF tools deploy as DaemonSets — one sensor per node.

- Package as a container; DaemonSet manifest; sensor-per-node watching that node's agent pods.
- Node-level PID→pod→session attribution: map kernel PIDs to container/pod identity.
- RBAC, security context, and the privileged-container story — justify and minimize it.

**Done when:** it deploys to a real cluster (kind/minikube) and catches exfil from an agent pod.

**Watch out:**
- **Container PID namespaces.** The PID the kernel sees is not the PID inside the container. The whole PID→session mapping assumed host PIDs; in Kubernetes it must translate across namespaces. This is the phase's core difficulty and it is genuinely fiddly.
- Privileged DaemonSets get scrutinized hard by security teams. The v0.1 transparency move — here is exactly what the probe does, read the source — scales up and matters more here.

### Phase 2 — Kernel-Level Blocking (LSM/KRSI) and Graceful Enforcement

Upgrades detection from detect-and-kill to actual prevention, closing the honest v0.1 limitation ("contained, not prevented" for Variant B).

- LSM/KRSI hook to block the `connect()` in-kernel before the packet leaves.
- Graceful responses beyond SIGKILL: block-the-call, quarantine-the-session, alert-only — configurable per verdict tier.
- A fail-closed option (v0.1 was fail-open for the demo; production wants the choice).

**Done when:** Variant B is upgraded — the packet never leaves, and the record reads `prevented`, not `contained_by_kill`.

**Watch out:**
- This is the **highest-risk work in either arc.** Kernel-level blocking via LSM/KRSI is more constrained than tracepoints, more kernel-version-sensitive, and a bug can break the host's networking or deadlock processes. Prototype in a throwaway VM you can destroy, not your main machine.
- **The blast radius inverts.** Once you block in-kernel, you're in the critical path of every connection. A bug no longer means a missed attack — it means broken legitimate traffic, or a downed host. Testing rigor has to level up at exactly this boundary.

### Phase 3 — Operability: Daemon, Config, Metrics, Alerting

The unglamorous layer that decides whether a team keeps it running.

- A proper service/daemon mode (systemd unit, real lifecycle), not a script invoked with `sudo`.
- Hot-reloadable, validated, versioned configuration.
- Prometheus metrics (sensor liveness, event rate, drop count, detection count, overhead) and health endpoints.
- Alerting integrations: Slack/PagerDuty webhooks, and structured SIEM export (OCSF or CEF) to plug into an existing security stack.

**Done when:** it runs as a managed service, exports metrics, and fires a real alert on detection.

**Watch out:**
- SIEM format compliance is finicky and boring, but it is *the* enterprise integration. Get the schema wrong and it won't ingest. Follow the OCSF spec exactly; don't invent fields.

### Phase 4 — Trust: Self-Security, Validation Corpus, Hardening

What makes senior engineers willing to run privileged kernel code in production.

- Least-privilege audit (drop every capability not needed post-load), tamper-resistance (can a compromised agent blind the sensor?), and a threat model *for Interlock itself*.
- Signed, reproducible releases — the run-as-root audience demands provenance.
- A real attack-scenario corpus (dozens of trifecta and evasion variants, not one fixture) and a **published false-positive rate** on realistic benign traffic.

**Done when:** there's a signed release, a documented threat model, and detection/false-positive numbers on a corpus rather than a single demo.

**Watch out:**
- The **false-positive rate** is where the product lives or dies. A tool that kills legitimate processes gets uninstalled on day one. If the FP rate on realistic traffic is bad, that is the single most important finding in the project, and it should reshape the detection logic — not get buried to protect a launch narrative. This is the v0.1 honesty discipline at product scale.

**v0.3 exit state:** deploys as a Kubernetes DaemonSet, blocks in-kernel, runs as an operable service with metrics and SIEM integration, and ships signed with a threat model and a published false-positive rate. An adoptable product.

---

## Cross-Cutting Hazards

Four things span both arcs and are the most likely to cause real damage:

- **Concurrency and races** (v0.2 Phase 2, v0.3 Phase 1) — PID reuse, namespace translation, shared-map mutation. `go test -race` is not optional. Demos never surface these; load does.
- **Performance vs detection depth** — every detection feature (taint, payload inspection, per-session tracking) taxes the hot path. Benchmark continuously, not once, or the tool becomes too expensive to run.
- **Scope-infinity** on taint and validation — both are bottomless. Bound them with explicit known-gap tests. Naming what you don't catch is the signature discipline; keep making that move.
- **The blast-radius inversion** (v0.3 Phase 2) — the moment enforcement moves from observing to blocking in-kernel, a bug stops meaning "missed detection" and starts meaning "broke the host."

---

## Backlog (Beyond v0.3)

Real features, deferred until demand justifies them: IPv6 and DNS-level tracing; Unix-socket and file-based exfil paths; a cross-session dashboard with search and trends; an API for programmatic evidence access; role-based access and operator audit logs; ARM support and cross-distro/CO-RE portability; a managed cloud offering; third-party security audit and red-team results; comparison benchmarks against static scanners.

None of these move the next release. They are a menu for when users ask.
