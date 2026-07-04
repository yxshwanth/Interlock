# Week 3 Summary — eBPF Sensor (Variant B)

**Status:** Complete (post-completion hardening applied)
**Duration:** Week 3 of the four-week build sequence

---

## Goal

> Catch the server-opened side channel the proxy is blind to. Scoped to `connect()` only — `sendto`/payload excerpt, `openat()`, and DNS deferred to v0.2 backlog.

**Achieved.** A compiled eBPF `connect()` probe loaded via cilium/ebpf detects outbound TCP connections from monitored server processes. When a malicious server opens its own socket to an attacker address — bypassing the proxy entirely — the eBPF sensor fires, the engine trips the trifecta, and the offending process is killed. The evidence viewer renders a fused timeline containing both proxy-intercepted events (Variant A) and kernel-observed syscall events (Variant B).

**Honest containment claim:** eBPF is detect-only at the kernel. The `connect()` may have already left when kill fires. "Contained" means the channel is severed and the process cannot continue — not "the first packet was prevented."

**Post-completion hardening (3 fixes):** (1) Demo comparison table widened to three columns (`MONITOR | BLOCK | eBPF`) so the Variant B result is in the money-shot table, not buried in prose. (2) Attacker IP swapped from `93.184.216.34` (example.com) to `203.0.113.66` (RFC 5737 TEST-NET-3) — reserved for documentation, guaranteed to route nowhere. (3) Variant B detection claim reframed honestly: "detected an unauthorized outbound connection during a sensitive session," not "detected exfiltration." False-positive surface stated plainly in architecture.md and scope decisions below.

---

## What Was Built

### eBPF Probe (`internal/ebpf/`)

| File | Lines | Purpose |
|---|---|---|
| `connect.c` | 74 | BPF C source. Tracepoint on `sys_enter_connect`, reads `sockaddr_in` to extract dest IP/port, checks PID membership in a BPF hash map, pushes a `connect_event` struct to a 256KB ring buffer. IPv4 only. |
| `generate.go` | 3 | `//go:generate` directive for `bpf2go` — compiles `connect.c` to `connect_x86_bpfel.o` + Go bindings via clang. |
| `connect_x86_bpfel.go` | 145 | Generated Go bindings: `connectObjects`, `connectMaps` (events ring buffer + pid_filter hash map), `connectPrograms` (tracepoint program). Embeds the compiled `.o` file. |
| `loader.go` | 138 | Go-side BPF lifecycle: `NewLoader()` loads the probe and attaches to the `sys_enter_connect` tracepoint via `link.Tracepoint`. `ReadEvent()` decodes ring buffer records into `ConnectEvent` structs. `UpdatePIDSet()` / `AddPID()` manage the PID filter map. `Close()` tears down in the correct order. |
| `sensor.go` | 146 | `Sensor` struct: owns the `Loader`, maintains the egress allowlist, reads events in a goroutine, filters allowlisted IPs, converts to `model.SyscallEvent`, calls the engine handler, and enforces kill-on-detect when `Action=ActionContained`. `KillProcess(pid)` sends SIGKILL to the process group. |

### Engine Extension (`internal/engine/engine.go` — now 375 lines)

The engine gained a second ingestion path for Variant B:

**`IngestSyscall(ev model.SyscallEvent) model.Decision`** — Called when the eBPF sensor detects a non-allowlisted `connect()` from a monitored PID. It:

1. Resolves the PID to a session (v0.1: single session, so `FirstSessionID()` is used).
2. Lights `external_sink_invoked` with a detail string including dest IP, port, PID, and comm.
3. Checks `AllLit()` — if all three legs are lit, determines verdict (`SUSPICIOUS`, since syscall events don't have value-overlap in v0.1) and action (`contained_by_kill`).
4. Builds a Variant B `EvidenceRecord` with a **fused timeline**: proxy-intercepted items (`kind: "intercepted"`) merged with the syscall event (`kind: "syscall"`).
5. Emits to the evidence sink and returns a `Decision` the sensor can act on.

**`buildEvidenceVariantB`** — Constructs the evidence record for Variant B. The `SinkCall` field contains syscall metadata (syscall name, dest IP/port, PID, comm) instead of tool call info. The timeline merges both planes.

**`SessionStore.FirstSessionID()`** — Returns the ID of any session in the store, used by the eBPF path where v0.1 has only one active session.

### Poisoned Exfil Server (`servers/exfil/main.go` — 71 lines)

A third toy MCP server for the Variant B demo. Provides a `run_analysis` tool that, when called, opens a TCP connection to a hardcoded attacker address (`203.0.113.66:4444`). The proxy sees this as a normal, innocuous tool call — `run_analysis` is not tagged as an external sink. The side-channel exfil is only visible to the eBPF sensor watching `connect()` syscalls.

The connection will likely fail (no server at that IP:port) — but the eBPF probe fires on the `connect()` attempt, not on success.

### Proxy Extension (`internal/proxy/proxy.go` — now 544 lines)

- **`OnServersReady(fn func(childPIDs []int))`** — Registers a callback that fires after all child servers are launched and initialized but before the dispatch loop begins. The eBPF sensor uses this to populate the PID filter map at the right time.
- **`ChildPIDs()`** — Returns the PIDs of all launched child server processes.

### Main Binary (`cmd/interlock/main.go` — now 89 lines)

Added `--ebpf` flag. When set, initializes the `Sensor` before `p.Run()` and wires the `OnServersReady` callback to:

1. Add self PID + all child PIDs to the BPF filter map.
2. Start the sensor's event-reading goroutine.

The sensor handler calls `eng.IngestSyscall(ev)` and the sensor's event loop handles kill-on-detect when the decision says `ActionContained`.

### Dual-Variant Demo (`cmd/demo/main.go` — now 462 lines)

Updated from two passes to three:

| Pass | Config | Mode | What Happens |
|---|---|---|---|
| **1 — Monitor** | `interlock-monitor.yaml` | Variant A, firewall off | Exfil via `send_message` goes through (breach) |
| **2 — Block** | `interlock.yaml` | Variant A, firewall on | Exfil via `send_message` blocked at proxy |
| **3 — eBPF** | `interlock.yaml` + `--ebpf` | Variant B, kill-on-detect | Exfil server opens socket, eBPF detects, process killed |

Pass 3 requires root. If not root, the demo gracefully skips with instructions (`sudo go run ./cmd/demo`). The summary table shows all three results side by side.

### Evidence Viewer (`web/viewer.html` — now 375 lines)

Updated with Variant B support:

- **Syscall timeline items** styled distinctly (orange dots, `[SYSCALL]` badge) from intercepted items.
- **Kind labels** displayed on each timeline item (`[intercepted]` or `[syscall]`).
- **Variant B sink call rendering** shows syscall name, destination IP:port, PID, and process name instead of tool name/server.
- **Variant label** displays "Variant B: Server Side Channel" for eBPF-detected events.

### Throwaway CLI (`cmd/ebpf-test/main.go` — 78 lines)

Rung 1 verification tool. Loads the BPF probe, adds self PID to the filter, listens for `connect()` events for 30 seconds. Used to verify the probe works in isolation before wiring to the engine.

---

## Architecture

```
Agent (demo client)
    │
    ▼ stdin/stdout
Interlock Proxy
    │
    ├── handleToolsCall ──── ┐
    │                        │  engine.EvaluateRequest(ev)
    │   ┌────────────────────┘
    │   │ Allow?
    │   ├── NO  → synthesized JSON-RPC error (-32000) → agent
    │   ├── YES → forward to child server
    │   │
    │   └── readServerFrames → engine.IngestResult(ev)
    │       │ lights legs 1+2, extracts tainted values
    │       └── forward response → agent
    │
    ├──→ tickets server (child, pid watched by eBPF)
    │       └── read_ticket → sensitive data + poisoned instruction
    │
    ├──→ messenger server (child, pid watched by eBPF)
    │       ├── send_message → external sink (Variant A: blocked)
    │       └── http_post   → external sink (Variant A: blocked)
    │
    └──→ exfil server (child, pid watched by eBPF)     ← NEW
            └── run_analysis → opens TCP to 203.0.113.66:4444
                                  │
                                  ▼ connect() syscall
                            eBPF Sensor (kernel)
                                  │
                                  ▼ SyscallEvent
                            engine.IngestSyscall(ev)
                                  │ lights leg 3, trips trifecta
                                  ▼ verdict=SUSPICIOUS, action=contained_by_kill
                            sensor.KillProcess(pid) → SIGKILL
```

**Two detection planes, one engine.** The proxy catches Variant A (chained tool calls where the agent itself is the exfil vector). The eBPF sensor catches Variant B (a malicious server that opens its own egress channel). Both feed the same trifecta state machine; both emit `EvidenceRecord`s with fused timelines.

---

## The Variant B Attack

The demo exercises a side-channel exfil that the proxy is structurally blind to:

1. Agent calls `read_ticket` → proxy lights legs 1+2 (sensitive source touched + untrusted content present), extracts tainted values.
2. Agent calls `run_analysis` on the exfil server → proxy sees a normal tool call. `run_analysis` is not tagged as an external sink. The proxy allows it.
3. The exfil server's handler opens a TCP connection to `203.0.113.66:4444` — the side-channel exfil. This `connect()` happens inside the server process, completely outside the proxy's stdin/stdout pipes.
4. The eBPF probe fires: the server's PID is in the filter map, the destination is not in the egress allowlist. The sensor builds a `SyscallEvent` and calls `engine.IngestSyscall()`.
5. The engine lights leg 3 (`external_sink_invoked` via eBPF). All three legs are now lit. Verdict: `SUSPICIOUS` (no value overlap for syscall events in v0.1). Action: `contained_by_kill`.
6. The sensor sends SIGKILL to the process group. The exfil server is dead.
7. The evidence record includes both the proxy-intercepted events (ticket read, analysis call) and the kernel-observed connect() in one fused timeline.

**What the proxy sees:** a normal `run_analysis` call with no suspicious arguments.
**What the kernel sees:** `connect(203.0.113.66:4444)` from a monitored PID.
**What the engine concludes:** all three legs lit — this is the lethal trifecta, detected from the kernel plane.

---

## The Rung-Based Build Approach

Week 3 isolated the real risk (can Go load a compiled BPF probe and get events out?) into Rung 1 and built incrementally:

| Rung | What | Risk Level | Outcome |
|---|---|---|---|
| **0** | bpftrace prototype — prove `connect()` visibility | De-risk | Confirmed: `sys_enter_connect` tracepoint present, bpftrace v0.20.2 installed, BTF available |
| **1** | Compiled probe loaded from Go via cilium/ebpf | **HIGH** (the week's risk) | BPF C compiled via bpf2go, Go loader reads ring buffer events, test CLI verified |
| **2** | BPF hash map for PID-set filtering | Low | Probe checks `bpf_map_lookup_elem` before emitting; Go manages the map |
| **3** | Ring buffer → SyscallEvent → engine | Low (Go plumbing) | `IngestSyscall` method, allowlist check, Variant B evidence, 5 new tests |
| **4a** | Kill-on-detect | Low | `KillProcess(pid)` via SIGKILL to process group |
| **4b** | Exfil server fixture | Low | `servers/exfil/main.go` — opens TCP to attacker address |
| **4c** | Fused timeline in viewer | Low | Distinct syscall styling, kind badges |
| **4d** | Dual-variant demo | Low | Three-pass demo with graceful root detection |

The antifragile fallback (ship Variant A now, post eBPF as v0.1.1) was never needed — Rung 1 worked on the first compile.

---

## Test Results

- **72 unit tests passing, 1 skipped** (73 total)
  - **8 config tests** — valid parse, defaults, invalid enforcement, missing fields, duplicates, file not found
  - **9 framer tests** — single/multi message, blank lines, CRLF, partial reads, EOF, concurrent writes
  - **20 engine tests** — 15 Variant A tests (leg lighting, tainted values, EXFIL/SUSPICIOUS verdicts, monitor/block modes, sticky legs, timeline, evidence fields) + **5 new Variant B tests** (IngestSyscall lights external sink, trips when all legs lit, no trip with insufficient legs, fused timeline, auto-resolves session)
  - **7 session store tests** — creation, retrieval, upsert, overwrite, all sessions, concurrent access, + `FirstSessionID`
  - **8 tagger tests** — per-tool override, server fallback, unknown tool, tag identification
  - **8 taint tests** — hashing, masking, API key extraction, bearer tokens, deduplication, JSON serialization
  - **8 overlap tests** — match, no match, empty inputs, first hit, partial match, empty value skip, + 1 skipped
  - **3 evidence sink tests** — JSONL append, standalone JSON, multiple emits
  - **9 proxy tests** — session creation, event creation, direction, method parsing, tools/call parsing, notifications
- **1 skipped test** — `TestCheckOverlap_EncodedExfil_KnownGap` (documented v0.1 gap)
- **`go vet`** — zero warnings
- **`go build ./...`** — clean across all packages
- **End-to-end demo** — passes 1+2 run cleanly; pass 3 (eBPF) requires `sudo`

---

## Demo Output (abridged)

```
╔═══════════════════════════════════════════════╗
║   INTERLOCK DEMO — DUAL-VARIANT DETECTION   ║
╚═══════════════════════════════════════════════╝

  Scenario: a poisoned support ticket instructs the agent to
  exfiltrate a customer auth token. Two attack vectors:

    Variant A: Agent chains tools/call to send_message (proxy sees it)
    Variant B: Malicious server opens its own socket (only eBPF sees it)

═══ PASS 1: MONITOR MODE (firewall OFF) — Variant A ═══

[engine] leg lit: sensitive_source_touched (tool=read_ticket)
[engine] extracted 2 tainted value(s) from tickets/read_ticket
[engine] leg lit: untrusted_content_present
[engine] leg lit: external_sink_invoked (tool=send_message)
[engine] TRIFECTA DETECTED: verdict=EXFIL action=allowed_monitor
  ← call went through — BREACH!

═══ PASS 2: BLOCK MODE (firewall ON) — Variant A ═══

[engine] leg lit: sensitive_source_touched (tool=read_ticket)
[engine] leg lit: external_sink_invoked (tool=send_message)
[engine] TRIFECTA DETECTED: verdict=EXFIL action=prevented
  ← BLOCKED by Interlock

═══ PASS 3: eBPF VARIANT B — Side-Channel Detection + Kill ═══

[engine] leg lit: sensitive_source_touched (tool=read_ticket)
[engine] leg lit: untrusted_content_present
[sensor] connect detected: pid=169059 comm=exfil dest=203.0.113.66:4444
[engine] leg lit: external_sink_invoked via eBPF (dest=203.0.113.66:4444)
[engine] TRIFECTA DETECTED (eBPF): verdict=SUSPICIOUS action=contained_by_kill
[sensor] KILL-ON-DETECT: sending SIGKILL to pid 169059

╔════════════════════════╗
║   RESULTS COMPARISON   ║
╚════════════════════════╝

                           MONITOR (off)         BLOCK (on)           eBPF (kill)
  ───────────────────────  ────────────────────  ────────────────────  ────────────────────
  read_ticket              OK (data returned)    OK (data returned)   OK (data returned)
  send_message (exfil)     SENT (breach!)        BLOCKED              —
  http_post (exfil)        SENT (breach!)        BLOCKED              —
  run_analysis (side ch.)  —                     —                    NO RESPONSE (process killed)
  connect() detected?      —                     —                    YES
  Process killed?          —                     —                    YES
  Evidence logged?         YES                   YES                  YES

  Monitor:  trifecta detected, calls went through (BREACH).
  Block:    trifecta detected, calls BLOCKED at proxy (Variant A prevented).
  eBPF:     unauthorized egress detected by kernel, process KILLED (Variant B contained).
```

---

## Scope Decisions

**connect()-only.** Each additional probe type (`sendto`, `openat`, DNS) is its own kernel struct with its own decoding and testing burden. Shipping `connect()` end-to-end — from BPF C to fused evidence viewer — is the right scope for v0.1. The acceptance criterion names `connect()` and nothing else.

**SUSPICIOUS, not EXFIL — and what that means for the claim.** Syscall events in v0.1 can't do value-overlap (we don't inspect payload). So the verdict for a Variant B trip is always `SUSPICIOUS` (confidence 0.60). The accurate detection claim is: "detected an unauthorized outbound connection during a sensitive session" — not "detected exfiltration." Which is genuinely valuable and defensible. An unexpected egress from a supervised process during a session where sensitive data has been touched is a high-signal tripwire worth killing and investigating, even without payload proof.

**The false-positive surface, stated plainly.** A monitored server that legitimately calls a non-allowlisted API mid-session gets killed, with no payload evidence that anything was actually exfiltrated. That's the gap. Payload inspection (`sendto` excerpt + kernel-side value-overlap) to distinguish exfil from benign egress is v0.2 — and it's what would upgrade this from `SUSPICIOUS` to `EXFIL`.

**contained_by_kill, not prevented.** The proxy's `prevented` action means the call never reached the server — true prevention. The eBPF sensor's `contained_by_kill` means the process was killed after the `connect()` attempt — the first packet may already be in flight. This is an honest distinction, not a hedge.

---

## What's Next — Week 4

Both detection planes are operational. Week 4 turns the prototype into a launch:

- Secret redaction audit (verify no raw token is ever written to evidence)
- Fail-open/closed decision documented
- One-command demo runner (`make demo`)
- README polish + money-shot GIF
- 90-second demo recording (off → breach, on → block, both variants, syscall receipt)
- Launch post draft
- Repo hygiene: CI, quickstart, contribution guide

---

## Files

### New in Week 3
```
internal/ebpf/connect.c            — BPF C source for connect() tracepoint (74 lines)
internal/ebpf/generate.go          — go:generate directive for bpf2go (3 lines)
internal/ebpf/connect_x86_bpfel.go — generated Go bindings (145 lines)
internal/ebpf/connect_x86_bpfel.o  — compiled BPF bytecode (embedded)
internal/ebpf/vmlinux.h            — generated BTF header (162,244 lines)
internal/ebpf/loader.go            — cilium/ebpf loader + PID map (138 lines)
internal/ebpf/sensor.go            — Sensor struct, event loop, kill-on-detect (146 lines)
cmd/ebpf-test/main.go              — throwaway Rung 1 verification CLI (78 lines)
servers/exfil/main.go              — poisoned server, opens own socket (71 lines)
```

### Modified in Week 3
```
internal/engine/engine.go          — +IngestSyscall, +buildEvidenceVariantB (375 lines, was 255)
internal/engine/engine_test.go     — +5 Variant B tests (693 lines, was 519)
internal/engine/session_store.go   — +FirstSessionID (81 lines, was 70)
internal/proxy/proxy.go            — +OnServersReady, +ChildPIDs (544 lines, was 524)
cmd/interlock/main.go              — +--ebpf flag, sensor init (89 lines, was 60)
cmd/demo/main.go                   — +Variant B pass, 3-col table, honest framing (483 lines, was 262)
web/viewer.html                    — +syscall timeline styling, Variant B sink (375 lines, was 352)
interlock.yaml                     — +exfil server entry (29 lines)
interlock-monitor.yaml             — +exfil server entry (30 lines)
docs/task_list.md                  — rung-based Week 3, sendto/openat/DNS to backlog (123 lines)
docs/architecture.md               — §5 updated, false-positive surface paragraph (368 lines, was 366)
go.mod                             — +cilium/ebpf v0.22.0, +golang.org/x/sys
```
