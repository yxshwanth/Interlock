# Interlock — Architecture (v0.2.2 + v0.3 Phase 1/2 Slice 1/3/4)

## 0. Reading note

Interlock is a backend/systems tool, not a web app, so the usual buckets map like this:

- **"Frontend / backend boundary"** → the process and **trust** boundaries between the proxy, the kernel sensor, the correlation engine, and the read-only evidence viewer.
- **"State management"** → the per-session **trifecta state machine** plus cross-plane event correlation (§7).
- **"Database schema"** → the **event and evidence data model** (§8). Session state is in-memory; evidence defaults to **JSONL append** (`evidence.jsonl`) by design, with opt-in **SQLite** retention (`evidence.backend: sqlite`, `max_records`).

---

## 1. Component topology

```mermaid
flowchart TB
    Agent[AI Agent]
    Proxy[MCP Proxy]
    Servers["MCP servers — untrusted<br/>tickets · messenger · exfil"]

    subgraph tcb [Interlock TCB]
        direction TB
        Engine[Correlation Engine]
        Ebpf[eBPF Sensor]
        Sink[Evidence Sink]
    end

    Attacker[Attacker host]

    Agent <-->|JSON-RPC STDIO or HTTP| Proxy
    Proxy <-->|spawns and pipes| Servers
    Proxy -->|InterceptedEvent| Engine
    Ebpf -->|SyscallEvent| Engine
    Engine -->|Decision| Proxy
    Engine -->|EvidenceRecord| Sink
    Ebpf -.->|PID watch| Proxy
    Ebpf -.->|connect / write| Servers
    Servers -.->|TCP bypasses proxy| Attacker
```

Four components, one binary (plus the kernel probes it loads): the **proxy** (Plane 1), the **eBPF sensor** (Plane 2), the **engine** (owns state and verdicts), and the **evidence sink + viewer** (the only "UI").

---

## 2. Trust boundaries

This is a security tool; boundaries are the design.

- **Untrusted:** MCP server processes (may be poisoned or outright malicious), all tool **results**, fetched web content, and — critically — **the agent's own outputs**, because the agent is the thing being hijacked. Interlock assumes the agent *will* be manipulated and does not trust its intent.
- **Trusted (TCB):** the proxy, engine, eBPF sensor, and config. Interlock **must not become the exfil path itself** — it never forwards a blocked call, holds minimal privilege beyond what eBPF requires, and performs **no network egress of its own** except writing local evidence.
- The agent sits **inside the untrusted zone** from Interlock's perspective. Detection is designed around behavior, not stated intent.

**Two planes, two Variant B stories (ROADMAP §7):**

| Deploy shape | Who spawns MCP servers | Variant B side-channel |
|---|---|---|
| **Proxy mode** with `sandbox.netns: true` | Interlock (`SessionManager` → `StartServer`) | **Prevented by netns** — child is in a zero-route network namespace (`CLONE_NEWNET`); non-loopback `connect()` gets `ENETUNREACH`. eBPF still observes, but the channel is closed by construction. |
| **Sensor-only** (DaemonSet) | Not Interlock | **Contained by eBPF** — Interlock does not control spawn, so netns does not apply; payload-overlap + kill / LSM quarantine remain the mechanism. |

Default is `sandbox.netns: false` (opt-in). DNS in the netns: **no resolution** — sensitive STDIO sources do not need it; no controlled resolver is stood up.

---

## 3. Data flow — life of a tool call

The proxy is **protocol-aware**, not a transparent byte pipe. It terminates `initialize`, `tools/list`, and `ping` internally, synthesizing responses on behalf of all child servers. For `tools/call`, it parses the tool name, resolves it to the owning server via its routing table, and dispatches. This is the enforcement chokepoint.

1. Agent emits a JSON-RPC request (STDIO or HTTP) → **proxy parses the method**. Protocol-level messages (`initialize`, `tools/list`, `ping`, notifications) are handled by the proxy itself — it responds with synthesized results (merged capabilities, merged tool list, etc.) and emits `InterceptedEvent`s for each. These never reach a child server.
2. For `tools/call`: the proxy parses the tool name and arguments from `params`, resolves the tool name to its owning child server via the routing table, and creates an `InterceptedEvent` (direction = agent→server) attributed to that server.
3. Engine runs a **pre-forward `EvaluateRequest`** at this parsed dispatch point — after the proxy knows the tool name, args, and target server. Is this call an `external_sink`, and are the other two legs already lit for this session? If a trip fires → **block** (Variant A): the proxy synthesizes a JSON-RPC error result back to the agent using the same response-synthesis mechanism it uses for `initialize` and `tools/list`. The call **never reaches the server**. When opt-in `vault.enabled` is on and the tool is in `vault.authorize`, the engine **detokenizes** dummy tokens to real secrets **before** `CheckOverlap`, then (only if allowed) returns `ForwardArgs` so the proxy rewrites the frame before `WriteFrame` — ordering is `vault → detokenize-at-authorized-sink → scan detokenized`.
4. Otherwise the proxy **forwards** the raw frame (or detokenized frame) to the resolved child server over its STDIN.
5. Server executes and returns a result on its STDOUT → **proxy intercepts the result frame** → `InterceptedEvent` (direction = server→agent), attributed to the specific server.
6. Engine **ingests the result**: if the tool is a `sensitive_source`, it **registers tainted values** and lights `sensitive_source_touched`; if the tool is **not** a sensitive source and `untrusted_origins.tool_results` is true, it lights `untrusted_content_present` and stores a bounded excerpt for content-binding. When `vault.enabled`, newly extracted secrets are also vault-mapped to inert `ilk.vault.*` dummies and the **agent-visible frame is rewritten** before delivery (children never see the rewrite of results they themselves produced; the agent and later tool args do).
7. In parallel, the **eBPF sensor** streams `SyscallEvent`s from the proxy's PID subtree. A `connect()` from a *server child* to a non-allowlisted destination → `external_sink_invoked` candidate. If the other legs are lit → **`SUSPICIOUS`** (Variant B): emit evidence only, `detected_only` — no kill. If a corroborating `write`/`writev`/`sendto`/`sendmsg` payload overlaps a tainted value → **`EXFIL`**: emit evidence and **kill the offending child** (containment); hard containment is reserved for `EXFIL` (§5, §7).
8. On any trip, the engine writes an `EvidenceRecord` to the sink; the viewer renders it.

---

## 4. Plane 1 — the MCP proxy (Go)

**Multi-server, protocol-aware.** In **STDIO mode**, the proxy launches all configured MCP servers as child processes at startup. In **HTTP mode**, each MCP session gets a dedicated backend pool spawned on `initialize` (see §4.1). In both modes the proxy wires stdin/stdout/stderr as pipes, runs the MCP handshake, queries `tools/list`, and builds a **tool name → server** routing table. The agent sees a single MCP endpoint; the proxy presents a merged view of all servers' capabilities.

**Response synthesis.** The proxy handles `initialize`, `tools/list`, and `ping` internally — it assembles responses from the child servers' capabilities and tool definitions without forwarding these protocol-level messages. `tools/list` returns a merged tool list aggregated from all servers. This is the same response-synthesis mechanism that Week 2's enforcement uses to return block errors.

**JSON-RPC framing.** The MCP stdio transport uses newline-delimited JSON-RPC messages (one compact JSON object per line, no embedded newlines). This was verified against the [MCP stdio transport spec](https://modelcontextprotocol.io/specification/draft/basic/transports/stdio) in Week 1: there are **no Content-Length headers** (unlike LSP) — the newline is the sole message delimiter. The frame reader uses `bufio.Scanner` with a 1MB buffer, handles partial reads across `read()` boundaries, tolerates `\r\n` line endings, and skips blank lines.

### 4.1 Transport — Streamable HTTP (v0.2 Phase 1)

Agents can connect via [Streamable HTTP `2025-11-25`](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports/streamable-http) instead of STDIO. **Backend MCP servers remain STDIO child processes** — eBPF PID watching and Variant B containment are unchanged.

**Inspect-then-forward, always.** A blocking firewall cannot stream bytes to the agent before policy runs:

| Direction | Rule |
|---|---|
| Agent → Interlock (POST body) | Full JSON-RPC body parsed before dispatch |
| Interlock → STDIO child | Unchanged — hold-before-forward on `tools/call` before `WriteFrame` |
| STDIO child → Interlock | Full result frame received before `IngestResult` |
| Interlock → Agent (SSE) | Buffer complete JSON-RPC response before writing first SSE `data:` line |

Blocked `tools/call` responses use `Content-Type: application/json` with a synthesized error immediately (no SSE).

**HTTP surface:** `POST /mcp` with `Accept: application/json, text/event-stream`, `MCP-Protocol-Version: 2025-11-25`, and `Mcp-Session-Id` after `initialize`. Optional `Mcp-Method` / `Mcp-Name` headers are validated against the JSON-RPC body (SEP-2243 baseline). `Authorization`, `Cookie`, and similar headers are redacted before any log metadata is emitted.

**TLS posture (Phase 1):** bind `127.0.0.1` only — Interlock sits inside the trust boundary. TLS termination and MITM mode are deferred to a later v0.2 slice.

**Deferred:** HTTP upstream backends (remote MCP server URLs), GET `/mcp` listen streams, TLS termination / MITM mode, and the [2026-07-28 stateless protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) migration.

### 4.2 Multi-session concurrency (v0.2 Phase 2)

HTTP mode supports **many concurrent MCP sessions**. Each `initialize` spawns an isolated tickets/messenger/exfil backend pool until idle expiry (`sessions.idle_timeout`, default 30m) or `sessions.max_concurrent` (default 32). A `SessionManager` tracks lifecycle; a `PIDRegistry` maps `(pid, start_time)` → `{session_id, server_id}` for eBPF attribution. `IngestSyscall` requires an explicit `SessionID` — no `FirstSessionID` fallback. Unattributed syscalls during PID teardown are audit-logged, not tripped. STDIO mode remains single-session.

**Process lifecycle.** Deterministic startup ordering (spawn all children, initialize each, confirm tools registered, then accept agent traffic); graceful shutdown that drains in-flight frames; crash handling that surfaces a clean error to the agent rather than hanging; process-group isolation (`Setpgid`) so children can be killed cleanly; **spawn allowlist** — each `servers[].command` is canonicalized (`filepath.Clean` → absolute via `filepath.Abs` → `filepath.EvalSymlinks`) and pinned at config load; spawn re-resolves and requires equality with the pinned real path (symlink swaps to a different target are rejected); rejects path traversal (`..` anywhere in the command string, including `servers/../../../bin/sh`) and executables that do not match the pinned path for that server ID (optional `sandbox.spawn_allowlist` for helpers); optional **zero-route network namespace** (`sandbox.netns: true` → `CLONE_NEWNET` at spawn — no host NIC route, no resolver; default off; needs `CAP_SYS_ADMIN`); and **kill-on-detect** — the containment primitive Plane 2 uses for Variant B when netns is off or for sensor-only deployments. Host-app config/UI poisoning before Interlock is invoked remains out of scope (see [`cve_corpus.md`](cve_corpus.md) out-of-scope spawn family).

**Enforcement (hold-before-forward at the `tools/call` dispatch point).** Enforcement hooks at the specific point where the proxy has parsed a `tools/call` request, extracted the tool name and arguments, and resolved the target server — not at a generic frame boundary. The engine's `EvaluateRequest` runs here. On `Allow`, the raw frame is forwarded to the resolved child. On block, the proxy **never forwards** and instead synthesizes a JSON-RPC error (`"call blocked by Interlock: <reason>"`) using the same response-synthesis path it already uses for protocol messages. The agent gets a clean, legible failure.

---

## 5. Plane 2 — the eBPF sensor (kernel)

**Attachment.** Probes are scoped to the proxy's **process subtree** — the proxy PID plus every server child PID. Userspace maintains the live PID set and pushes it to a **BPF hash map** (`BPF_MAP_TYPE_HASH`) so the probe checks membership cheaply in-kernel before emitting events.

**Probe: `connect()` + `write()` / `writev()` + `sendto()` / `sendmsg()` + `openat()` (Variant B).**
- Tracepoints: `sys_enter_connect`, `sys_enter_write`, `sys_enter_writev`, `sys_enter_sendto`, `sys_enter_sendmsg`, `sys_enter_openat`.
- Connect: destination family + 16-byte addr + port from `sockaddr_in` / `sockaddr_in6`, PID, TID, and comm (`AF_INET` / `AF_INET6`).
- Write / writev: first **N** bytes via `bpf_probe_read_user` (fd ≥ 3; compiled `PAYLOAD_MAX=1024`, runtime `ebpf.payload_capture_bytes` default **1024**); writev probes the **first iovec only** (verifier-bounded). Correlated in userspace to a recent non-allowlisted connect/`sendto`/`sendmsg` from the same PID.
- Sendto / named sendmsg: **self-contained** dest (family+16B+port) + first-N payload (sendmsg: first iov); allowlist on dest IP; port **53** tagged as `dns` in userspace. No prior `connect()` required. Unnamed sendmsg (`msg_name` NULL) correlates like write.
- Openat: pathname (≤128 bytes); userspace matches `sensitive_paths` prefixes (empty list = ignore).
- Events pushed to **two ring buffers** (`BPF_MAP_TYPE_RINGBUF`, 256KB each): **routine** `events` for `connect`/`openat`, **critical** `critical_events` for `write`/`writev`/`sendto`/`sendmsg`/`lsm_deny` (EXFIL carriers + kernel-deny evidence). Reserve failures increment `drop_count` or `critical_drop_count` respectively, surfaced via `Sensor.DropCount()` / `Sensor.CriticalDropCount()`.
- Compiled from BPF C via `bpf2go` (cilium/ebpf), loaded by Go at runtime. CO-RE via BTF at `/sys/kernel/btf/vmlinux`.
- **Still deferred on this plane:** larger/dynamic capture / `tcp_sendmsg` before segmentation; connected sendto/sendmsg with NULL name stays “correlate like write.” **Out of scope:** DoH/DoT (network-layer DNS controls).

**Mostly detect-only at the kernel, plus an opt-in quarantine (v0.3 Phase 2, Slice 1).** The sensor **observes**; the eBPF tracepoints do not block anything. Containment happens in **userspace via kill-on-detect**, and it is **immediate**: `sendto`/`sendmsg`/`write`/`writev` `EXFIL` (payload overlap) and `openat` trips kill promptly, with no waiting window. A bare `connect()` never triggers a kill on its own, at any tier — hard containment is reserved for `EXFIL` (ROADMAP §1), and `connect()` carries no payload at the kernel level so it can never itself prove `EXFIL`. What a payload-less, non-allowlisted `connect()` *can* still do, on a proxy-tied session with every other trifecta leg lit, is trip soft `SUSPICIOUS` (evidence/alert, `detected_only`, no containment) — a real tripwire that a self-authored corpus never exercised and a CVE-derived reconstruction (`cve_2025_53967_figma_reverse_shell_connect_only_gap`, [`docs/cve_corpus.md`](cve_corpus.md)) found had been silently deleted as an unintended side effect of the ROADMAP §1 content-binding fix (`CheckContentBind` rejected an empty sink string before any comparison) — now fixed in `classifyTrip` (`internal/engine/engine.go`). Pure sensor-only DaemonSet mode never lights `untrusted_content_present`, so it can only ever reach `EXFIL`, never this `SUSPICIOUS` tier. An earlier "wait ~100 ms after a suspicious connect for a corroborating write, then kill regardless" design predates ROADMAP §1's "hard block only on `EXFIL`" doctrine and has been removed — it could never legitimately fire under that doctrine (SUSPICIOUS never maps to a containment action), and its removal changes no observable timing: `EXFIL` containment was always immediate, never routed through it. `ebpf.lsm_enforce` (default `false`) additionally attaches a `BPF_PROG_TYPE_LSM` hook on `security_socket_connect`: the instant the existing write/`sendto`/`sendmsg`/`writev` payload-overlap path confirms EXFIL for a PID/cgroup, the sensor writes that PID/cgroup into a BPF map, and **any further `connect()`** from it is denied in-kernel with `-EPERM` before the socket forms — no reliance on the kill racing the process. **This does not move detection earlier.** `connect()` carries no payload, so the hook cannot distinguish a merely non-allowlisted destination from actual exfiltration at connect-time — that determination still requires the payload-bearing syscall. **Honest consequence, unchanged for the first packet:** for Variant B the first packet (and possibly a short write) may have already left when kill fires — Interlock **severs the channel and kills the process before it can exfiltrate further**, rather than perfectly preventing the first byte; the resulting evidence is `contained_by_kill`, never `prevented`. Only *repeat* connection attempts from the already-flagged PID/cgroup — forked children sharing the cgroup, a kill that races, or a respawned process — get `prevented`. Requires `CONFIG_BPF_LSM=y` and `"bpf"` active in `/sys/kernel/security/lsm` (see [`deploy/k8s/PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md)); attach failure fails soft with a `[SECURITY]` warning and the sensor keeps running tracepoint-only. Variant A (proxy) is true prevention; Variant B (eBPF) is detection + containment, with this quarantine as defense-in-depth on top.

**Verdicts.** A bare `connect()` (no payload channel at all) → `SUSPICIOUS` at 0.60 on `AllLit` alone — there's no payload to content-bind against. `write`/`writev`/`sendto`/`sendmsg`/`dns` (all payload-bearing) → `SUSPICIOUS` at 0.60 only if the payload excerpt content-binds against a stored untrusted excerpt (`CheckContentBind`); the same events overlapping a tainted secret's exact bytes → `EXFIL` at 0.95 with `value_overlap.where_found: egress payload`. A payload-bearing event with neither content-bind nor overlap does not trip at all. Openat of a sensitive path → `SUSPICIOUS` only (open ≠ proven exfil). Writes without a recent suspicious connect/`sendto`/`sendmsg` are ignored (noise filter).

**Transport to userspace.** Dual ring buffers → Go decoders in `internal/ebpf/loader.go` (`ReadEvent` / `ReadCriticalEvent`) → sensor drain loops → `model.SyscallEvent` structs → engine's `IngestSyscall` method.

**Allowlist check.** The sensor checks each `connect()`/`sendto()`/named-`sendmsg()` destination against the config's `egress_allowlist`. Allowlisted IPs are silently dropped; non-allowlisted destinations light the `external_sink_invoked` leg and arm write-payload correlation for that PID.

**False-positive surface (stated plainly).** Connect-only Variant B no longer hard-kills on `SUSPICIOUS`: after ROADMAP §1, hard contain is EXFIL-only (payload overlap). Soft `SUSPICIOUS` trips two ways: a bare `connect()` on `AllLit` alone (no payload channel to content-bind against), or a payload-bearing `write`/`sendto`/`sendmsg`/`writev` via `AllLit` plus content-bind. Either way it uses `detected_only`, never containment.

**Prototype-first.** The `connect()` probe was validated with a `bpftrace` one-liner before writing compiled eBPF. This de-risked the hardest part of the week.

---

## 6. The correlation + policy engine

Consumes `InterceptedEvent` (Plane 1) and `SyscallEvent` (Plane 2); **owns `SessionState`**; emits `Decision`s (→ proxy) and `EvidenceRecord`s (→ sink).

**Correlation (syscall → session).** eBPF events carry a PID. The proxy maintains a `PIDRegistry` mapping `(pid, start_time)` → `{session_id, server_id}` for each per-session backend child. The sensor resolves `SessionID` before calling `IngestSyscall`. HTTP mode spawns an isolated server pool per MCP session; STDIO mode runs a single session.

**Time alignment.** All events carry a monotonic timestamp (`ts_mono_ns`) from a shared reference. Syscall events are joined to recent proxy events within a **recency window** so a `connect()` can be attributed to the sensitive read that preceded it.

---

## 7. State management — the trifecta state machine

One state machine **per session**.

**The three legs** (each is a `Leg`: lit-flag + the event that lit it + a human detail):

- `sensitive_source_touched` — set when a tool tagged `sensitive_source` returns data.
- `untrusted_content_present` — set when content enters context from an attacker-controllable origin. Lights on **non-`sensitive_source`** tool results when `untrusted_origins.tool_results` is true; stores a bounded excerpt for content-binding. Does **not** light on sensitive-source results or sensor `openat`.
- `external_sink_invoked` — set when a tool tagged `external_sink` is called, **or** an eBPF `connect()`/egress to a non-allowlisted destination fires.

**Tainted values.** When a `sensitive_source` returns data, the engine extracts candidate secrets and stores them as `TaintedValue`s — **hashed + masked, never raw** (§12). At registration, each value gets a fixed set of **canonical encodings** (literal, base64, hex, URL-encoding, reversal) held in memory only.

**Value overlap.** At sink time, `CheckOverlap` scans sink args for any tainted value in any canonical form, then (if needed) **same-call JSON string reassembly** (concat of string leaves). Forms: literal, base64, hex, URL-encoding, reversal, closed depth-2 nests (`base64_hex`, `hex_base64`, `base64_url`, `base64_reversed`), and compressor+base64 (`gzip_base64`, `brotli_base64`, `zstd_base64`, `lz4_base64` — ROADMAP §9). For long secrets (`len ≥ chunk_match_min_value_len`, default 64), **contiguous N-byte body chunks** (default N=32; PEM/PuTTY armor stripped) are also searched after a full-variant miss — `match_form=chunk_N`. On still-miss, a **bounded recursive decoder** (base64 then hex, default depth **5**, configurable `trifecta.max_decode_depth` clamp `[3,5]` — ROADMAP §15) unwraps JSON string leaves / payloads and rematches against single-layer forms — `match_form` records `decoded_*`. Default was raised from 3→5 after the benign corpus showed EXFIL FP **0.0%** at depths 3/4/5 with flat decode-miss latency (~380µs) — FP picks the default, not cost (`TestCorpus_DecodeDepthFPCurve`). After decode miss, **bounded container descent** (ROADMAP §20) sniffs ZIP/gzip/zlib/tar (including a single-layer base64 unwrap for binary-in-JSON packaging) and rematches interiors — `match_form=container_*`; aborts on hard caps soft-`SUSPICIOUS` with `container_inspect_limit` when AllLit, never EXFIL. **Cross-call / paginated abutting splits** are closed by the session **fragment buffer** (reassembly-first taint registration). Still out of scope: nests needing more than five decode steps (beyond clamp), custom ciphers, encrypted archives / zip-bombs / depth>2 nests, git pack wire outside ToolArgs/PayloadExcerpt, secrets entirely past the eBPF capture window — each has a skip / KnownGap. `RedactJSON` scrubs all variant strings from logs.

**Content-binding.** `CheckContentBind` requires a shared contiguous substring (default ≥ 16 bytes; `trifecta.content_bind_min_len`) between stored untrusted excerpts and the sink args/payload before `SUSPICIOUS` can fire — **when the sink event has a payload/args channel at all.** A bare `connect()` structurally never carries one (no `Payload` field on the raw eBPF event), so requiring content-bind there would make the connect-only tripwire permanently unreachable — an empty sink string always fails the length check regardless of taint or leg state. `classifyTrip` (`internal/engine/engine.go`) accounts for this explicitly: `AllLit` alone is sufficient for `SUSPICIOUS` on a payload-less event; content-bind still gates every event type that *does* carry a payload/args channel (write/sendto/sendmsg/tool-call args), exactly as originally intended. This distinction was missing for one release and silently deleted the connect-only tripwire entirely — found by [`docs/cve_corpus.md`](cve_corpus.md)'s `cve_2025_53967_figma_reverse_shell_connect_only_gap`, fixed, and pinned by `TestEngine_IngestSyscall_ConnectOnly_AllLit_Suspicious`. Soft `SUSPICIOUS` is evidence + `allowed_monitor` / `detected_only` — never hard block/kill.

Operators running fetch-heavy agents (web fetch → quote/summarize into a sink) will see soft-SUSPICIOUS noise whenever a long product blurb or doc excerpt is echoed outbound. That is correct system behavior for the current bind threshold, not a sticky-leg false block. To reduce operator noise: raise `trifecta.content_bind_min_len`, or avoid treating high-chatter servers as untrusted (leave `untrusted_origins.tool_results` false for those paths / omit them from untrusted lighting). Do **not** widen hard enforcement to cover this class.

**Extraction boundary.** `extractResultText` prefers MCP `content[].text`, then walks other JSON string leaves (bounded depth/bytes), skipping the already-handled `content` key so paginated halves stay abutting for the fragment buffer. Nested metadata secrets are tainted; the benign twin keeps an unrelated sink so EXFIL FP stays 0%.

**Tool tagging / intra-server writes.** By default (`server_defaults.inherit_sink_suspicion: false`), `EvaluateRequest` only gates tools tagged `external_sink` — Option C. An untagged write-shaped tool on a `sensitive_source` server (e.g. `internal_note` with an empty `tool_tags` override) is invisible — pinned as `malicious_gap_untagged_tool_on_sensitive_server`. **Opt-in (ROADMAP §14):** `inherit_sink_suspicion: true` treats any tool on a `sensitive_source` server as a sink unless listed in `sink_suspicion_allowlist`. Empty `tool_tags` overrides (`internal_note: []`) do **not** exempt — they still inherit (fail toward suspicion). **The sole exemption path is `sink_suspicion_allowlist`.** Restart-required. Pin: `malicious_proxy_a_untagged_inherit_sink`; TN: `benign_proxy_a_inherit_allowlisted_note`.

**Evaluation — verdict and action are separate dimensions.** The machine evaluates the moment a sink fires. **Verdict** describes what was concluded (the detection result); **Action** describes what was done about it (the enforcement response). This separation is load-bearing: Variant A can *prevent* (hold-before-forward), Variant B can only *contain* (kill after the first packet), and monitor mode *allows* — all three are valid actions for the same verdict.

| Condition at sink time | Verdict | Confidence |
|---|---|---|
| Tainted value appears in the sink's args/payload (`CheckOverlap`) | `EXFIL` | 0.95 |
| All three legs lit, sink event has no payload channel at all (bare `connect()`) | `SUSPICIOUS` | 0.60 |
| All three legs lit, sink event has a payload/args channel **and** untrusted↔sink content-bind, no value overlap | `SUSPICIOUS` | 0.60 |
| All three legs lit, sink event has a payload/args channel, no content-bind, but container inspect aborted on a hard cap (`container_inspect_limit`) | `SUSPICIOUS` | 0.60 |
| Otherwise | — (no trip) | — |

| Action | When | Effect |
|---|---|---|
| `prevented` | Variant A, block mode, **EXFIL only** | Call never forwarded; synthesized JSON-RPC error |
| `allowed_monitor` | Monitor mode (any verdict), **or** Variant A `SUSPICIOUS` in block mode | Call goes through; evidence logged |
| `contained_by_kill` | Variant B (eBPF), **EXFIL only** | Offending child killed; first packet may escape |
| `detected_only` | Variant B, `SUSPICIOUS` | Detected and logged; no kill |

**Reset / decay.** Legs are session-scoped. Configurable `trifecta.leg_ttl` (default 30m) and `trifecta.decay_after_calls` (default 32) dim sticky legs so a poisoned session does not forever treat every sink as suspicious. Tainted values are **not** cleared on leg decay — a late sink that still carries a secret can still reach EXFIL.

**Detection scope.** Mechanisms here; attack classes in/out of scope (including intentional **semantic / paraphrase** EXFIL gap) live in [`detection_boundary.md`](detection_boundary.md). Measured rates: [`fp_corpus.md`](fp_corpus.md).

**Concurrency.** Sessions are isolated; state is per-`session_id`. HTTP mode runs many concurrent sessions (§4.2); STDIO mode exercises one session. Race coverage: `go test -race` on `./internal/proxy/...` and `./internal/engine/...` in CI.

**Monitor / dry-run mode.** `enforcement: monitor` runs the full machine and emits evidence **without** blocking or killing — for tuning and for the "before" half of the demo.

---

## 8. Data model ("schemas")

The load-bearing contract. Getting this right **now** is what lets Weeks 2–3 plug in without a rewrite.

```go
// ---- Plane 1: proxy ----
type Direction string
const (
    AgentToServer Direction = "agent_to_server" // request
    ServerToAgent Direction = "server_to_agent" // response
)

type InterceptedEvent struct {
    SessionID   string          `json:"session_id"`
    Seq         uint64          `json:"seq"`            // monotonic per session
    TSWall      time.Time       `json:"ts_wall"`
    TSMono      int64           `json:"ts_mono_ns"`
    Direction   Direction       `json:"direction"`
    Method      string          `json:"jsonrpc_method"` // "tools/call", "tools/list", ...
    ToolName    string          `json:"tool_name,omitempty"`
    ToolArgs    json.RawMessage `json:"tool_args,omitempty"`  // requests
    Result      json.RawMessage `json:"result,omitempty"`     // responses
    ServerID    string          `json:"server_id"`
    ServerPID   int             `json:"server_pid"`     // key for eBPF correlation
    Tags        []string        `json:"tags,omitempty"` // ["sensitive_source"] | ["external_sink"]
    Decision    string          `json:"decision"`       // forwarded | blocked | pending
    BlockReason string          `json:"block_reason,omitempty"`
}

// ---- Plane 2: kernel ----

// PodContext identifies the Kubernetes pod that owns a monitored process.
// Present on sensor-mode (v0.3 Phase 1) evidence; omitted for proxy-local demos.
type PodContext struct {
    Namespace string `json:"namespace"`
    PodName   string `json:"pod_name"`
    PodUID    string `json:"pod_uid"`
    NodeName  string `json:"node_name,omitempty"`
}

type SyscallEvent struct {
    TSMono         int64       `json:"ts_mono_ns"`
    PID            int         `json:"pid"`
    TID            int         `json:"tid"`
    Comm           string      `json:"comm"`
    Syscall        string      `json:"syscall"`      // connect | sendto | sendmsg | write | writev | openat | dns
    DestIP         string      `json:"dest_ip,omitempty"`
    DestPort       int         `json:"dest_port,omitempty"`
    Allowlisted    bool        `json:"allowlisted,omitempty"`
    Path           string      `json:"path,omitempty"`            // openat
    PayloadExcerpt string      `json:"payload_excerpt,omitempty"` // redacted first-N-bytes
    SessionID      string      `json:"session_id,omitempty"`      // resolved via PID map, or "k8s:<podUID>" in sensor mode
    CgroupID       uint64      `json:"cgroup_id,omitempty"`       // sensor mode: cgroup → container → pod lookup key
    Pod            *PodContext `json:"pod_context,omitempty"`     // sensor mode only
    FileContents   string      `json:"-"`                         // sensor-mode openat taint seed via /proc/<pid>/root; never persisted
}

// ---- Engine state ----
type Leg struct {
    Lit        bool   `json:"lit"`
    TriggerSeq uint64 `json:"trigger_seq,omitempty"` // event that lit it
    Detail     string `json:"detail,omitempty"`
}
type TrifectaLegs struct {
    SensitiveSourceTouched  Leg `json:"sensitive_source_touched"`
    UntrustedContentPresent Leg `json:"untrusted_content_present"`
    ExternalSinkInvoked     Leg `json:"external_sink_invoked"`
}

type TaintedValue struct {
    Value        string `json:"-"`       // NEVER serialized raw
    Hash         string `json:"hash"`    // sha256(value)
    Preview      string `json:"preview"` // masked, e.g. "sk-...a9f2"
    Source       string `json:"source"`  // server/tool that produced it
    Seq          uint64 `json:"seq"`     // event that introduced it
    RegisteredAt int64  `json:"registered_at_ns"`
}

type Status string
const (
    Monitoring Status = "monitoring"
    Tripped    Status = "tripped"
    Terminated Status = "terminated"
)

type SessionState struct {
    SessionID    string         `json:"session_id"`
    Status       Status         `json:"status"`
    Legs         TrifectaLegs   `json:"legs"`
    Tainted      []TaintedValue `json:"tainted_values"`
    Confidence   float64        `json:"confidence"`
    Timeline     []uint64       `json:"timeline"` // ordered event seqs
    CreatedAt    int64          `json:"created_at_ns"`
    LastActivity int64          `json:"last_activity_ns"`
}

// ---- Evidence (feeds the viewer) ----
// Verdict = what was concluded (detection). Action = what was done (enforcement).
type Verdict string
const (
    VerdictExfil      Verdict = "EXFIL"      // high confidence: all legs + value overlap
    VerdictSuspicious Verdict = "SUSPICIOUS"  // lower confidence: all legs, no overlap
)
type Action string
const (
    ActionPrevented    Action = "prevented"        // Variant A block: call never forwarded
    ActionAllowed      Action = "allowed_monitor"   // monitor mode: call went through
    ActionContained    Action = "contained_by_kill" // Variant B: child killed (Week 3)
    ActionDetectedOnly Action = "detected_only"     // detected, no enforcement (kill too aggressive)
)
type Variant string
const (
    VariantA Variant = "A_chained_tool"   // caught by proxy
    VariantB Variant = "B_server_channel"  // caught by eBPF
)

type EvidenceRecord struct {
    SessionID    string         `json:"session_id"`
    TripTS       int64          `json:"trip_ts_ns"`
    Verdict      Verdict        `json:"verdict"`
    Action       Action         `json:"action"`                // what enforcement took
    Variant      Variant        `json:"variant"`
    Confidence   float64        `json:"confidence"`
    Legs         TrifectaLegs   `json:"legs"`
    SinkCall     any            `json:"sink_call"`             // the tool call or syscall that tripped
    ValueOverlap *OverlapHit    `json:"value_overlap,omitempty"`
    Timeline     []TimelineItem `json:"timeline"`              // full ordered story
    Pod          *PodContext    `json:"pod_context,omitempty"` // sensor mode (v0.3 Phase 1) only
    ChainSeq     uint64         `json:"chain_seq"`             // 0-indexed position in this evidence stream
    PrevHash     string         `json:"prev_hash"`             // hex sha256 of previous record (empty when ChainSeq==0)
    Hash         string         `json:"hash"`                  // hex sha256 over this record with Hash==""
}

type OverlapHit struct {
    TaintedHash string `json:"tainted_hash"`
    Preview     string `json:"preview"`
    WhereFound  string `json:"where_found"`         // "sink args" | "egress payload"
    MatchForm   string `json:"match_form,omitempty"` // literal | base64 | hex | url_encoded | reversed | ...
}
// TimelineSeq is an engine-assigned causal ordering — sort on this, not
// ts_mono_ns, because proxy and kernel clocks use different references.
type TimelineItem struct {
    TimelineSeq int    `json:"timeline_seq"`
    TSMono      int64  `json:"ts_mono_ns"`
    Kind        string `json:"kind"`   // intercepted | syscall
    Label       string `json:"label"`  // human line for the viewer
    Ref         uint64 `json:"ref,omitempty"`
}
```

---

## 9. Configuration model

A single `interlock.yaml` declares servers, tool tags, the egress allowlist, and enforcement mode.

```yaml
enforcement: block          # block | monitor
sandbox:
  netns: false              # opt-in CLONE_NEWNET for spawned children (proxy mode); needs CAP_SYS_ADMIN
egress_allowlist:           # anything NOT here is treated as an external sink at the kernel
  - 127.0.0.1
  - api.anthropic.com
servers:
  - id: tickets
    command: ./servers/tickets/tickets
    provides_tags: [sensitive_source]
  - id: messenger
    command: ./servers/messenger/messenger
    provides_tags: [external_sink]
tool_tags:                  # per-tool overrides (authoritative)
  read_ticket: [sensitive_source]
  send_message: [external_sink]
  http_post:   [external_sink]
untrusted_origins:
  tool_results: true        # v0.1 default: all results untrusted
  web_fetches:  true
trifecta:
  chunk_match_bytes: 32           # long-secret contiguous chunk size N (ROADMAP §8)
  chunk_match_min_value_len: 64   # only chunk tainted values ≥ this length
```

---

## 10. The evidence viewer ("frontend")

A **self-contained local HTML file** (`web/viewer.html`) that reads one `EvidenceRecord` JSON and renders the timeline: a horizontal time axis, the three legs lighting up in sequence, the tainted-value highlight where it surfaces in the sink, and a verdict badge (`EXFIL`/`SUSPICIOUS`) plus action label. The action label renders `ev.action` verbatim as text — `prevented`, `allowed_monitor`, `contained_by_kill`, and `detected_only` (now the most common action Variant B emits, since ROADMAP §1) all display the same way; the badge's color comes from `ev.verdict`, not `ev.action`, so no action string needs special-casing to render correctly. **Read-only, no framework, no server.** "State" on the frontend is just the single evidence file — this is the money-shot visual, not an app. Unknown JSON fields (including the hash-chain fields `chain_seq` / `prev_hash` / `hash`) are ignored.

**Tamper-evident chain.** JSONL and SQLite sinks seal each record into an append-only hash chain (`sha256` → lowercase hex, same encoding as `TaintedValue.Hash`). Verify with `make verify-evidence` / `go run ./cmd/verify-evidence -path evidence.jsonl` (exit 0 = intact; exit 1 names the first broken record). SIEM/webhook fan-out remains the off-node durability path; the chain is on-node integrity — both, not either.

---

## 11. Module boundaries / interfaces (Go)

Interfaces so components stay swappable and testable, and so the eBPF plane slots into the same engine the proxy already feeds.

```go
// Both proxy and eBPF sensor implement this.
type EventSource interface {
    Events() <-chan any   // yields InterceptedEvent or SyscallEvent
    Close() error
}

type Decision struct {
    Allow    bool
    Verdict  Verdict
    Action   Action
    Reason   string
    Evidence *EvidenceRecord // set when a trip fires
}

type PolicyEngine interface {
    EvaluateRequest(ev InterceptedEvent) Decision // pre-forward gate (Variant A)
    Ingest(ev any)                                // results + syscalls; may trip (Variant B)
}

type Enforcer interface {
    BlockCall(sessionID, reason string)  // synthesize JSON-RPC error to agent
    KillProcess(pid int, reason string)  // containment for Variant B
}

type EvidenceSink interface {
    Emit(rec EvidenceRecord) error       // JSONL append + trigger viewer
}

type SessionStore interface {
    Get(sessionID string) *SessionState
    Upsert(s *SessionState)
}
```

---

## 12. Security of Interlock itself

Full TCB threat model (blind sensor, poison bridge, fail-open, misattribution, evidence tamper, bypass channels): [`threat_model.md`](threat_model.md). Provenance: [`reproducible_builds.md`](reproducible_builds.md).

- **Runs privileged** (loading eBPF, managing child processes). Prefer the capabilities DaemonSet; residual `SYS_ADMIN` documented in the threat model / PRIVILEGE.md. Drop further capabilities post-attach remains iterative.
- **Never leaks the secrets it's protecting.** Tainted values are stored **hashed + masked** (`sk-...a9f2`), never raw. The value-overlap check compares raw values in memory only; evidence stores only the masked preview. All output files (`evidence.jsonl`, `evidence.json`, `events.jsonl`) are scrubbed by `RedactJSON` before writing — any known tainted value is replaced with its masked preview. Interlock writing the token in plaintext to a log would make the tool *itself* an exfil path — forbidden.
- **Fail-open vs. fail-closed.** Current default is **fail-open with loud `[SECURITY]` warnings** on stderr. Opt-in `fail_closed.enabled` (see `internal/failclosed`) trips on routine or critical ringbuf drop rate (hysteresis high/low watermarks), consecutive evidence sink write failures, or engine/sensor panics. Policy includes `min_trip_duration`, `recovery_window`, and exponential backoff on flap so engage/clear cannot oscillate. **Scope is always all currently watched PIDs/cgroups** — drop counters are severity-class globals, not per-pod (named limitation). Sensor mode requires `ebpf.lsm_enforce` and reuses `lsm_blocklist_*` via `Sensor.SetFailClosedActive` (fail-closed-owned entries are tracked separately from EXFIL quarantines). Proxy mode denies `tools/call` before `EvaluateRequest`. Metrics: `interlock_fail_closed_active`, `interlock_fail_closed_transitions_total`. The `[SECURITY]` prefix also fires for: (1) engine not configured, (2) engine panics mid-evaluation, (3) evidence sink write failure, (4) missing tool tags, (5) **unattributed eBPF syscalls**, (6) **event log backpressure drops**, (7) **eBPF routine/critical ring-buffer reserve failures**, (8) **`ebpf.lsm_enforce` requested but the LSM hook failed to attach** — the sensor keeps running tracepoint-only rather than refusing to start. Deployers should monitor for `[SECURITY]` in stderr output and ringbuf / fail-closed metrics.

**Evidence persistence (v0.2 Phase 4).** **Intentional default:** JSONL append (`evidence.jsonl`) + standalone `evidence.json` for the viewer — demo/dev-friendly, no extra deps. **Opt-in retention:** SQLite (`evidence.backend: sqlite`) with `max_records` — survives restart, prunes oldest records. Bounded growth is available when operators enable SQLite; leaving JSONL as default is a posture choice, not an unfinished gap. See [`performance.md`](performance.md) for engine microbenchmarks and end-to-end HTTP overhead (v0.2.1).

**Event log backpressure.** `logging.backpressure: block` (default) — synchronous writes, caller blocks. `drop` — bounded queue; overflow increments `DroppedEvents` and logs `[SECURITY]` at shutdown.

**eBPF ring-buffer drops.** When `bpf_ringbuf_reserve` fails in [`connect.c`](../internal/ebpf/bpf/connect.c), the kernel increments `drop_count` (routine: connect/openat) or `critical_drop_count` (critical: write/writev/sendto/sendmsg/lsm_deny). Userspace reads via `Sensor.DropCount()` / `Sensor.CriticalDropCount()`; Prometheus gauges `interlock_ebpf_ringbuf_drops_total` and `interlock_ebpf_critical_ringbuf_drops_total` are polled every 5s. Fail-closed watches both drop rates.

---

## 13. Known gaps and deferred work

Priority tiers below are the design SoT for what Interlock does *not* catch yet (or never will). Execution queue: [`ROADMAP.md`](ROADMAP.md) **Next build order**. A tool that claims no gaps is lying; a tool that names them is honest.

### Will cover — real detection value, tractable

| Gap | Trigger / why deferred |
|---|---|
| Secrets past capture window | **Improved (ROADMAP §8 + §16):** chunk overlap when excerpt holds ≥N body bytes; default `payload_capture_bytes` = **1024** (`PAYLOAD_MAX`) — the knob only reduces from that ceiling. Still open when the secret lies entirely past even 1024 (`malicious_gap_payload_truncated` — permanent KnownGap) |
| Tamper-evident evidence (WORM / external signing) | Hash chain shipped; WORM volume and external signing still deferred |
| CEF SIEM / cross-session evidence query | OCSF + single-record viewer shipped; enterprise ingest + dashboard open |
| **Content-bound `SUSPICIOUS` on payload-bearing sensor egress** | The connect-only tripwire is fixed (below), but a sensor-observed `write`/`sendto` whose payload is merely unrelated (not overlapping taint) still can't reach `SUSPICIOUS` on the sensor plane, because `register_untrusted` (below) deliberately forwards no excerpt text — `CheckContentBind` has nothing to compare against. Would need the bridge to also carry a bounded excerpt, raising its own size/sensitivity questions; not attempted. |
| **Finite egress reassembly window** | ROADMAP §19 appends payload-bearing `write`/`writev`/`sendto`/`sendmsg`/`dns` excerpts into bounded per-(pid,destination) buffers before `CheckOverlapPayload`, closing normal DNS and chunked-write splitting (including `cve_2025_65720_gpt_researcher_dns_fragmented_exfil`). Remaining honest boundary: fragments slower than `trifecta.egress_fragment_max_age` or split across different destinations are not joined (`malicious_gap_egress_slow_trickle`, `malicious_gap_egress_cross_destination_split`). Unbounded trickle / sockmap stream scan remain rejected (§11). |

### Will cover eventually — diminishing returns, real gaps

| Gap | Trigger / why deferred |
|---|---|
| Depth-6+ nests (beyond clamp) | Default `trifecta.max_decode_depth=5` (clamp `[3,5]`); Fetch five-layer nest closed at default (`cve_2025_65513_fetch_ssrf_cloud_metadata_depth5_nest`); deeper than 5 needs a clamp raise |
| ZIP/xlsx / archive containers; custom ciphers | Token compressors closed (§9); **whole-file** ZIP/xlsx relay closed via path-driven taint (§18); **extracted-cell** + sink/egress ZIP/gzip/zlib/tar interiors closed via bounded container descent (§20). Still open: custom ciphers; encrypted archives / zip-bombs / depth>2 nests (`malicious_gap_container_inspect_bomb`) |
| Write before suspicious connect | Correlation assumes connect→write (or self-contained sendto/sendmsg) |
| Tool-shadowing runtime re-registration | Startup detection shipped |
| Per-pod ringbuf drop maps | Dual severity-class counters shipped; per-cgroup attribution is a larger BPF change |
| Critical-ring write/sendto/writev/sendmsg flood | Named residual after segregation — harder than connect storm; accepted KnownGap |
| **Non-token-shaped taint extraction** | **Content-driven** (`secretPatterns` in `internal/engine/taint.go`): PEM/PuTTY private keys are closed ([`cve_corpus.md`](cve_corpus.md)'s `cve_2025_53109_filesystem_escaperoute_pem_exfil`). **Path-driven** (ROADMAP §18, `internal/engine/path_taint.go`): when a sensitive read's provenance path matches `sensitive_paths` or extension/name heuristics (`.p12`, `.pfx`, `.kdbx`, `.xlsx`, …), the entire read blob is tainted regardless of textual markers — closes **whole-file** binary-container relay ([`cve_2026_40576_excel_path_traversal_binary_container_exfil`](cve_corpus.md)). **Container interiors** (ROADMAP §20): registration-side `InspectContainer` + `ExtractTaintedValues` on ZIP/gzip/zlib/tar text parts closes credential-in-cell exfil (`malicious_proxy_a_extracted_from_xlsx_container`); overlap-path descent closes sink/egress-wrapped secrets. Still open on content alone: X.509 certs / DB connection strings. Overlap gates unchanged — EXFIL still requires sink/payload overlap (`benign_proxy_a_path_driven_xlsx_partial_relay` pins that short public-cell relay does not EXFIL). |
| **Protocol-aware egress parsers (Named §21)** | Git pkt-line / pack over smart HTTP or SSH, HTTP body + `Content-Encoding`, SMTP DATA — would close structured-protocol exfil family-at-a-time, but each dissector grows untrusted-input TCB. **Demand-gated:** build only if a deployment shows that MCP family; otherwise NamedGap. Pin: `cve_2025_68143_mcp_git_push_wire_protocol_gap`. **§20 vs §21:** flat zlib/ZIP on ToolArgs/PayloadExcerpt is closed; framing outside those surfaces is not. |

### Probably never / out of scope — wrong trade-off

| Gap | Why |
|---|---|
| **DoH/DoT** | Encrypted DNS needs TLS interception; mitigate with **network-layer DNS controls** |
| Exotic/custom multi-layer compressors | Attacker has infinite encodings; Variant B raw-byte overlap is encoding-agnostic when capture works |
| First EXFIL-carrying packet kernel-prevented | Architectural: `connect()` has no payload — always `contained_by_kill` for the first packet |
| **Blind side-channel / query-pattern EXFIL (ROADMAP §22)** | Secret inferred from booleans/timing, never transmitted — byte-overlap cannot prove what was never on the wire. Sequence-anomaly detection is a different FP-heavy product; rejected for EXFIL. Pin: `cve_2025_66335_doris_blind_sql_injection_exfil_gap`. If ever researched: SUSPICIOUS-dark only (like §12). |
| Sockmap / SOCKS5 stream scan / unbounded slow-trickle | Considered and rejected — [`detection_boundary.md`](detection_boundary.md) / ROADMAP §11 |

**Also deferred (not tier tables):** HTTP upstream backends, TLS termination / MITM, GET `/mcp` listen streams.

**Recently closed on this plane (do not re-open as “open gaps”):**
- **`writev` / `sendmsg` / IPv6 dest layout** — critical-ring probes + family+16B addr on connect/sendto/named-sendmsg (§5)
- **LSM Slice 1** — opt-in `ebpf.lsm_enforce` repeat-connect quarantine; first packet remains `contained_by_kill`
- **`fail_closed`** + **dual ringbufs** — opt-in breaker; connect floods cannot starve EXFIL/`lsm_deny` evidence
- **Sensor↔proxy taint bridge** — Unix NDJSON + **SO_PEERCRED** allowlists (`allowed_uids` / `allowed_gids`, optional `socket_gid`); residual: node root / shared-GID / allowed peer forging `pod_uid` ([`threat_model.md`](threat_model.md) T2)
- **Evidence hash chain** — `chain_seq`/`prev_hash`/`hash` + `make verify-evidence`
- **Bounded container descent (ROADMAP §20)** — ZIP/gzip/zlib/tar interiors under hard caps; extracted-cell + sink/egress-wrapped secrets EXFIL; bomb/encrypted/depth NamedGaps; git pack wire remains Named §21 (demand-gated)
- **Boundary writeups (ROADMAP §11 / §21 / §22)** — sockmap/SOCKS5/unbounded trickle rejected; protocol dissectors Named/demand-gated; blind side-channel rejected for EXFIL
- **Sensor-only mode's `SUSPICIOUS` tier, opt-in** — `IngestSyscallSensor` still never lights `untrusted_content_present` on its own; there is genuinely no MCP untrusted-content plane inside a privileged, proxy-less DaemonSet pod, and that has not changed. What shipped: `Engine.RegisterRemoteUntrusted` + the taint bridge's new `register_untrusted` message let an **unprivileged proxy sidecar that already observes MCP traffic** (the same deployment shape `taint_bridge` was built for) forward "untrusted content observed" alongside taint, so a sensor session sharing that bridge connection CAN light the leg and reach the connect-only tripwire. Requires `taint_bridge.enabled` and a proxy on the other end; a true no-proxy-anywhere sensor-only deployment still cannot reach `SUSPICIOUS` — that combination has no untrusted-content observer at all, by construction, not by omission. See the "Sensor-only DaemonSet" paragraph below, `TestEngine_RegisterRemoteUntrusted_ClosesSensorSuspiciousGap`, `TestBridge_ClientToEngine_UntrustedClosesSensorSuspiciousGap`.

### Sensor-only DaemonSet (v0.3 Phase 1)

`--mode=sensor --ebpf` runs without the MCP proxy. A node-local watcher (`internal/k8s`) lists pods with label `interlock.io/monitor=true` on `NODE_NAME`, maps host PIDs via `/proc/<pid>/cgroup` → container ID → pod, and feeds `Sensor.AddPIDs`. Evidence includes `pod_context`.

`IngestSyscallSensor`: sensitive `openat` seeds `sensitive_source_touched` + taint (via `/proc/<pid>/root` file read; no kill); egress `connect`/`write`/`writev`/`sendto`/`sendmsg`/`dns` contain. Payload overlap → **EXFIL 0.95** with redacted `payload_excerpt`.

**Corrected (previously wrong on this exact point — see [`docs/cve_corpus.md`](cve_corpus.md)):** without a value-overlap-proving payload, egress in sensor-only mode reaches **no verdict at all**, not `SUSPICIOUS` — **unless** an unprivileged proxy sidecar is also forwarding an untrusted-content signal over the taint bridge (see next paragraph). `IngestSyscallSensor` on its own never lights `untrusted_content_present` — a privileged, proxy-less DaemonSet pod genuinely has no MCP untrusted-content plane to observe — so `AllLit()` (`sensitive_source_touched` + `untrusted_content_present` + `external_sink_invoked`) is permanently false in that specific deployment shape, and `SUSPICIOUS` requires it (§7). This was never implemented, not a regression: the code has explicitly not lit `untrusted_content_present` since sensor-only mode's introduction (v0.3.0), and this doc line describing an "untrusted leg detail" string was aspirational from the same commit, not a description of a seed that was later removed. Confirmed empirically, pinned by `TestEngine_IngestSyscallSensor_NeverReachesSuspicious_KnownGap` (`internal/engine/engine_test.go`).

**Shipped remediation, opt-in:** `Engine.RegisterRemoteUntrusted` + the taint bridge's `register_untrusted` message let a proxy that *does* observe MCP traffic (the same sidecar deployment `taint_bridge` was already built for — see the EKS note below) forward "untrusted content observed" alongside taint, closing this specific gap for that shape: `TestEngine_RegisterRemoteUntrusted_ClosesSensorSuspiciousGap`, `TestBridge_ClientToEngine_UntrustedClosesSensorSuspiciousGap`. It deliberately forwards no excerpt text (a boolean signal, not a content channel), so it restores the payload-less connect-only tripwire specifically — content-bound `SUSPICIOUS` on a payload-*bearing* sensor-observed write/sendto still isn't reachable (see the gap tier above). A genuinely proxy-less sensor-only deployment (no sidecar anywhere) still cannot reach `SUSPICIOUS` at all — there is no untrusted-content observer to forward from, by construction. Operators on that path get `EXFIL`-tier detection (hard, proven) but no soft tripwire; do not read the absence of a `SUSPICIOUS` trip there as "nothing anomalous happened," only as "nothing was proven."

Privilege story: [`deploy/k8s/PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md); demo: [`deploy/k8s/README.md`](../deploy/k8s/README.md).

**Managed-cluster note (EKS 2026-07-12):** capabilities DaemonSet loads probes and observes cross-pod `connect`/`write`; `/proc/<pid>/root` seed was permission-denied on AL2023/containerd. Privileged DaemonSet completed seed → EXFIL → kill. **Production EXFIL without privileged root reads:** enable `taint_bridge` (proxy → Unix socket → `RegisterRemoteTaint`; SO_PEERCRED allowlist required) — the same bridge connection now also carries `RegisterRemoteUntrusted`, so this deployment shape gets both tiers, not just `EXFIL`.

---

## 14. Operability layer (v0.3 Phase 3)

Four packages that decide whether a team keeps Interlock running in production. All are optional — disabled unless configured — and all fan out from the same point: after an `EvidenceRecord` is persisted by `AsyncEvidenceSink`.

```go
// engine.MultiEmitObserver — fan-out to every configured observer.
type EvidenceEmitObserver interface {
    OnEvidenceEmitted(rec model.EvidenceRecord)
}
type MultiEmitObserver []EvidenceEmitObserver // metrics, webhook, siem — nil entries skipped
```

### 14.1 Metrics and health (`internal/observability`)

Starts an HTTP server on `observability.listen` (disabled when empty) serving:

| Endpoint | Behavior |
|---|---|
| `metrics_path` (default `/metrics`) | Standard Prometheus exposition via `promhttp.Handler()` |
| `health_path` (default `/healthz`) | `200 ok` when ready, `503` otherwise |

Metrics: `interlock_up` (gauge), `interlock_detections_total{verdict,variant,action}` (counter, incremented on every evidence emit), `interlock_evidence_dropped_total` / `interlock_events_dropped_total` (async backpressure drops), `interlock_ebpf_ringbuf_drops_total` / `interlock_ebpf_critical_ringbuf_drops_total` / `interlock_watched_pids` / `interlock_watched_cgroups` (polled from the live sensor every 5s via `observability.PollRuntime`), `interlock_fail_closed_active` / `interlock_fail_closed_transitions_total{direction,reason}` (opt-in fail-closed breaker), `interlock_alert_deliveries_total{kind,result}` (webhook/SIEM delivery outcomes, `kind` ∈ `webhook|siem`, `result` ∈ `ok|error|skipped`).

The DaemonSet wires `/healthz` as the liveness/readiness probe and exposes `/metrics` via a headless Service for Prometheus scrape (`deploy/k8s/service-metrics.yaml`).

### 14.2 Trip webhooks (`internal/alerting`)

`alerting.webhook` fires an async HTTP POST whenever an evidence record's verdict meets `min_verdict` (default `SUSPICIOUS`). Three formats:

| Format | Body |
|---|---|
| `generic` (default) | Compact JSON: session/verdict/action/variant/confidence/legs/sink_call/value_overlap |
| `slack` | Slack Incoming Webhook `{"text": ...}` |
| `pagerduty` | Events API v2 `trigger` with `routing_key`, `dedup_key`, `payload.summary/severity/source/custom_details` |

Delivery is bounded-concurrency and non-blocking relative to the evidence hot path; a full backlog drops the alert (counted, never blocks a trip). `WebhookNotifier.Close()` drains in-flight deliveries.

### 14.3 SIEM export (`internal/siem`)

`siem` maps an `EvidenceRecord` to an **OCSF 1.3 Detection Finding** (`class_uid=2004`, `category_uid=2`, `activity_id=1`) and writes it to a JSONL file (`siem.path`) and/or POSTs it to `siem.url`. Severity: `EXFIL` → `5/Critical`, `SUSPICIOUS` → `3/Medium`. Interlock-specific fields (session_id, verdict, action, variant, pod_context, sink_call, value_overlap) live under OCSF's `unmapped`. CEF export is not implemented. Same `min_verdict` filtering and async delivery semantics as webhooks.

### 14.4 SIGHUP hot-reload (`internal/reload`)

`cmd/interlock/main.go` installs a `SIGHUP` handler in both proxy and sensor modes. On signal, it re-parses the config file and calls `reload.Runtime.ApplyReloadable`, which live-swaps:

- `egress_allowlist`, `sensitive_paths` — via `Sensor.UpdateAllowlist` / `UpdateSensitivePaths` (sensor/eBPF mode only; guarded by a `sync.RWMutex` so the syscall handlers never race the reload)
- `alerting.webhook`, `siem` — new notifier/exporter constructed, wired into a fresh `MultiEmitObserver`, then the *old* instance's `Close()` is called after the swap so in-flight deliveries finish
- The async evidence sink's emit observer set

`reload.DiffNonReloadable` flags fields that changed but are **not** applied live — `enforcement`, `transport`, `observability.listen`/`metrics_path`/`health_path`, `evidence` backend/path, and a change in `servers` count — logged as "restart required" warnings. Invalid YAML or a failed validation on reload is logged and the **previous** config is kept; Interlock never runs on a half-applied config.

### 14.5 systemd units (`deploy/systemd/`)

For bare-metal/VM hosts (Kubernetes remains the primary deploy path). `interlock-sensor.service` and `interlock-proxy.service` wrap the same binary and flags as the DaemonSet/local demo; `ExecReload=/bin/kill -HUP $MAINPID` maps `systemctl reload` to the hot-reload path above.
