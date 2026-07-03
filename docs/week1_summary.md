# Week 1 Summary — Transparent Multi-Server MCP Proxy

**Status:** Complete
**Commits:** `173fce5` (scaffold) → `1889b9b` (full implementation)
**Duration:** Week 1 of the four-week build sequence

---

## Goal

> The demo agent talks to both MCP servers *through* Interlock, every frame intercepted and logged. Zero detection, zero blocking, zero eBPF.

**Achieved.** The proxy is fully transparent — servers behave identically to being run directly, while every JSON-RPC frame is intercepted, parsed, and logged with session metadata.

---

## What Was Built

### Core Proxy (`internal/proxy/`)

| File | Purpose |
|---|---|
| `proxy.go` | Multi-server proxy with protocol-aware routing. Handles `initialize`, `tools/list`, and `tools/call` dispatch by tool name. Tracks pending request IDs for response attribution. |
| `framer.go` | `FrameReader` / `FrameWriter` implementing MCP stdio transport: newline-delimited JSON-RPC with partial-read buffering, blank line skipping, and `\r\n` tolerance. |
| `server.go` | `ServerProcess` — child process lifecycle management with piped stdio, process group isolation, and graceful SIGTERM → SIGKILL shutdown. |
| `logger.go` | `EventLogger` — dual-output structured logging: human-readable one-line summaries to stderr + full `InterceptedEvent` objects as JSONL to file. |

### Data Model (`internal/model/`)

| Type | Role |
|---|---|
| `InterceptedEvent` | Emitted for every JSON-RPC frame. Carries `session_id`, monotonic sequence number, wall/mono timestamps, direction, parsed method/tool name/args/result, server ID, server PID, decision. |
| `JSONRPCMessage` | Generic JSON-RPC 2.0 envelope for parsing frames (request/response/notification discrimination). |
| `ToolCallParams` | Parsed `tools/call` parameters: tool name + arguments. |

### Config (`internal/config/`)

YAML-based configuration loader with validation. Defines servers (id, command, args, tags), tool tags, egress allowlist, enforcement mode, and untrusted origin settings.

### MCP Server Harness (`internal/mcpserver/`)

Reusable stdio MCP server skeleton. Handles the full JSON-RPC dispatch loop: `initialize` handshake, `notifications/initialized`, `tools/list`, `tools/call` routing, `ping`, and error responses. Toy servers register their tools and call `Run()`.

### Toy MCP Servers (`servers/`)

| Server | Tools | Role |
|---|---|---|
| `tickets` | `read_ticket` | Sensitive source. Returns customer support tickets containing auth tokens (`sk-live-...`) and a hidden poisoned instruction for the Week 2 exfiltration demo. |
| `messenger` | `send_message`, `http_post` | External sink. Simulates sending messages and HTTP POST requests — the exfiltration channel in the attack scenario. |

### Demo Client (`cmd/demo/`)

Scripted Go MCP client that exercises the full pipeline end-to-end. Builds all binaries, launches Interlock (which launches both servers), then scripts the protocol sequence: `initialize` → `tools/list` → `tools/call` for each tool. Displays results and summarizes the JSONL event log.

---

## Architecture

```
Demo Client (stdin/stdout)
    │
    ▼
Interlock Proxy
    ├── handles initialize, tools/list internally
    ├── routes tools/call by tool name
    ├── logs every frame as InterceptedEvent
    │
    ├──→ tickets server (child process, stdio pipes)
    │       └── read_ticket → sensitive data + poison
    │
    └──→ messenger server (child process, stdio pipes)
            ├── send_message → external sink
            └── http_post → external sink
```

**Multi-server routing:** The proxy initializes all servers at startup, queries each for its tool list, and builds a `tool name → server` routing table. Agent `tools/call` requests are dispatched to the correct server; responses are forwarded back with full event attribution.

---

## Test Results

- **17 unit tests** — all pass
  - 8 config tests (valid parse, defaults, invalid enforcement, missing fields, duplicates, file not found)
  - 9 framer tests (single/multi message, blank lines, CRLF, partial reads, EOF, concurrent writes)
- **`go vet`** — zero warnings
- **End-to-end demo** — 11 events logged across both servers, all tool calls return correct results, clean shutdown

---

## Demo Output (abridged)

```
[interlock] session a556f855b2c7ca9b started
[interlock] starting server "tickets": ./servers/tickets/tickets
[interlock] server "tickets" started (pid=151089)
[interlock]   registered tool "read_ticket" from server "tickets"
[interlock] starting server "messenger": ./servers/messenger/messenger
[interlock] server "messenger" started (pid=151095)
[interlock]   registered tool "send_message" from server "messenger"
[interlock]   registered tool "http_post" from server "messenger"
[interlock] all servers initialized, 3 tools available

[interlock] #1  agent→server initialize
[interlock] #2  server→agent result
[interlock] #3  agent→server notifications/initialized
[interlock] #4  agent→server tools/list
[interlock] #5  server→agent result (3 tools)
[interlock] #6  agent→server tools/call read_ticket   → tickets (pid=151089)
[interlock] #7  server→agent result                   ← tickets
[interlock] #8  agent→server tools/call send_message   → messenger (pid=151095)
[interlock] #9  server→agent result                   ← messenger
[interlock] #10 agent→server tools/call http_post      → messenger (pid=151095)
[interlock] #11 server→agent result                   ← messenger
```

The ticket result contains auth token `sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef` and the poisoned instruction — both visible in the intercepted event stream. In Week 2, the trifecta engine will detect this pattern and block the exfiltration.

---

## What's Next — Week 2

The proxy now sees everything. Week 2 adds the **trifecta engine and enforcement** (Variant A):

- Trifecta state machine (sensitive source touched / untrusted content present / external sink invoked)
- Tool tagging wired from config
- Tainted-value extraction with hashed+masked storage
- Value-overlap check (tainted value in sink args)
- Hold-before-forward enforcement with synthesized JSON-RPC block errors
- Evidence record emission and HTML timeline viewer
- Poisoned-ticket demo: firewall off → breach, firewall on → blocked

---

## Files

```
cmd/interlock/main.go           — entry point (flag parsing, signal handling)
cmd/demo/main.go                — scripted end-to-end demo client
internal/config/config.go       — config structs + Load() + validation
internal/config/config_test.go  — 8 config tests
internal/model/model.go         — InterceptedEvent, JSONRPCMessage, ToolCallParams
internal/proxy/proxy.go         — multi-server proxy with protocol-aware routing
internal/proxy/framer.go        — MCP stdio frame reader/writer
internal/proxy/framer_test.go   — 9 framer tests
internal/proxy/server.go        — child process lifecycle management
internal/proxy/logger.go        — JSONL + stderr dual event logger
internal/mcpserver/mcpserver.go — reusable MCP server harness
servers/tickets/main.go         — tickets MCP server (sensitive source)
servers/messenger/main.go       — messenger MCP server (external sink)
interlock.yaml                  — proxy configuration
```
