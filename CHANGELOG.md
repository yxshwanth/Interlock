# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Async evidence emit: `AsyncEvidenceSink` decorator; `evidence.backpressure: block | drop`, `evidence.queue_size`; `DroppedEvidence` runtime stats
- eBPF `sys_enter_write` first-256-byte payload capture; userspace correlation to recent non-allowlisted `connect`
- Variant B `EXFIL` (0.95) when egress excerpt overlaps taint (`where_found: egress payload`); connect-only remains `SUSPICIOUS` (0.60)
- Deferred kill window (~100 ms) after connect so write can land before SIGKILL
- Local exfil fixture mode (`INTERLOCK_EXFIL_MODE=local`) + `interlock-ebpf-local.yaml` for payload-backed demo
- Known-gap skips: truncated excerpt, write-before-connect, UDP `sendto`
- `TestHTTP_ConcurrentLoad_ReadTicket` — multi-session absolute latency p50/p95/p99 (`CONCURRENT_SESSIONS`, CI smoke)
- eBPF `DropCount` tests: unloaded API (CI), idle after load + ringbuf saturation flood (root-gated)

### Changed

- README / architecture / ROADMAP: Variant B dual claim (tripwire or payload-backed EXFIL)
- Taint registration path: `CanonicalEncodings` → `[]TaintedVariant` directly; cheaper `HashValue`; `extractResultText` via `strings.Builder`
- [`docs/performance.md`](docs/performance.md) — async evidence, ingest opts, concurrent load snapshot, ringbuf test honesty

## [0.2.1] - 2026-07-05

### Added

- End-to-end HTTP overhead benchmarks (A + C): `TestHTTP_OverheadReport_*` (p50/p95/p99/p999 histogram), `BenchmarkHTTP_EngineDelta_*` (engine on vs passthrough), `make bench-http`
- `mcphttp.Client.CallDuration` for client-perceived latency measurement
- `TestHTTP_ConcurrentLoad_KnownGap` — concurrent multi-session HTTP load deferred (replaces former `TestBenchmark_FullHTTPLoad_KnownGap`; single gap, one skip test)
- CI HTTP overhead smoke (`OVERHEAD_SAMPLES=100`)

### Changed

- [`docs/performance.md`](docs/performance.md) — engine delta headline (~0.5 ms sensitive reads typical, ~0.1 ms sink checks); explains taint-ingestion vs overlap delta inversion; secret-count scaling caveat

### Removed

- `TestBenchmark_FullHTTPLoad_KnownGap` — duplicate of `TestHTTP_ConcurrentLoad_KnownGap` (one HTTP load gap, one skip test)

## [0.2.0] - 2026-07-05

### Added

- Performance benchmarks (v0.2 Phase 4): engine hot-path suite, `make bench`, [`docs/performance.md`](docs/performance.md)
- Opt-in SQLite evidence store with `max_records` retention (`evidence.backend: sqlite`; JSONL default)
- Concurrent SQLite retention test (`TestSQLiteEvidenceSink_ConcurrentRetention`; covered by race CI)
- Event log backpressure policy (`logging.backpressure: block | drop`) and runtime stats at shutdown
- eBPF ring-buffer drop counter (`drop_count` BPF map, `Sensor.DropCount()`)
- Bounded encoding overlap (v0.2 Phase 3): canonical transforms at taint registration (base64, hex, URL-encoding, reversal)
- `OverlapHit.match_form` in evidence records how overlap was detected
- Known-gap skip tests: split-across-calls, compressed, double-encoded exfil
- Multi-session concurrency (v0.2 Phase 2): per-session backend server pools, `SessionManager`, `PIDRegistry` (PID + start time)
- Sessions config: `sessions.max_concurrent`, `sessions.idle_timeout`
- eBPF dynamic PID watch/unwatch on session spawn and cleanup
- Unattributed eBPF syscalls audit-logged to stderr and `events.jsonl` (`SecurityAuditEvent`, kind `unattributed_syscall`)
- CI race job: `go test -race` on `./internal/proxy/...` and `./internal/engine/...`
- Concurrent overlap tests: `TestSessionManager_ConcurrentCreate`, `TestPIDRegistry_ConcurrentRegisterLookup`; dual-session HTTP test releases both sessions together
- Streamable HTTP transport ([MCP 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports/streamable-http)): `POST /mcp`, `Mcp-Session-Id`, JSON and SSE responses
- Transport config: `transport.mode` (`stdio` | `http`), `listen`, `endpoint`, `protocol_version`, `prefer_sse_responses`
- Inspect-then-forward for HTTP: full JSON-RPC body before dispatch; SSE only after complete backend response; blocked calls return JSON
- HTTP demo path: `make demo-http`, `make demo-http-ebpf`, `make demo-quiet-http`, `make demo-quiet-http-ebpf`
- Example configs: `interlock-http.yaml`, `interlock-http-monitor.yaml`
- Auth header redaction helpers for HTTP request metadata
- v0.2 milestone summary: [`docs/v0.2_summary.md`](docs/v0.2_summary.md)

### Changed

- `IngestSyscall` requires explicit `SessionID` — removed `FirstSessionID` fallback
- HTTP `initialize` spawns dedicated backend children per MCP session (no shared server pool)
- Extracted transport-agnostic dispatch from `internal/proxy/proxy.go` into `internal/proxy/dispatch.go`
- STDIO mode unchanged and still the default
- README two-plane framing: Variant A = dataflow analysis; Variant B = connect() tripwire (not payload detection)

### Fixed

- `SQLiteEvidenceSink.Count()` now holds the same mutex as `Emit` for safe concurrent use

### Known limitations

- Performance numbers are **engine-component benchmarks** — not end-to-end per-request proxy latency (`TestBenchmark_FullHTTPLoad_KnownGap`)
- Value-overlap catches literal + canonical encodings only — not split/compressed/nested (see overlap known-gap tests)
- HTTP multi-session: each `initialize` spawns a full backend pool — bounded by `sessions.max_concurrent` and `sessions.idle_timeout`, but a session-flood can exhaust host process slots (see README)
- Unattributed eBPF events during PID teardown are audit-logged, not tripped — inspect `events.jsonl` for `unattributed_syscall` records
- Variant B is a **connect() tripwire** — legs-only `SUSPICIOUS` at 0.60; no eBPF payload overlap yet (post-v0.2)

## [0.1.0] - 2026-07-04

First release — a working proof that runtime trifecta detection works across two observation planes.

### Added

- Two-plane architecture: userspace MCP proxy (Plane 1) + eBPF `connect()` sensor (Plane 2)
- Trifecta state machine per session: `sensitive_source_touched`, `untrusted_content_present`, `external_sink_invoked`
- Verdict/action split: `EXFIL`/`SUSPICIOUS` vs `prevented`/`contained_by_kill`/`allowed_monitor`
- **Variant A** — chained-tool exfil blocked at the proxy before forward (`prevented`)
- **Variant B** — server side-channel detected via eBPF, contained by process kill (`contained_by_kill`)
- Value-overlap confidence heuristic (0.95 with overlap, 0.60 without)
- Fused evidence timeline with engine-assigned `timeline_seq` across proxy and kernel clocks
- Self-contained HTML evidence viewer ([`web/viewer.html`](web/viewer.html))
- Three-pass demo: monitor (breach), block (prevented), eBPF (detected and contained)
- Quiet demo mode for screen recordings (`make demo-quiet`, `make demo-quiet-ebpf`)
- 73 tests across engine, proxy, config, and supporting packages
- CI: `go build`, `go vet`, `go test` on every push to `main`

### Known limitations

- Value-overlap is raw-substring matching — misses encoded/obfuscated exfil (`TestCheckOverlap_EncodedExfil_KnownGap`)
- Variant B is legs-only `SUSPICIOUS` at 0.60 confidence — unauthorized connection during a sensitive session, not proven exfiltration
- eBPF containment is kill-after-connect, not first-packet prevention
- STDIO MCP transport only; single session; IPv4 `connect()` tracing only
- Redaction is pattern-matched — treat runtime event/evidence logs as sensitive artifacts
- eBPF integration tested locally (root + BTF kernel), not in CI

[Unreleased]: https://github.com/yxshwanth/Interlock/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/yxshwanth/Interlock/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/yxshwanth/Interlock/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yxshwanth/Interlock/releases/tag/v0.1.0
