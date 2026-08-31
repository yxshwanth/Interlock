# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **CEF SIEM export (ROADMAP §5)** — `siem.format: cef` ArcSight CEF 0 text lines beside existing OCSF; OCSF path unchanged
- **Cross-session evidence query (ROADMAP §5)** — SQLite `Query` by `session_id` / `verdict` / `pod_name`; `make query-evidence`; viewer multi-record list mode
- **Shannon entropy dark measurement (ROADMAP §12)** — corpus-only would-fire rates in `docs/fp_corpus.md`; not wired to verdicts/alerts
- **Post-attach capability drop (ROADMAP §13)** — clear `CAP_SYS_ADMIN` after eBPF attach; keep `KILL`/`BPF`/`PERFMON`; netns keeps SYS_ADMIN
- HTTP MCP optional `transport.bearer_token` and `transport.rate_limit_rps`; example configs moved to `examples/configs/`
- `.editorconfig` for non-Go file formatting

### Changed

- **Audit remediation (2026-08-31)** — capabilities-first `daemonset.yaml` default; `daemonset-dev.yaml` for privileged kind demos; strict Origin hostname validation; `ParseToolCallParams` errors surfaced on proxy path; shared `model.MeetsMinVerdict` / `RuntimeStats`; Dockerfile defaults to non-root user (sensor sets `runAsUser: 0`)

### Removed

- Dead code: `ContainerIDFromPID`, `PodAttribution.Register`, `SessionStore.Delete`, `PIDRegistry.AllPIDs`, `PayloadMax`, `Loader.PayloadCaptureBytes`, unused `Proxy.mu`
- Orphan `deploy/k8s/configmap-sensor.yaml` (live sensor ConfigMap is `interlock-sensor-config` in `deploy/k8s/rbac.yaml`)

## [0.4.0] - 2026-07-30

**v0.4 — Detection depth + definitive reference.** LSM Slice 1, fail-closed, dual ringbufs, and evidence hash chain from the post-v0.3 tree, plus ROADMAP §§7–20 detection/hardening work and [`docs/INTERLOCK.md`](docs/INTERLOCK.md) as the code-backed architecture SoT.

### Added

- **Definitive technical reference** — [`docs/INTERLOCK.md`](docs/INTERLOCK.md): two-plane architecture, taint/verdict/action model, TCB scenarios, gap ledger, considered-and-rejected; discrepancy index vs stale docs; measured-state snapshot pointing at `make fp-corpus` / `make cve-corpus`
- **CVE-derived corpus** — [`docs/cve_corpus.md`](docs/cve_corpus.md) / `internal/corpus/scenarios_cve.go`: 7 families, 15 genuine reconstructions (12/15 EXFIL); found connect-only tripwire deletion and PEM taint gap
- **LSM/KRSI kernel quarantine** (Phase 2 Slice 1) — opt-in `ebpf.lsm_enforce`: repeat `connect()` after EXFIL → in-kernel `-EPERM` (`prevented`); first EXFIL packet remains `contained_by_kill`
- **Fail-closed mode** — opt-in `fail_closed.enabled` (`internal/failclosed`): ringbuf drop-rate hysteresis, sink failures, panic → block monitored egress; flap damping; global-scope named limitation
- **Ring-buffer segregation** — dual 256 KiB BPF rings (routine connect/openat vs critical write/writev/sendto/sendmsg/lsm_deny); fail-closed watches both drop rates
- **Tamper-evident evidence hash chain** — `chain_seq` / `prev_hash` / `hash`; `make verify-evidence`
- **Variant B `writev` / `sendmsg` / IPv6** — critical-ring probes; family + 16-byte dest on connect/sendto/named-sendmsg
- **Taint bridge SO_PEERCRED** — `allowed_uids` / `allowed_gids`; optional `register_untrusted` for sensor soft SUSPICIOUS
- **Standard compressors as canonical forms (ROADMAP §9)** — `brotli_base64` / `zstd_base64` / `lz4_base64` (+ `gzip_base64`); custom cipher remains KnownGap
- **Token vaulting (ROADMAP §10)** — opt-in `vault.enabled`; `ilk.vault.*` dummies; authorize-list detokenize-then-scan
- **Zero-route netns (ROADMAP §7)** — opt-in `sandbox.netns` → `CLONE_NEWNET` for spawned children (proxy mode; default off)
- **Spawn pinning (ROADMAP §17)** — resolve/pin `servers[].command` at config load; reject mismatched binaries; optional `spawn_allowlist`
- **Long-secret chunk matching (ROADMAP §8)** — contiguous body chunks for values ≥64 B; closes truncated-capture PEM EXFIL when a chunk is in-window
- **Inherit sink suspicion (ROADMAP §14)** — opt-in `server_defaults.inherit_sink_suspicion` + `sink_suspicion_allowlist`
- **Configurable decode depth (ROADMAP §15)** — `trifecta.max_decode_depth` default **5**, clamp `[3,5]`; FP curve 0% EXFIL at 3/4/5
- **Payload capture default 1024 (ROADMAP §16)** — equals compiled `PAYLOAD_MAX`; runtime reduce-only clamp `[64,1024]`
- **Path-driven taint (ROADMAP §18)** — sensitive path heuristics / config prefixes → whole-blob taint (xlsx whole-file relay)
- **Egress flow reassembly (ROADMAP §19)** — bounded per-(pid,dest) buffers; closes normal DNS/write fragmentation; slow-trickle / cross-dest remain KnownGaps
- **Bounded container descent (ROADMAP §20)** — ZIP/gzip/zlib/tar under streaming caps; abort → soft SUSPICIOUS only; bomb/encrypted/depth NamedGaps
- **Boundary writeups (ROADMAP §11 / §21 / §22)** — sockmap/SOCKS5/unbounded trickle rejected; protocol dissectors Named/demand-gated; blind side-channel rejected for EXFIL

### Changed

- Connect-only soft SUSPICIOUS restored via `classifyTrip` `hasPayloadChannel` (CVE corpus finding); deferred-kill subsystem removed (unreachable after §1)
- PEM/PuTTY private-key patterns in `secretPatterns`; any-trip FP published at **18.9% (7/37)** with EXFIL-tier FP **0%**
- Docs: three-doc model (architecture gaps / ROADMAP queue / project overview pitch); SUMMARY.md removed; INTERLOCK.md is the definitive reference
- README / PRIVILEGE / threat model / detection_boundary / performance / demo-k8s.sh aligned with immediate EXFIL kill and current capture defaults

## [0.3.0] - 2026-07-12

**v0.3 — Adoptable Product** (Phase 1 DaemonSet, Phase 3 operability, Phase 4 Trust). Phase 2 LSM/KRSI remains demand-gated.

### Added

- **Phase 4 Trust:** TCB threat model ([`docs/threat_model.md`](docs/threat_model.md)) — ringbuf blind, bridge poison, fail-open DoS, PID misattribution, evidence tamper, unmonitored bypass channels; least-privilege residual caps documented
- **Reproducible releases:** `make release` / `scripts/release-build.sh` (`CGO_ENABLED=0`, `-trimpath`, version ldflags); `SHA256SUMS` (+ BPF embed hashes); `.github/workflows/release.yml` on `v*` tags; pinned BPF builder [`deploy/build/Dockerfile.bpf`](deploy/build/Dockerfile.bpf); [`docs/reproducible_builds.md`](docs/reproducible_builds.md); `--version` on `interlock`
- **Monitor mode pilot brief:** [`docs/pilot.md`](docs/pilot.md)
- **Bounded recursive decoder (depth-3)** — on `CheckOverlap` / `CheckOverlapPayload` miss, unwrap base64 then hex up to depth 3; `match_form` `decoded_*`; closes triple-nest KnownGap; benches gate ~100 µs miss-path at 1K and ~0.3 ms decode-miss
- **Sensor↔proxy taint bridge** — Unix NDJSON socket (`internal/bridge`, `taint_bridge` config); proxy forwards newly extracted taints keyed by `POD_UID`; sensor `RegisterRemoteTaint` into `k8s:<podUID>`; hostPath `/var/run/interlock` on DaemonSets + [`proxy-taint-bridge-example.yaml`](deploy/k8s/proxy-taint-bridge-example.yaml)
- **Sensor-only Kubernetes DaemonSet** (`--mode=sensor`): runs the eBPF sensor without the MCP proxy; `internal/k8s` node-local pod watcher (`interlock.io/monitor=true`), cgroup→container ID→pod attribution via `/proc/<pid>/cgroup`, `PodAttribution` registry
- `IngestSyscallSensor`: sensitive `openat` seeds taint via `/proc/<pid>/root` file read (no kill); egress `connect`/`write`/`sendto`/DNS contain; payload overlap → `EXFIL` 0.95 with redacted `payload_excerpt`
- Evidence `pod_context` (`namespace`, `pod_name`, `pod_uid`, `node_name`); sensor session ID is `k8s:<podUID>`
- `cmd/k8s-exfil-demo` — demo workload that reads a mounted secret then exfiltrates it over TCP, for the kind e2e path
- Multi-stage `Dockerfile` + `make image`; `deploy/k8s/` — `daemonset.yaml`, `daemonset-capabilities.yaml`, `rbac.yaml` (includes `interlock-sensor-config` ConfigMap), `service-metrics.yaml`, `demo/exfil-pod.yaml`; [`deploy/k8s/PRIVILEGE.md`](deploy/k8s/PRIVILEGE.md) privilege surface doc
- `deploy/k8s/eks/` — EKS cluster/IAM/push/validate/delete helpers; `push-image-kaniko.sh` for builds without local Docker
- `make demo-k8s` / `scripts/demo-k8s.sh` — kind load, apply, labeled exfil pod, asserts EXFIL evidence with redacted excerpt
- **Prometheus metrics + health** (`internal/observability`): `/metrics` (`promhttp`) and `/healthz` on `observability.listen`; detection and drop counters; DaemonSet liveness/readiness probes + headless `interlock-sensor-metrics` Service
- **Trip webhooks** (`internal/alerting`): async HTTP delivery on evidence emit — `generic` | `slack` | `pagerduty`
- **OCSF SIEM export** (`internal/siem`): Detection Finding (`class_uid=2004`) to JSONL and/or HTTP; CEF deferred
- `engine.MultiEmitObserver` — fan-out of evidence emits to metrics, webhook, and SIEM observers
- **SIGHUP hot-reload** (`internal/reload`): live-swaps `egress_allowlist`, `sensitive_paths`, `alerting.webhook`, `siem`
- **systemd units** (`deploy/systemd/`): sensor + proxy units with `ExecReload` → `SIGHUP`
- **FP / detection corpus** (`internal/corpus`, `docs/fp_corpus.md`, `docs/detection_boundary.md`) — EXFIL-tier detection 100% on non-gap malicious; EXFIL-tier FP 0.0%
- Config: `observability.*`, `alerting.webhook.*`, `siem.*`, `taint_bridge.*`

### Changed

- `cmd/interlock/main.go`: sensor and proxy modes wire reload runtime, optional taint bridge, `--version`
- `internal/ebpf/sensor.go`: allowlist / sensitive_paths behind `RWMutex` for hot-reload
- Docs: ROADMAP Phase 1/3/4 Trust marked shipped; Phase 2 LSM/KRSI demand-gated
- Docs: EKS validation (2026-07-12) recorded in [`deploy/k8s/PRIVILEGE.md`](deploy/k8s/PRIVILEGE.md)

## [0.2.2] - 2026-07-10

### Added

- Async evidence emit: `AsyncEvidenceSink` decorator; `evidence.backpressure: block | drop`, `evidence.queue_size`; `DroppedEvidence` runtime stats
- eBPF `sys_enter_write` first-256-byte payload capture; userspace correlation to recent non-allowlisted `connect`
- Variant B `EXFIL` (0.95) when egress excerpt overlaps taint (`where_found: egress payload`); connect-only remains `SUSPICIOUS` (0.60)
- Deferred kill window (~100 ms) after connect so write can land before SIGKILL
- Local exfil fixture mode (`INTERLOCK_EXFIL_MODE=local`) + `interlock-ebpf-local.yaml` for payload-backed demo
- Known-gap skips: truncated excerpt, write-before-connect, IPv6 sendto, sendmsg, DoH/DoT, cross-call split, depth-3 nests, non-gzip compressors
- `TestHTTP_ConcurrentLoad_ReadTicket` — multi-session absolute latency p50/p95/p99 (`CONCURRENT_SESSIONS`, CI smoke)
- eBPF `DropCount` tests: unloaded API (CI), idle after load + ringbuf saturation flood (root-gated)
- eBPF `sys_enter_sendto` (IPv4, self-contained dest+payload); DNS tagged when dest port is 53
- eBPF `sys_enter_openat` + config `sensitive_paths` → `SUSPICIOUS` (never EXFIL)
- Same-call JSON string reassembly; depth-2 nested encodings; `gzip_base64` canonical form
- Startup tool-shadowing detection: first-owner-wins routing; duplicate omitted from `tools/list`; `SecurityAuditEvent` kind `tool_shadowing`

### Changed

- README / architecture / ROADMAP: Variant B dual claim (tripwire or payload-backed EXFIL); sendto/openat/DNS; bounded overlap expansion
- Taint registration path: `CanonicalEncodings` → `[]TaintedVariant` directly; cheaper `HashValue`; `extractResultText` via `strings.Builder`
- [`docs/performance.md`](docs/performance.md) — async evidence, ingest opts, concurrent load snapshot, ringbuf test honesty; encoding form-count growth note
- Docs: consolidated historical week/v0.2 summaries (later superseded by [`docs/INTERLOCK.md`](docs/INTERLOCK.md))

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
- Current product summary docs (later superseded by [`docs/INTERLOCK.md`](docs/INTERLOCK.md))

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

[Unreleased]: https://github.com/yxshwanth/Interlock/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/yxshwanth/Interlock/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/yxshwanth/Interlock/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/yxshwanth/Interlock/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/yxshwanth/Interlock/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/yxshwanth/Interlock/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yxshwanth/Interlock/releases/tag/v0.1.0
