# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

### Changed

### Fixed

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

[Unreleased]: https://github.com/yxshwanth/Interlock/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yxshwanth/Interlock/releases/tag/v0.1.0
