# ADR 0001 — Rust for the eBPF layer (Stage 1 of the Rust migration)

Status: Proposed · Context: [`STARTUP_ROADMAP.md`](../STARTUP_ROADMAP.md) Phase 2

## Decision

Port `internal/ebpf` (probes in `bpf/connect.c` + loader/sensor in Go) to Rust using [`aya`](https://aya-rs.dev): kernel programs in `aya-ebpf`, userspace loader in `aya`. The Go proxy and engine stay unchanged in Stage 1.

## Why this layer first

[`security_review.md`](../security_review.md) findings 1–6 and 21–22 are concentrated here, and most are bug classes Rust removes or narrows:

| Finding | Class | Rust effect |
|---|---|---|
| 6 unchecked `bpf_probe_read_user`, stale ring-buffer bytes | unchecked fallible call, uninitialised memory | `Result` must be handled; ring-buffer entries zero-initialised by construction |
| 3 `iov[0]` only | verifier-shaped shortcut | not solved by Rust; needs a bounded loop, same as C |
| 1, 2, 4 | logic bugs (`send` NULL sockaddr, `fd < 3`, 5s TTL) | not solved by Rust; fix in C first, port the fixed behaviour |
| 5 TOCTOU | kernel semantics | not solved by Rust; needs `sys_exit` capture + `lsm/socket_connect` dest |

Honest read: Rust fixes the memory-safety subset (6) and makes the userspace loader safer. The logic bugs must be fixed regardless, so fix them in C **before** porting and use the fixed behaviour as the parity spec.

## Boundary contract (Go ⇄ Rust)

Keep the existing seam: the sensor emits `model.SyscallEvent`. Stage 1 ships the Rust sensor as a separate process (`interlock-sensor-rs`) that writes newline-delimited `SyscallEvent` JSON to a Unix socket; Go's `IngestSyscall` / `IngestSyscallSensor` consume it via a small adapter. Reverse channel (Go → Rust): allowlist/PID/cgroup updates and `Quarantine` over the same socket. No FFI, no cgo.

## Acceptance criteria

1. `go test ./internal/corpus/...` and `make fp-corpus` / `make cve-corpus` unchanged (corpus drives the engine, so it validates the adapter, not the probes).
2. Linux-only parity suite: replay a recorded syscall trace through both sensors, diff emitted `SyscallEvent`s.
3. Existing root-gated tests (`TestEBPF_RingbufSaturation_UnderLoad`, `TestLSM_DenySurvivesConnectFlood`, `TestDropPostAttach_RootGated`) ported.
4. Verifier accepts on kernel 6.1 (EKS AL2023) and current Ubuntu LTS.

## Risks

- `aya` LSM and BTF/CO-RE coverage must be checked against the pinned kernels before committing; spike first.
- Two-language build/release (signed releases, `reproducible_builds.md`) grows.
- Cannot be developed or tested on macOS; needs the `deploy/ec2` Linux VM.

## Sequence

1. Fix findings 1–6 in C, land with tests on Linux.
2. Spike: `aya` connect + write tracepoints + one ring buffer, 1 week timebox. Go/no-go on verifier and LSM support.
3. Port probes, then loader/sensor, then adapter; run parity suite.
4. Only then consider Stage 2 (engine hot path).
