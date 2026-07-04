# Contributing to Interlock

Thanks for your interest. Interlock is a young project and contributions are welcome.

## Prerequisites

- **Go 1.21+**
- **Linux with BTF** (for eBPF — `ls /sys/kernel/btf/vmlinux` should succeed)
- **clang** and **llvm** (only if modifying BPF C code in `internal/ebpf/`)

## Getting started

```bash
git clone https://github.com/yxshwanth/Interlock.git
cd Interlock
make test       # build, vet, and run all tests
make demo       # run the demo (passes 1+2, no root needed)
```

For the full demo including eBPF Variant B:

```bash
sudo make demo GO=$(which go)
```

## Project structure

```
cmd/interlock/       Main binary — proxy + engine + optional eBPF sensor
cmd/demo/            Scripted demo client (three-pass)
internal/proxy/      MCP proxy: frame I/O, routing, enforcement gate
internal/engine/     Trifecta state machine, taint extraction, evidence
internal/ebpf/       eBPF connect() probe, loader, sensor
internal/model/      Shared data types
internal/config/     YAML config loader
servers/             Toy MCP servers (tickets, messenger, exfil)
web/                 Evidence viewer (self-contained HTML)
docs/                Architecture, task list, weekly summaries
```

## Running tests

```bash
make test
```

This runs `go test ./...` and `go vet ./...`. All tests should pass without root. The eBPF probe tests require root and a kernel with BTF.

## Code style

- `go vet` must pass with zero warnings.
- No raw secrets in log output or evidence files. Use `RedactJSON` for any field that might carry tainted values.
- Comments explain *why*, not *what*. Don't narrate obvious code.
- Log lines that indicate a security-relevant failure use the `[SECURITY]` prefix.

## What to work on

See `docs/task_list.md` for the current roadmap. The **Backlog** section lists planned v0.2 and v0.3 work. If you want to pick something up, open an issue first so we can coordinate.

High-value areas for contribution:
- Additional eBPF probes (`sendto` payload excerpt, `openat`, DNS)
- HTTP/SSE transport support
- Improved taint extraction patterns (JWTs, private URLs, PII)
- Cross-plane clock normalization for real inter-event latency
