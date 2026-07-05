# Contributing to Interlock

Thanks for your interest. Interlock is at v0.1 — early, deliberately scoped, and open to contributions that match the project's honesty standard.

## Prerequisites

- **Go 1.21+**
- **Linux with BTF** for eBPF (`ls /sys/kernel/btf/vmlinux` should succeed). eBPF paths do not build or run on macOS/Windows.
- **clang** and **llvm** only if modifying BPF C code in `internal/ebpf/bpf/` (see [Generated eBPF artifacts](#generated-ebpf-artifacts))

## Build and run

```bash
git clone https://github.com/yxshwanth/Interlock.git
cd Interlock
make test
sudo make demo-quiet-ebpf GO=$(which go)   # full three-pass demo (root required for Variant B)
```

Proxy-only demo (no root):

```bash
make demo-quiet
```

## Project layout

```
cmd/interlock/       Main binary — proxy + engine + optional eBPF sensor
cmd/demo/            Scripted demo client (three-pass)
cmd/ebpf-test/       Throwaway eBPF verification tool — not a supported product surface
internal/            Private packages (Go enforces: not a public API)
servers/             Toy MCP servers for the demo (tickets, messenger, exfil)
web/                 Evidence viewer (self-contained HTML)
docs/                Architecture, roadmap, design notes
```

## Tests

```bash
make test              # go test ./... && go vet ./...
go test -race ./...    # concurrency-sensitive paths should pass clean
```

**73 tests** across 8 packages is the current baseline — new features should include tests.

CI runs `go build`, `go vet`, and `go test` on every push to `main`. eBPF probe loading requires root and a BTF-enabled kernel; it is tested locally, not in CI.

## Known-gap discipline

Detection features must ship with tests that name what they **do not** catch. Example: `TestCheckOverlap_EncodedExfil_KnownGap` documents that raw-substring overlap misses base64-encoded exfil. This is Interlock's signature standard — uphold it in every PR that adds detection logic.

## Runtime output — never commit

These files are gitignored and must **never** be committed:

- `evidence.json`, `evidence*.jsonl` — forensic receipts with tool-result bodies
- `events*.jsonl` — full intercepted protocol logs

They may contain fixture PII or secrets shaped outside the redaction patterns. Treat them as sensitive artifacts.

## eBPF changes

Code under `internal/ebpf/` is kernel-version-sensitive. Changes need testing on a real BTF-enabled kernel, not just a passing compile. Prototype new probes with bpftrace one-liners before writing compiled eBPF.

## Generated eBPF artifacts

The repo commits bpf2go-generated files so users can `go build` without installing clang/llvm:

- `internal/ebpf/connect_x86_bpfel.go`
- `internal/ebpf/connect_x86_bpfel.o`
- `internal/ebpf/bpf/vmlinux.h`

Regenerate after changing `internal/ebpf/bpf/connect.c`:

```bash
go generate ./internal/ebpf/...
```

Do not hand-edit generated files.

## Code style

- `go vet` must pass with zero warnings.
- No raw secrets in logs or evidence output. Use `RedactJSON` for fields that may carry tainted values.
- Comments explain *why*, not *what*.
- Security-relevant failures use the `[SECURITY]` prefix on stderr.

## Commit and PR conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(engine): add verdict/action split for eBPF containment
fix(demo): resolve pass-3 deadlock via demo-side timeout
test(overlap): add known-gap test for encoded exfil
docs(readme): document sudo requirement and probe transparency
```

One logical change per PR. Update [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]` for user-visible changes.

PR checklist:

- [ ] Tests added or updated
- [ ] `go vet` clean
- [ ] `go test -race ./...` clean (for concurrency-touching changes)
- [ ] CHANGELOG updated (if user-visible)
- [ ] Known-gap tests for new detection features

## What to work on

See [docs/ROADMAP.md](docs/ROADMAP.md) for v0.2 and v0.3 plans. Open an issue before starting significant work so we can coordinate.

High-value areas:

- HTTP/SSE MCP transport (v0.2 Phase 1)
- Multi-session PID attribution (v0.2 Phase 2)
- Encoded-exfil taint tracking (v0.2 Phase 3)
- Additional eBPF probes (`sendto` payload excerpt)

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open public issues for security bugs.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
