# Reproducible builds and release verification

Interlock ships **signed git tags** (since `v0.2.0`) and **checksummed release
binaries**. Consumers build the Go binary with `CGO_ENABLED=0` and embed
**committed** eBPF objects — no clang required at install time.

Threats against the running TCB: [`threat_model.md`](threat_model.md).
Tag verification: [`SECURITY.md`](../SECURITY.md).

---

## What is reproducible

| Artifact | How built | Reproducibility notes |
|---|---|---|
| `interlock_linux_amd64` | `make release` / `scripts/release-build.sh` | `CGO_ENABLED=0`, `-trimpath`, pinned Go module versions (`go.sum`), `-ldflags` version stamp |
| `k8s-exfil-demo_linux_amd64` | same script | Demo workload; same flags except no version `ldflags` |
| `SHA256SUMS` | `sha256sum` of the two binaries | Published as a GitHub Release asset |
| `connect_x86_bpfel.o` (+ `.go` embed) | Committed in-tree; regen via `make bpf-generate` | Bit-identical across hosts only when using the **pinned BPF builder** image; host clang/header drift is expected |

Container images (`make image`) use the same `-trimpath` / `CGO_ENABLED=0` /
version ldflags as release binaries. Pinning `golang:1.25` / `debian:bookworm-slim`
**by digest** is recommended for operator hardening but not required by the Makefile.

---

## Build a release locally

```bash
# optional: VERSION=v0.3.0
make release
ls dist/
# interlock_linux_amd64  k8s-exfil-demo_linux_amd64  SHA256SUMS  SHA256SUMS.bpf
./dist/interlock_linux_amd64 --version
sha256sum -c dist/SHA256SUMS
```

Flags (locked):

```text
CGO_ENABLED=0 GOOS=linux GOARCH=amd64
go build -trimpath -ldflags="-s -w -X main.version=${VERSION}"
```

`VERSION` defaults to `git describe --tags --always --dirty`.

---

## Verify a GitHub Release

1. **Verify the signed tag** (SSH allowed signers):

```bash
git fetch --tags
git -c gpg.ssh.allowedSignersFile=allowed_signers tag -v vX.Y.Z
```

2. **Download** `interlock_linux_amd64` and `SHA256SUMS` from the GitHub Release
   for that tag.

3. **Check hashes**:

```bash
sha256sum -c SHA256SUMS
./interlock_linux_amd64 --version   # should print vX.Y.Z
```

Cosign / Sigstore container signing is **not** part of this release path (follow-up).

---

## eBPF objects

### Source of truth for consumers

[`internal/ebpf/connect_x86_bpfel.o`](../internal/ebpf/connect_x86_bpfel.o) is
`//go:embed`’d. A normal `go build` / `make release` **does not** invoke clang.
Release uploads include `SHA256SUMS.bpf` so reviewers can confirm the embed was
not swapped without a corresponding source change.

### Regenerating (maintainers)

Host clang versions and kernel header paths differ. Use the pinned builder:

```bash
make bpf-generate
# equivalent:
#   docker build -f deploy/build/Dockerfile.bpf -t interlock-bpf-builder .
#   docker run --rm -v "$PWD:/src" -w /src interlock-bpf-builder go generate ./internal/ebpf/...
```

Builder: [`deploy/build/Dockerfile.bpf`](../deploy/build/Dockerfile.bpf) —
`golang:1.25-bookworm` + Debian `clang` / `llvm` / `libbpf-dev`.

Generate directive: [`internal/ebpf/generate.go`](../internal/ebpf/generate.go)
(`-Ibpf` only; libbpf headers from the image’s `/usr/include`).

After regen, commit updated `.o` / `.go` if the BPF C changed, and re-run
`make release` so `SHA256SUMS.bpf` matches.

### Why BPF is harder than Go

`bpf2go` output depends on clang version, libbpf headers, and `vmlinux.h`.
Full bit-reproducibility across arbitrary developer laptops is not promised;
the **pinned builder image** is the supported regen path. Operators who never
edit BPF C never need clang.

---

## CI

| Workflow | Role |
|---|---|
| [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | test / vet / build on `main` |
| [`.github/workflows/release.yml`](../.github/workflows/release.yml) | on tag `v*`: `make release`, upload `dist/*` to the GitHub Release |

Maintainers: create an annotated **signed** tag (`git tag -s vX.Y.Z`), push the
tag, and let the release workflow attach checksummed binaries.
