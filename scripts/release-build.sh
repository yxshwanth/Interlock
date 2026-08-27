#!/usr/bin/env bash
# Build reproducible linux/amd64 release artifacts into dist/.
# Usage: ./scripts/release-build.sh [VERSION]
# VERSION defaults to: git describe --tags --always --dirty
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-${VERSION:-}}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
fi

DIST="${DIST:-$ROOT/dist}"
mkdir -p "$DIST"
rm -f "$DIST"/interlock_linux_amd64 "$DIST"/k8s-exfil-demo_linux_amd64 "$DIST"/SHA256SUMS "$DIST"/SHA256SUMS.bpf

LDFLAGS="-s -w -X main.version=${VERSION}"
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

echo "release-build: version=${VERSION} go=$(go version) trimpath=on"
go build -trimpath -ldflags="$LDFLAGS" -o "$DIST/interlock_linux_amd64" ./cmd/interlock
go build -trimpath -ldflags="-s -w" -o "$DIST/k8s-exfil-demo_linux_amd64" ./cmd/k8s-exfil-demo

(
  cd "$DIST"
  sha256sum interlock_linux_amd64 k8s-exfil-demo_linux_amd64 > SHA256SUMS
)

# Record committed BPF object hash (source of truth for consumers; not rebuilt here).
if [[ -f internal/ebpf/connect_x86_bpfel.o ]]; then
  sha256sum internal/ebpf/connect_x86_bpfel.o internal/ebpf/connect_x86_bpfel.go > "$DIST/SHA256SUMS.bpf"
fi

echo "artifacts:"
ls -la "$DIST"
cat "$DIST/SHA256SUMS"
if [[ -f "$DIST/SHA256SUMS.bpf" ]]; then
  echo "bpf embeds:"
  cat "$DIST/SHA256SUMS.bpf"
fi
