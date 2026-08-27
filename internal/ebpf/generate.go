package ebpf

// Regenerate with: make bpf-generate
// (pinned clang/libbpf via deploy/build/Dockerfile.bpf — see docs/reproducible_builds.md)
//
// Host shortcut when clang + libbpf-dev are installed:
//
//	go generate ./internal/ebpf/...
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 connect bpf/connect.c -- -Ibpf
