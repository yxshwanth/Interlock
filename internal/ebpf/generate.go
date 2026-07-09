package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 connect bpf/connect.c -- -Ibpf -I/usr/src/linux-headers-6.17.0-35-generic/tools/bpf/resolve_btfids/libbpf/include
