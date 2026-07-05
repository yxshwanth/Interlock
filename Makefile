.PHONY: build test demo demo-ebpf demo-quiet demo-quiet-ebpf demo-http demo-http-ebpf demo-quiet-http demo-quiet-http-ebpf demo-http-concurrent clean bench race

GO ?= $(shell which go 2>/dev/null || echo /usr/local/go/bin/go)
BINARIES = interlock servers/tickets/tickets servers/messenger/messenger servers/exfil/exfil

build:
	$(GO) build -o interlock ./cmd/interlock
	$(GO) build -o servers/tickets/tickets ./servers/tickets
	$(GO) build -o servers/messenger/messenger ./servers/messenger
	$(GO) build -o servers/exfil/exfil ./servers/exfil

test:
	$(GO) test ./...
	$(GO) vet ./...

race:
	CGO_ENABLED=1 $(GO) test -race -short ./internal/proxy/... ./internal/engine/...

bench:
	$(GO) test -bench=. -benchmem -benchtime=50ms ./internal/engine/...

demo: clean-evidence build
	$(GO) run ./cmd/demo

demo-ebpf: clean-evidence build
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo ""; \
		echo "  eBPF demo requires root. Run:"; \
		echo "    sudo make demo-ebpf GO=$(GO)"; \
		echo ""; \
		exit 1; \
	fi
	$(GO) run ./cmd/demo

demo-quiet: clean-evidence build
	INTERLOCK_DEMO_QUIET=1 $(GO) run ./cmd/demo

demo-quiet-ebpf: clean-evidence build
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo ""; \
		echo "  eBPF demo (quiet) requires root. Run:"; \
		echo "    sudo make demo-quiet-ebpf GO=$(GO)"; \
		echo ""; \
		exit 1; \
	fi
	INTERLOCK_DEMO_QUIET=1 $(GO) run ./cmd/demo

demo-http: clean-evidence build
	INTERLOCK_DEMO_HTTP=1 $(GO) run ./cmd/demo

demo-http-ebpf: clean-evidence build
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo ""; \
		echo "  eBPF HTTP demo requires root. Run:"; \
		echo "    sudo make demo-http-ebpf GO=$(GO)"; \
		echo ""; \
		exit 1; \
	fi
	INTERLOCK_DEMO_HTTP=1 $(GO) run ./cmd/demo

demo-quiet-http: clean-evidence build
	INTERLOCK_DEMO_QUIET=1 INTERLOCK_DEMO_HTTP=1 $(GO) run ./cmd/demo

demo-http-concurrent: clean-evidence build
	INTERLOCK_DEMO_HTTP=1 $(GO) run ./cmd/demo --concurrent

demo-quiet-http-ebpf: clean-evidence build
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo ""; \
		echo "  eBPF HTTP demo (quiet) requires root. Run:"; \
		echo "    sudo make demo-quiet-http-ebpf GO=$(GO)"; \
		echo ""; \
		exit 1; \
	fi
	INTERLOCK_DEMO_QUIET=1 INTERLOCK_DEMO_HTTP=1 $(GO) run ./cmd/demo

clean-evidence:
	rm -f evidence.jsonl evidence.json events.jsonl
	rm -f events-monitor.jsonl events-block.jsonl events-ebpf.jsonl
	rm -f evidence-monitor.jsonl evidence-block.jsonl evidence-ebpf.jsonl

clean: clean-evidence
	rm -f $(BINARIES)
