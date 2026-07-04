.PHONY: build test demo demo-ebpf clean

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

clean-evidence:
	rm -f evidence.jsonl evidence.json events.jsonl
	rm -f events-monitor.jsonl events-block.jsonl events-ebpf.jsonl
	rm -f evidence-monitor.jsonl evidence-block.jsonl evidence-ebpf.jsonl

clean: clean-evidence
	rm -f $(BINARIES)
