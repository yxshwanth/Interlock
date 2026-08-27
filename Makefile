.PHONY: build test demo demo-ebpf demo-quiet demo-quiet-ebpf demo-http demo-http-ebpf demo-quiet-http demo-quiet-http-ebpf demo-http-concurrent demo-k8s image clean bench bench-http race readme-gif fp-corpus cve-corpus verify-evidence query-evidence release bpf-generate lsm-vm-up lsm-vm-ssh lsm-vm-sync lsm-vm-down

GO ?= $(shell which go 2>/dev/null || echo /usr/local/go/bin/go)
BINARIES = interlock servers/tickets/tickets servers/messenger/messenger servers/exfil/exfil
IMAGE ?= interlock:dev
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS_RELEASE = -s -w -X main.version=$(VERSION)

build:
	$(GO) build -o interlock ./cmd/interlock
	$(GO) build -o servers/tickets/tickets ./servers/tickets
	$(GO) build -o servers/messenger/messenger ./servers/messenger
	$(GO) build -o servers/exfil/exfil ./servers/exfil

# Reproducible linux/amd64 artifacts + SHA256SUMS under dist/ (see docs/reproducible_builds.md).
release:
	chmod +x scripts/release-build.sh
	VERSION=$(VERSION) ./scripts/release-build.sh

# Regenerate bpf2go artifacts inside the pinned builder (requires Docker).
bpf-generate:
	docker build -f deploy/build/Dockerfile.bpf -t interlock-bpf-builder .
	docker run --rm -v "$(CURDIR):/src" -w /src interlock-bpf-builder \
		go generate ./internal/ebpf/...

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

test:
	$(GO) test ./...
	$(GO) vet ./...

race:
	CGO_ENABLED=1 $(GO) test -race -short ./internal/proxy/... ./internal/engine/... ./internal/k8s/... ./internal/config/...

bench:
	$(GO) test -bench=. -benchmem -benchtime=50ms ./internal/engine/...

bench-http: build
	$(GO) test -run='TestHTTP_OverheadReport|TestHTTP_ConcurrentLoad' -bench=BenchmarkHTTP_EngineDelta -benchmem -benchtime=500ms ./internal/proxy/http/...

# Regenerates docs/fp_corpus.md from the internal/corpus benign/malicious
# corpus. No root/BTF/kind required — drives internal/engine directly.
fp-corpus: build
	$(GO) run ./cmd/fp-corpus

# Regenerates docs/cve_corpus.md from the internal/corpus CVE-derived
# corpus (reconstructed, third-party-disclosed MCP CVEs, not self-authored
# scenarios). No root/BTF/kind required — drives internal/engine directly.
cve-corpus: build
	$(GO) run ./cmd/cve-corpus

# Verify the on-disk evidence hash chain (tamper-evident). Override:
#   make verify-evidence EVIDENCE_PATH=evidence.jsonl BACKEND=jsonl
#   make verify-evidence EVIDENCE_PATH=evidence.db BACKEND=sqlite
BACKEND ?= jsonl
EVIDENCE_PATH ?= evidence.jsonl
verify-evidence: build
	$(GO) run ./cmd/verify-evidence -backend=$(BACKEND) -path=$(EVIDENCE_PATH)

# Query SQLite evidence by session_id / verdict / pod_name (JSON array to stdout).
#   make query-evidence EVIDENCE_DB=evidence.db SESSION=sess-a VERDICT=EXFIL POD=agent-1
EVIDENCE_DB ?= evidence.db
SESSION ?=
VERDICT ?=
POD ?=
LIMIT ?= 100
query-evidence: build
	$(GO) run ./cmd/query-evidence -db=$(EVIDENCE_DB) -session='$(SESSION)' -verdict='$(VERDICT)' -pod='$(POD)' -limit=$(LIMIT)

# Convert media/ReadmeGif.mp4 → media/ReadmeGif.gif for the README hero (requires ffmpeg).
readme-gif: media/ReadmeGif.gif

media/ReadmeGif.gif: media/ReadmeGif.mp4
	@command -v ffmpeg >/dev/null || { echo "ffmpeg required: sudo apt install ffmpeg"; exit 1; }
	ffmpeg -y -i $< -vf "fps=10,scale=800:-1:flags=lanczos,split[s0][s1];[s0]palettegen=stats_mode=diff[p];[s1][p]paletteuse=dither=bayer" $@

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

# Sensor-only DaemonSet on kind (requires docker, kind, kubectl). See deploy/k8s/PRIVILEGE.md.
demo-k8s:
	chmod +x scripts/demo-k8s.sh
	INTERLOCK_IMAGE=$(IMAGE) ./scripts/demo-k8s.sh

# Throwaway EC2 VM for LSM/KRSI prototyping (v0.3 Phase 2). See deploy/ec2/README.md.
lsm-vm-up:
	chmod +x deploy/ec2/setup-instance.sh deploy/ec2/bootstrap.sh
	./deploy/ec2/setup-instance.sh

lsm-vm-ssh:
	chmod +x deploy/ec2/ssh.sh
	./deploy/ec2/ssh.sh

lsm-vm-sync:
	chmod +x deploy/ec2/sync.sh
	./deploy/ec2/sync.sh

lsm-vm-down:
	chmod +x deploy/ec2/destroy-instance.sh
	./deploy/ec2/destroy-instance.sh

clean-evidence:
	rm -f evidence.jsonl evidence.json events.jsonl
	rm -f events-monitor.jsonl events-block.jsonl events-ebpf.jsonl
	rm -f evidence-monitor.jsonl evidence-block.jsonl evidence-ebpf.jsonl

clean: clean-evidence
	rm -f $(BINARIES)
	rm -rf dist/
