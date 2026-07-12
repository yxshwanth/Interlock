# Monitor Mode Pilot

## The problem you already know about

Your agents read secrets, ingest attacker-controlled content, and reach the internet. That's the lethal trifecta. Static scanners check tool definitions before approval — they miss the attack that matters: a sequence of individually authorized calls that chains into exfiltration at runtime.

## What Interlock does

Sits between your agent and its MCP servers on two planes. The proxy sees tool-call chains and tracks tainted values through encodings. The eBPF sensor sees `connect()` and `write()` from monitored processes — the side channels JSON-RPC inspection can't reach.

When a tainted secret appears in a sink call or an egress payload: verdict `EXFIL`, confidence 0.95. Evidence record with the full causal timeline.

## What monitor mode means

Interlock observes. It does not block, kill, or modify any call. Your agents run exactly as they do today. The only output is evidence files — structured records of what Interlock would have caught if enforcement were on.

Zero production impact. Zero enforcement risk.

## What you need

A Kubernetes cluster running MCP-connected agents. EKS, GKE, or any distribution with BTF-enabled kernels.

Deploy two things:

1. **Sensor DaemonSet** — eBPF probes on labeled nodes. Capabilities-only (no `privileged: true` required with the taint bridge).
2. **Proxy sidecar** — sits in front of your MCP servers. Forwards taint registrations to the sensor over a Unix socket.

Label agent pods with `interlock.io/monitor: "true"`. Apply the manifests. Done.

```bash
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/daemonset-capabilities.yaml
# proxy sidecar: deploy/k8s/proxy-taint-bridge-example.yaml
```

Set `enforcement: monitor` in the sensor/proxy config so trips emit evidence with `allowed_monitor` / `detected_only` and never block or kill.

## What you get back

After one week of real traffic:

- Every `EvidenceRecord` your deployment produced — the detections, the SUSPICIOUS tripwires, and the quiet sessions where nothing fired.
- A coverage report: which tool-call patterns Interlock saw, which secrets it tainted, which egress it flagged, and which gaps it hit.
- Published detection and false-positive rates against your traffic, not our corpus.

We analyze this together. The evidence reshapes the detection logic if it needs reshaping — that's the discipline, not the exception.

## What Interlock does not do

Detect paraphrased secrets. If an LLM reads `sk-live-abc123` and outputs "the key is sk live abc one two three," no encoding transform catches that. Interlock's detection boundary is programmatic exfil — literal values and their encoded forms. Semantic exfil is a different tool. This is documented: [`detection_boundary.md`](detection_boundary.md).

It also does not replace network policies, credential rotation, or context-window isolation. Those reduce the attack surface before Interlock's layer. Interlock catches what gets through. Deploy both.

## The numbers

| Metric | Value |
|---|---|
| EXFIL detection rate (corpus, non-gap) | 100% (21/21) |
| EXFIL false-positive rate (corpus) | 0.0% (0/30) |
| Known detection gaps | 4 (documented, pinned by tests) |
| Engine overhead — sensitive read | ~0.5 ms |
| Engine overhead — sink check | ~0.1 ms |
| Decode miss-path at 1K tainted values | ~320 µs |

Corpus: 55 scenarios (25 malicious, 30 benign). Published: [`fp_corpus.md`](fp_corpus.md). Scaling benchmarks: [`performance.md`](performance.md).

## The artifacts

| Artifact | What it proves |
|---|---|
| [Threat model](threat_model.md) | Six attack vectors against Interlock itself, with accepted risks named |
| [Detection boundary](detection_boundary.md) | What it catches, what it doesn't, and why |
| [FP corpus](fp_corpus.md) | Regression suite with published rates |
| [Reproducible builds](reproducible_builds.md) | How to build checksummed binaries; signed tags since `v0.2.0`; release workflow ready |
| [Privilege doc](../deploy/k8s/PRIVILEGE.md) | Minimum capability set, EKS-validated |

**Release status:** Signed tag **`v0.3.0`** with checksummed binaries (`SHA256SUMS`) on [GitHub Releases](https://github.com/yxshwanth/Interlock/releases). Verify the tag with [`allowed_signers`](../allowed_signers), then `sha256sum -c SHA256SUMS`. See [`reproducible_builds.md`](reproducible_builds.md) and [`SECURITY.md`](../SECURITY.md).

## Start

Open an issue or email yxshwanth directly. The conversation is short: your cluster, your agent topology, a week of monitor mode. The evidence decides what happens next.
