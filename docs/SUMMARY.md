# Interlock — Current Summary

**Latest tagged release:** [`v0.2.1`](https://github.com/yxshwanth/Interlock/releases/tag/v0.2.1) (2026-07-05).  
**This tree:** post-v0.2 detection + operability work beyond the tag (async evidence, Variant B payload paths, bounded overlap expansion, openat/DNS). See [`CHANGELOG.md`](../CHANGELOG.md) `[Unreleased]`.

Living docs: [`architecture.md`](architecture.md) · [`ROADMAP.md`](ROADMAP.md) · [`task_list.md`](task_list.md) · [`performance.md`](performance.md) · [`project_overview.md`](project_overview.md)

---

## What Interlock is

Runtime MCP exfiltration detection across **two planes**:

| Plane | Role | Verdict when tripped |
|---|---|---|
| **Proxy (Variant A)** | Inspect tool-call chains; block sink calls that carry tainted secrets (encoding-aware) | `EXFIL` 0.95 |
| **eBPF (Variant B)** | Kernel probes on monitored PIDs; contain via SIGKILL | `EXFIL` 0.95 with payload overlap; else `SUSPICIOUS` 0.60 |

Honest asymmetry: Variant A **prevents**; Variant B **detects + contains** (first packet may already have left).

---

## Shipped capabilities (current)

### Transport & sessions
- STDIO (default) and Streamable HTTP/SSE (`2025-11-25`)
- Multi-session HTTP with per-session backend pools + PID→session attribution

### Detection — Variant A
- Trifecta legs + taint extraction on sensitive sources
- Canonical forms: literal, base64, hex, URL-encoding, reversal
- Depth-2 nests (`base64_hex`, `hex_base64`, `base64_url`, `base64_reversed`) + `gzip_base64`
- Same-call JSON string reassembly (secret split across fields in one `tools/call`)
- Evidence records `match_form`; `RedactJSON` scrubs variants

### Detection — Variant B
- `connect()` (IPv4) tripwire → `SUSPICIOUS` / deferred kill (~100 ms)
- `write()` first-256 bytes correlated to recent non-allowlisted connect/`sendto` → `EXFIL` on overlap
- `sendto()` self-contained dest + first-256 → dual claim; port **53** tagged as `dns`
- `openat()` + config `sensitive_paths` → `SUSPICIOUS` only (open ≠ proven exfil)

### Operability
- Async evidence emit (`AsyncEvidenceSink`, `evidence.backpressure`)
- Evidence posture: **JSONL intentional default**; SQLite opt-in for retention
- Event-log backpressure; eBPF `drop_count`; runtime stats
- Published overhead: [`performance.md`](performance.md) — engine delta ~0.5 ms sensitive reads / ~0.1 ms sink checks; concurrent HTTP absolute p99 via `TestHTTP_ConcurrentLoad_ReadTicket`

### Demos
- `make demo` / `make demo-ebpf`: Pass 1 literal breach → Pass 2 `gzip_base64` block → Pass 3 payload EXFIL + kill (`INTERLOCK_EXFIL_MODE=local` + `interlock-ebpf-local.yaml`); HTTP variants separate

---

## Known gaps (explicit)

| Gap | Notes |
|---|---|
| Cross-call secret splits | Same-call reassembly only |
| Depth-3+ / exotic encodings | Closed depth-2 + gzip_base64 only |
| Other compressors | zstd, deflate-raw, multi-layer |
| Secrets past first 256 egress bytes | write/sendto N=256 |
| IPv6, `sendmsg`/`writev` | AF_INET only |
| DoH/DoT | DNS = sendto:53 heuristic |
| Write before suspicious connect | Correlation requires recent connect/sendto |
| First-packet prevention | LSM/KRSI → v0.3 |
| Tool-shadowing | Backlog |

---

## What’s next

**Active backlog:** cross-server tool-shadowing; then demand-gated **v0.3** (K8s DaemonSet, LSM/KRSI, daemon/metrics/SIEM, signed releases). Details: [`task_list.md`](task_list.md), [`ROADMAP.md`](ROADMAP.md).

**Do not start v0.3** until external demand appears for fleet deploy / in-kernel prevent.

---

## Reproduce

```bash
make build && make test
make demo                  # proxy-only
sudo make demo-ebpf GO=$(which go)
make bench && make bench-http
```

eBPF needs root + BTF kernel. CI covers unit/race + DropCount API; live probe load is local/`sudo`.

---

## Milestone history (short)

| Tag | What |
|---|---|
| `v0.1.0` | STDIO proof: trifecta, Variant A block, connect tripwire, JSONL evidence |
| `v0.2.0` | HTTP/SSE, multi-session, encoding overlap, benches, SQLite opt-in, backpressure |
| `v0.2.1` | End-to-end HTTP overhead A+C |
| Unreleased (this tree) | Async evidence; write/sendto/openat/DNS; bounded overlap expansion; concurrent load + ringbuf tests |
