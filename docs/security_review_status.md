# Security review — status against current code (Wave 0, A1)

Checked each finding in [`security_review.md`](security_review.md) against the tree at `5d9e946` by reading the cited code. "Fixed" means the described defect is gone in the code; it does not mean a regression test exists (not yet verified per finding).

| # | Finding | Status | Evidence |
|---|---|---|---|
| 1 | `send(2)` blind spot | Open | Probes: write, writev, sendto, sendmsg only (`connect.c`); no `sendmmsg`/`send`/`pwrite` |
| 2 | `fd < 3` skip | Open | `connect.c:277,320,367,420` |
| 3 | Only `iov[0]` captured | Open | `connect.c:328,432`; comment still says "verifier-safe" |
| 4 | 5s connect→write window | Open | `SuspiciousConnectTTL = 5 * time.Second`, `sensor.go:20` |
| 5 | TOCTOU on `bpf_probe_read_user` | Open | Inherent; needs a `KnownGap` pin |
| 6 | Payload not zeroed, read unchecked | Open | `memset` stops at `offsetof(payload)`; return of `bpf_probe_read_user` ignored (`connect.c:294,303`) |
| 7 | Children inherit privileges | Open | `server.go:43` sets only `Setpgid`; no uid/`NoNewPrivs`/userns |
| 8 | `ReadContainerFile` traversal | **Fixed** | `proc_root.go` cleans path, rejects `..`, no host fallback |
| 9 | Unbounded taint/sessions | Open | No taint-size, taint-count or session cap found in `internal/engine` |
| 10 | Low-entropy chunks → false EXFIL | **Fixed** | `minChunkEntropyBitsPerByte = 3.0` in `chunk.go`; confirm against corpus |
| 11 | Origin validation bypass | **Fixed** | Exact hostname compare, empty entries skipped (`headers.go`) |
| 12 | Reader goroutine wedge | **Fixed** | Non-blocking `select` with `default` (`dispatch.go`) |
| 13 | Logs mode 0644 | **Fixed** | `0600` in `evidence_sink.go`, `logger.go`, `evidence_factory.go` |
| 14 | Bridge min length / hash unchecked | Open | Only non-empty and max-size checks (`bridge.go:244-248`) |
| 15 | `RedactJSON` malformed JSON | **Fixed** | Parses, redacts leaves, remarshals |
| 16 | DNS reassembly first label only | Open | `normalizedEgressFragment` returns `q[:i]` |
| 17 | Reassembly per-(pid,dest) | Open | `egressFlowKey`, `enforceEgressFlowCap` unchanged |
| 18 | Decoder drops layers >8 KiB | Open | `maxDecodeBytes = 8*1024`, `decode.go:17,75` |
| 19 | Divider → false EXFIL | **Fixed** | Same fix as 10 |
| 20 | Ingest path panic | **Partial** | `recover()` added, but logs "FAIL-OPEN for this result" and relies on the breaker; Wave 1 §26 wants fail-closed |
| 21 | Containment kills process group | Open | `syscall.Kill(-pid, SIGKILL)`, `sensor.go:670` |
| 22 | Allowlist semantics | Open (unconfirmed) | Sensor matches destination IP strings only; `interlock.yaml` lists the hostname `api.anthropic.com`, which can't match an IP |
| 23 | Viewer unescaped `item.ref` | **Fixed** | `esc(String(item.ref))`, `viewer.html:464` |

**Fixed (8):** 8, 10, 11, 12, 13, 15, 19, 23. **Partial (1):** 20. **Open (15):** 1–7, 9, 14, 16–18, 21, 22.

## Implications for Wave 1

- §24 (kernel plane) scope is unchanged: findings 1–6 all open.
- §25: entropy gate already landed; the remaining work is measuring it against the Wave 0 baseline, plus privilege drop (7) and bounds (9).
- §26: only 20 is left, as a fail-closed change.
- 16–18, 21, 22 need triage: pin as `KnownGap` or schedule.
- Not yet checked: whether each "Fixed" item has a regression test that fails without the fix.
