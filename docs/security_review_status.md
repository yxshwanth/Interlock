# Security review — status against current code (Wave 0, A1)

Checked each finding in [`security_review.md`](security_review.md) against the tree at `5d9e946` by reading the cited code. "Fixed" means the described defect is gone in the code; it does not mean a regression test exists (not yet verified per finding).

| # | Finding | Status | Evidence |
|---|---|---|---|
| 1 | `send(2)` blind spot | Fixed for `sendto`/`send`/`sendmsg`/`sendmmsg[0]`, kernel-verified | The kernel run showed NULL-address `sendto` still returned early; it is now emitted as a write on the fd (`emit_write`) and correlates via `(pid, fd)`. `TestKernel_SendWithNullAddressCaptured`, `_SendmmsgFirstMessageCaptured`, `_SendtoCapturedOnLowFD`. `pwrite64`, `pwritev`, `sendfile`, `io_uring` and `sendmmsg` beyond msgvec[0] remain unprobed and documented |
| 2 | `fd < 3` skip | Fixed for send paths, kernel-verified | Skip removed from `sendto`/`sendmsg` (`TestKernel_SendtoCapturedOnLowFD` dups a UDP socket onto fd 0); `write`/`writev` keep it (pinned `TestBPFSource_WriteStdioSkip_KnownGap`) |
| 3 |Only `iov[0]` captured | Fixed, kernel-verified | `gather_iov` copies up to 4 iovecs via a per-CPU scratch map. The kernel run found the verifier rejected it (a re-read of `iov_len` lost its bounds, which blocked every program from loading); fixed with masks and `barrier_var`. `TestKernel_WritevGathersAllIovecs`, `_SendmsgGathersAllIovecs` |
| 4 |5s connect→write window | Fixed, kernel-verified | Connect events now carry the fd; the sensor keys correlation by `(pid, fd)` and a connect-armed fd lives 10 min (`staleFDTTL`), not 5 s. `SuspiciousConnectTTL` only bounds the fd-less `sendto` arming. `close(2)` is not probed, so a reused fd can keep a stale dest until the TTL. Tests `TestWriteCorrelation_*`, `TestKernel_ConnectEventCarriesFD` |
| — |`connect_event`/`sendto_event` layout vs Go decoder | Fixed, kernel-verified | Found while doing #4: natural C alignment put `dest_port` at 42 and `cgroup_id` at 56, but the decoder read 41 and 48. Layout is now explicit with `_Static_assert`s on every offset the decoder hard-codes. `TestKernel_ConnectEventCarriesFD` checks port, fd, comm and cgroup decode against a real event. The committed `.o` is built by the pinned container (clang 14) |
| 5 |TOCTOU on `bpf_probe_read_user` | Pinned as gap | Inherent to `sys_enter` tracepoints; `TestBPFSource_PayloadProbesAreSysEnter_TOCTOUKnownGap`, `threat_model.md` T6 |
| 6 |Payload not zeroed, read unchecked | Fixed, kernel-verified | Reads sized to the captured length and checked; ringbuf record discarded on failure; loader clamps `Len` to the sample. All programs load and run under the real verifier |
| 7 |Children inherit privileges | Fixed, verified as root | Root proxy drops children to SUDO_UID/nobody with `no_new_privs`; `TestStartServer_NetNS_ChildCannotSetnsOut` ran and passed as root on the VM. Also found: `DropPostAttach` cleared `CAP_SYS_ADMIN` on one thread only; it now uses `AllThreadsSyscall` (pure-Go builds, as the release build is) |
| 8 | `ReadContainerFile` traversal | **Fixed** | `proc_root.go` cleans path, rejects `..`, no host fallback |
| 9 |Unbounded taint/sessions | Fixed | Per-session taint caps (1,024 values / 1 MiB, drop oldest), hash dedupe, 10,000-session LRU cap. Dropped values pinned as gaps |
| 10 | Low-entropy chunks → false EXFIL | **Fixed** | `minChunkEntropyBitsPerByte = 3.0` in `chunk.go`; confirm against corpus |
| 11 | Origin validation bypass | **Fixed** | Exact hostname compare, empty entries skipped (`headers.go`) |
| 12 | Reader goroutine wedge | **Fixed** | Non-blocking `select` with `default` (`dispatch.go`) |
| 13 | Logs mode 0644 | **Fixed** | `0600` in `evidence_sink.go`, `logger.go`, `evidence_factory.go` |
| 14 |Bridge min length / hash unchecked | Fixed | Bridge rejects values under 8 bytes and hashes that do not match the value |
| 15 | `RedactJSON` malformed JSON | **Fixed** | Parses, redacts leaves, remarshals |
| 16 |DNS reassembly first label only | Fixed, residual pinned | Full DNS query scanned. Secret split across two labels is a pinned gap |
| 17 |Reassembly per-(pid,dest) | Mostly fixed, residual pinned | Per-pid buffer joins cross-destination splits. Slow trickle and 32-decoy-flow eviction remain pinned gaps |
| 18 |Decoder drops layers >8 KiB | Fixed, residual pinned | Layers up to 64 KiB matched. Nested padded layers remain a pinned gap |
| 19 | Divider → false EXFIL | **Fixed** | Same fix as 10 |
| 20 |Ingest path panic | Fixed | Ingest panic withholds the result, fails closed, and the engine lock is released (`defer`). |
| 21 |Containment kills process group | No code change | Group kill only reaches a group whose id is the attributed PID; tests pin it. PID-reuse residual documented |
| 22 |Allowlist semantics | Fixed | Hostname entries are dropped with a warning; `interlock.yaml` and examples list IPs only |
| 23 | Viewer unescaped `item.ref` | **Fixed** | `esc(String(item.ref))`, `viewer.html:464` |

**Wave 1 (this branch):** 1, 2, 3, 4, 6 and 7 verified on a Linux 7.0 kernel as root (see `baseline_wave0.md`); 5 pinned as a gap; 9, 14, 16, 17, 18, 20, 22 fixed (16, 17, 18 with pinned residuals); 21 needed no code change. Fixed before Wave 1: 8, 10, 11, 12, 13, 15, 19, 23.

## Implications for Wave 1

- §24 (kernel plane) scope is unchanged: findings 1–6 all open.
- §25: entropy gate already landed; the remaining work is measuring it against the Wave 0 baseline, plus privilege drop (7) and bounds (9).
- §26: only 20 is left, as a fail-closed change.
- 16–18, 21, 22 need triage: pin as `KnownGap` or schedule.
- Regression coverage: every "Fixed" item now has a named test (#23 gained `web/viewer_test.go`, mutation-checked against the unescaped form). Kernel items have root-gated tests that ran on the VM (`kernel_probes_test.go`).

## Tier 4 (README outruns the code) — docs audit, Wave 1 worker D

Checked at `cbdf3b4`; full claim table in [`audit_wave1_readme.md`](audit_wave1_readme.md).

| Tier 4 item | Status | Evidence |
|---|---|---|
| Overlap computed only for `external_sink`-tagged tools | **Docs fixed** (README "What counts as proof") | `engine.go:344-345` |
| brotli/zstd/lz4 forms are byte-exact, demo-grade | **Docs fixed** (README, `detection_boundary.md`, `threat_model.md` T6); code unchanged | `encoding.go:66-72`, `decode.go:85-91` |
| Hash chain unkeyed; head truncation verifies clean | **Docs fixed** (README, T5, `INTERLOCK.md` §11); code unchanged | `evidence_chain.go:50-79` |
| HTTP transport is an unauthenticated tool-execution endpoint | **Docs fixed** (README gap 7); optional `transport.bearer_token` exists but is off by default | `transport.go:88`, `config.go:29` |

Also corrected: `threat_model.md` T6 no longer lists `sendmsg`/`writev` as closed (#3) or `sandbox.netns` as closing egress against a privileged child (#7); T7 added for #7. README HTTP overhead and PEM ratio were stale (re-measured, see audit R38/R39); test count 345 → 352. Every doc statement about an open finding says so and links here. **These docs must be re-checked after the Wave 1 merge.**
