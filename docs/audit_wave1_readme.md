# Wave 1 docs audit: README and threat model against the code (§28, review Tier 4)

Tree: branch `wave-0-1` at `cbdf3b4`. Every claim below was checked by reading the cited code, not other docs. Line numbers in "Location" refer to `README.md` and `docs/threat_model.md` as they were at `cbdf3b4`, before this audit edited them.

Verdicts: **true**, **overstated** (true in a narrower case than stated), **false**, **unverifiable here** (needs root, a BPF-LSM kernel, a cluster, or outside sources).

Other Wave 1 workers are fixing findings 1–9, 14, 16–22 on separate branches. The fixes here describe the code **as it is on this branch**: open findings are worded as "known gap, see `docs/security_review_status.md`". **Re-run this audit after the Wave 1 merge**; several rows will flip back.

## README.md

| # | Claim | Location | Verdict | Evidence | Fix applied |
|---|---|---|---|---|---|
| R1 | Secrets expand into thirteen canonical forms | L41, L294-303 | true | `internal/engine/encoding.go:22-34` | none |
| R2 | Proof → `EXFIL` 0.95; no proof + AllLit → `SUSPICIOUS` 0.60 | L46, L274-279 | true | `internal/engine/engine.go:511-530` | none |
| R3 | Proof means "blocked, or the process is killed"; "Hard proof always does something" | L47-49 | overstated | Monitor mode forwards Variant A `EXFIL` (`engine.go:532-536`); Variant B kills in every mode (`engine.go:543-548`) | Reworded; added audit-status banner linking `security_review_status.md` |
| R4 | FP corpus: 31/31, 7/37 (18.9%), 0/37, 7 known-gap misses | L57, L469-476 | true | `docs/fp_corpus.md:21-24`, `docs/baseline_wave0.md`, `docs/budgets.json` `fp_corpus` | none |
| R5 | CVE corpus: 12/15 genuine reach `EXFIL`; 7/7 families | L58, L484-485 | true | `docs/cve_corpus.md:25-28`, `docs/budgets.json` `cve_corpus` | none |
| R6 | "reconstructs seven independently disclosed MCP CVEs" | L60 | overstated | 7 families, 16 scenarios (`docs/cve_corpus.md:25,85`) | "seven families ... (16 scenarios)" |
| R7 | Pass 2 matches `gzip_base64` precomputed at ingestion | L147 | true | `encoding.go:31,40-75` | none |
| R8 | eBPF probes on `write`/`writev`/`sendto`/`sendmsg` carry a payload excerpt; Variant B "Sees" row | L153, L199 | overstated | `fd < 3` skipped (`internal/ebpf/bpf/connect.c:277,320,367,420`); `writev`/`sendmsg` read only `iov[0]` (`:328-351,432-433`); `sendto` with NULL addr returns early (`:373`); no `sendmmsg`/`pwrite` probe (`SEC` list `:225-529`) | Caveat in "Sees" row; paragraph after Pass 3 naming the demo's `conn.Write` path; item 10 under "Where it fails" |
| R9 | First EXFIL packet is contained, not prevented | L163, L536 | true | `TestIngestSyscall_FirstPacketStillContained_KnownGap` | none |
| R10 | Opt-in LSM denies *repeat* `connect()` as `prevented` | L201, L285 | unverifiable here | Program exists (`connect.c:529`); needs a BPF-LSM kernel to run | none |
| R11 | `PAYLOAD_MAX` 1024; routine ring `connect`/`openat`, critical ring `write`/`writev`/`sendto`/`sendmsg`/`lsm_deny` | L204 | true | `connect.c:22,122,134,246,288,336,386,451,473,506,545` | none |
| R12 | `sandbox.netns`: side channel **prevented**, children "have no network to reach" | L210, L455, L536 | overstated | Child gets only `Setpgid` + `CLONE_NEWNET` (`internal/proxy/server.go:45`, `internal/proxy/sandbox_linux.go:22`); no uid drop, `NoNewPrivs`, or userns, so a root child can `setns` out (review #7, open) | Qualified in all three places |
| R13 | "Interlock performs no network egress of its own beyond local evidence and configured alerting" | L246, L516 | false | SIEM POST (`internal/siem/ocsf.go:147`); Kubernetes API client in sensor mode (`internal/k8s/watcher.go:16-18`) | Lists webhook, SIEM, and the Kubernetes API |
| R14 | `classifyTrip` excerpt | L252-262 | true | `engine.go:511-529` | none |
| R15 | "Overlap alone is `EXFIL`" | L264 | overstated | Proxy computes overlap only for `external_sink`-tagged tools: `engine.go:344-345` returns `Allow` first (review Tier 4) | Tag gate stated in "What counts as proof" |
| R16 | Legs decay at 30m / 32 calls | L272, L348 | true | `engine.go:112-113` | none |
| R17 | `contained_by_kill` = "immediate SIGKILL"; `allowed_monitor` = "Variant A SUSPICIOUS, or monitor mode" | L286-287 | overstated | Kill also goes to the process group (`internal/ebpf/sensor.go:359-369,672`, review #21); monitor mode does not stop Variant B kills (`engine.go:543-548`) | Rows corrected |
| R18 | `brotli_base64`/`zstd_base64`/`lz4_base64` as coverage | L303 | overstated | Precomputed byte-exact strings (`encoding.go:66-72`); decoder tries only base64/hex (`internal/engine/decode.go:85-91`); container walker handles ZIP/gzip/zlib/tar only (`internal/engine/container.go:165-171`) | Caveat paragraph under the forms table |
| R19 | Recursive decoder, depth 5, clamp `[3,5]` | L307 | overstated | Depth and clamp true (`decode.go:25,40-41`); base64/hex only; decoded layers over 8 KiB skipped (`decode.go:19,94`, review #18, open) | Added both limits |
| R20 | Fragment FIFO 16 chunks / 64 KB | L308 | true | `engine.go:23-24` | none |
| R21 | Egress reassembly per `(pid, destination)`, 10s window | L309 | overstated | True (`engine.go:25-28`) but DNS reduced to first label (`engine.go:1173-1185`, #16) and 32-flow eviction (`engine.go:28`, #17) | Added #16/#17 |
| R22 | Chunk matching on a 32-byte run | L310 | true | `internal/engine/chunk.go:13-14`; entropy gate `:24,61` not mentioned | Added 64-byte minimum and 3.0 bits/byte gate |
| R23 | Container limits 10 MiB / depth 2 / 100 / 50ms; abort → `SUSPICIOUS` | L312, L351 | true | `container.go:40-46`; `engine.go:526-528` | none |
| R24 | `TaintedValue.Value` tagged `json:"-"` | L314 | true | `internal/model/model.go:167-169` | none |
| R25 | `make verify-evidence` "tells you whether anything was altered or removed" | L322 | overstated | Unkeyed SHA-256; `VerifyChain` accepts first record with `chain_seq > 0`, so head and tail truncation verify clean (`internal/engine/evidence_chain.go:50-79`) | Rewritten with the limits |
| R26 | `ts_mono_ns` vs `timeline_seq` ordering | L324 | true | `model.go:302-305` | none |
| R27 | "0% EXFIL-tier FP" as a property of byte overlap | L342, L478 | overstated | Property of the 75-scenario token-shaped corpus; review #19 found a false `EXFIL` on path-taint input (since fixed, `chunk.go:61`) | Scoped to the corpus |
| R28 | `CheckOverlap` is "~70 ns"; memory "bounded: 13 variants per secret per session" | L347 | overstated | 70 ns is the hit path only; miss is ~4 µs for 1 value, ~1.2 ms at 10,000 (`docs/baseline_wave0.md`); no cap on taint or sessions (review #9, open) | Rewritten |
| R29 | 11 direct dependencies | L349 | true | `go.mod:5-17` | none |
| R30 | Detection engine is "~1400 lines of Go with zero non-stdlib imports" | L350 | false | `encoding.go:12-14` imports brotli, klauspost zstd, lz4; `internal/engine` is 4,287 non-test lines (`engine.go` alone 1,413) | Row rewritten |
| R31 | Go 1.26+ | L19, L357 | true | `go.mod:3` | none |
| R32 | Probes copy IPv4/IPv6 destination; send no traffic, write no files | L382 | true | `connect.c:187-211` | none |
| R33 | `daemonset-capabilities.yaml` is capabilities-first, non-privileged | L402 | true | `deploy/k8s/daemonset-capabilities.yaml:61` | none |
| R34 | Capability posture needs the bridge for `EXFIL` | L409 | unverifiable here | Needs a cluster; consistent with `deploy/k8s/PRIVILEGE.md` | none |
| R35 | Sample `egress_allowlist: [127.0.0.1, api.anthropic.com]` (implied: trusts the API host) | L427-429 | false (as implied) | Sensor matches destination IP strings only, never resolves (`sensor.go:150-153`); `127.0.0.1` exempts loopback (`interlock.yaml:14-16`, review #22, open) | Explanatory paragraph under the config block; config itself not changed (outside this worker's boundary) |
| R36 | `ebpf.payload_capture_bytes` can only reduce | L458 | true | `connect.c:171-172,218-219` | none |
| R37 | Config reloads on `SIGHUP` | L463 | true | `cmd/interlock/main.go:165,389` | none |
| R38 | HTTP overhead: 936/400 µs (~536 µs) read, 492/374 µs (~118 µs) sink; "Sub-millisecond" | L491-496 | false | Re-run 2026-10-20, 3× `BenchmarkHTTP_EngineDelta -benchtime=500ms`, i7-11800H: read 3.88–4.15 ms on vs 0.34 ms off; sink 0.34–0.39 ms on vs 0.31–0.36 ms off. Consistent with the `docs/budgets.json` ceiling (9.3 ms = 2× worst) | Table replaced with measured ranges; "sub-millisecond" removed |
| R39 | PEM `TaintExtract` ~4.1–4.3 ms/op, "roughly 12×" the token baseline | L498 | false (ratio) | Wave 0 baseline: PEM 4.60 ms, token 2.27 ms (≈2×); re-run: PEM 4.20–4.94 ms, token 1.62–1.99 ms | Uses Wave 0 baseline numbers |
| R40 | Linux x86_64 only for the eBPF plane | L512 | true | `internal/ebpf/connect_x86_bpfel.go` build tag; `internal/ebpf/generate.go:12` `-target amd64` | none |
| R41 | Scale: process table is the first bottleneck | L514 | overstated | Omits unbounded taint/sessions (review #9, open) | Added |
| R42 | "MCP servers are untrusted" (implied: contained) | L516 | overstated | They inherit the proxy's privileges (`server.go:45`, review #7) | Added |
| R43 | "Design boundaries ... Every one has a `KnownGap` test" | L530 | overstated | Items 6, 7, 9 have no pin; 11 `KnownGap` tests exist | Reworded; item 10 lists open review findings |
| R44 | Gap 4 pinned by `TestEngine_IngestSyscallSensor_NeverReachesSuspicious_KnownGap` | L538 | true | test exists | none |
| R45 | Gap 7: process-table exhaustion; "none of that authenticates who may connect" | L544 | false | Optional `transport.bearer_token` exists (`internal/proxy/http/transport.go:88`, `internal/config/config.go:29`); the real risk is unauthenticated tool execution returning secrets with no sink check (review Tier 4); default listen `127.0.0.1:8080` (`internal/config/config_validate_sections.go:31`) | Rewritten |
| R46 | Gap 8 pinned by `TestToolShadowing_RuntimeReregistration_KnownGap` | L546 | true | test exists | none |
| R47 | Gap 9: "Monitor mode allows proven `EXFIL` through" | L548 | overstated | Proxy plane only; Variant B still kills (`engine.go:543-548`) | Reworded |
| R48 | "345 test functions, 11 of them `KnownGap`" | L590 | false (count) | 352 top-level `Test*` functions, 11 `*KnownGap*` (`git ls-files '*_test.go'`, matches `CONTRIBUTING.md:58`) | 352 |
| R49 | "CI runs `test` and `race` on `main`" | L590 | overstated | Race runs only on proxy and engine with `-short`; CI also runs gofmt, vet, layers/SPDX, corpus and engine-bench gate; HTTP ceilings skipped (`.github/workflows/ci.yml:32-44,67-68`) | Rewritten |
| R50 | Latest release `v0.4.0` | L605 | true | `git tag`; `CHANGELOG.md:30` | none |
| R51 | Shipped feature list | L607 | true | Each item has code under the named package; behavior of LSM/k8s parts unverifiable here | none |
| R52 | Problem framing, CVE counts, demo narrative | L86-125 | unverifiable here | Not code claims; demo needs root | none |

## docs/threat_model.md (T1–T6, plus new T7)

| # | Claim | Location | Verdict | Evidence | Fix applied |
|---|---|---|---|---|---|
| T1a | Critical ring carries `write` / `sendto` / `lsm_deny` | T1 Mechanism | overstated (incomplete) | Also `writev`, `sendmsg` (`connect.c:336,451,473`) | Listed all five |
| T3a | Panic paths `recover()`-wrapped; in-flight call fails open once | T3 | true, incomplete | `IngestResult` recover fails open for that result (`internal/proxy/dispatch.go:277-282`, review #20 partial) | Added to Mitigations and Residual |
| T4a | Attribution by `(pid, start_time)`; kill only with attribution | T4 | overstated | Kill targets the process group (`sensor.go:672`, #21); connect destination is TOCTOU-racy (#5) | Added to Residual |
| T5a | Chain detects mid-chain edit/delete; residual is node root forging a full genesis chain | T5 | overstated | Any writer can recompute the unkeyed chain; head and tail truncation verify clean (`evidence_chain.go:50-79`) | Residual rewritten |
| T6a | `sendmsg`/`writev` listed under "No longer bypass channels — closed" | T6 | false | Only `iov[0]` captured (`connect.c:328,432`, review #3, open) | Moved out of "closed"; stated as probed-but-partial |
| T6b | Proxy-mode TCP egress "closed when `sandbox.netns: true`" | T6 | overstated | Holds for an unprivileged child only; root child can `setns` out (`server.go:45`, review #7) | Qualified; points to new T7 |
| T6c | Token-shaped brotli/zstd/lz4 closed | T6 | overstated | Byte-exact precomputed strings only (`encoding.go:66-72`) | Qualified |
| T6d | Egress allowlist (absent from T6) | T6 | omitted | Hostnames never match; `127.0.0.1` exempts loopback (`sensor.go:150-153`, review #22) | Added, with guidance to list IPs only |
| T6e | Kernel-plane evasions #1, #2, #4, #5, #6 (absent) | T6 | omitted | `connect.c:277,294-303,373`; `sensor.go:22,517` | Added as open, not yet pinned |
| T6f | IPv6 closed | T6 | true | `connect.c:187-211` | none |
| T7 | (new) Spawned servers run with the proxy's privileges | new | n/a | `server.go:45`; no `Credential`/`NoNewPrivs`/userns anywhere under `internal/proxy` | Added T7 and accepted risk 8 |

## Same claims in other docs

| Doc | Claim | Verdict | Fix applied |
|---|---|---|---|
| `docs/INTERLOCK.md` §3 | netns side channel **prevented** at spawn | overstated (#7) | Qualified |
| `docs/INTERLOCK.md` §6 | Allowlist matches exact/normalized IPs | true, incomplete (#22) | Added hostname and loopback consequence |
| `docs/INTERLOCK.md` §11 | Tail truncation detected "if remaining chain breaks"; full-file forge needs node root | overstated | Added rows: tail truncation, head truncation, recompute-after-edit (all undetected) |
| `docs/INTERLOCK.md` §16 | `writev`/`sendmsg` and proxy TCP egress listed as closed | false / overstated | Marked partial; added "Open security-review findings" ledger |
| `docs/INTERLOCK.md` §16 | Shannon entropy "not wired" | overstated | Not a verdict signal, but gates chunk minting since #10/#19 |
| `docs/architecture.md` §1 | "no network egress of its own except writing local evidence" | false | Lists webhook/SIEM and Kubernetes API; notes #7 |
| `docs/architecture.md` §5 | `openat` trips kill promptly | false | `openat` never proves `EXFIL`, never kills (`engine.go:802-804`); noted pgid kill |
| `docs/architecture.md` §16 | `writev`/`sendmsg` "recently closed" | false | IPv6 closed; `iov[0]` gap stated |
| `docs/detection_boundary.md` | brotli/zstd/lz4 as caught encodings | overstated | Caveat |
| `docs/detection_boundary.md` | Gap list (no review findings) | omitted | Added "Open security-review findings (not yet pinned)" |
| `docs/README.md` | Variant B "correlates it in time with the sensitive read, and flags it" | false | Attribution is by PID/cgroup; `EXFIL` needs payload overlap |
| `SECURITY.md` | "As of this tree (v0.3.0 ...)"; probes "connect / write / sendto / openat" | false (stale) | v0.4.0 + Wave 0; added `writev`/`sendmsg`; points to open findings |
| `docs/repository_hygiene.md` | "the current 178 tests" | false | 352 at Wave 0 (outside the listed boundary; edited because the task asked for stale counts anywhere) |

## Not fixed here (outside this worker's file boundary)

- `docs/performance.md` still publishes the ~536 µs / ~118 µs HTTP deltas and the "~12×" PEM ratio. Both are stale (R38, R39); it needs re-measuring by whoever owns it.
- `docs/baseline_wave0.md` lists `make bench-http` as not recorded. The R38 figures above are a dev-laptop measurement, not a recorded baseline.
- `interlock.yaml` still ships `api.anthropic.com` and `127.0.0.1` in `egress_allowlist` (#22 owner).
- `docs/STARTUP_ROADMAP.md` says "T1–T6"; the threat model now has T7.
