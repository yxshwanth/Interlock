# Interlock — Roadmap

Map from *proof* to *product* — not a commitment. Priorities follow dependency and risk; integrator feedback can reorder. **Every detection feature ships with KnownGap tests naming what it does *not* catch.**

Companion SoTs (do not duplicate their prose here):

| Topic | Document |
|---|---|
| Detection gaps / tiers | [`architecture.md`](architecture.md) §13, [`INTERLOCK.md`](INTERLOCK.md) §16 |
| Boundaries / rejected | [`detection_boundary.md`](detection_boundary.md) |
| FP / CVE rates | [`fp_corpus.md`](fp_corpus.md), [`cve_corpus.md`](cve_corpus.md) |
| Privilege / deploy | [`deploy/k8s/PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md) |
| Performance | [`performance.md`](performance.md) |

---

## How to maintain this file

**Fixed sections (do not rename or reorder):**

1. Status snapshot
2. Active queue
3. Shipped ledger
4. Version history
5. Backlog (demand-gated)
6. Out of scope
7. Cross-cutting hazards

**Item schema** (use for every Active-queue and new Shipped-ledger row):

| Field | Required | Notes |
|---|---|---|
| `ID` | yes | Stable `§N` for cross-doc refs (`ROADMAP §N`). Never renumber shipped IDs. |
| `Title` | yes | Short noun phrase |
| `Status` | yes | `[ ]` open · `[~]` partial · `[x]` done · `Named` · `Rejected` |
| `Tier` | yes | 1 / 2 / 3 (see architecture §13) |
| `Goal` | yes | ≤2 sentences |
| `Done when` | yes | Testable exit criteria |
| `Links` | when shipped | Docs, tests, config knobs — not narrative |

**Rules:**

- Open work lives only in **Active queue** (full schema).
- Shipped work is one table row in **Shipped ledger** — detail belongs in code/docs/tests, not here.
- Do not re-open `[x]` / `Named` / `Rejected` items; file a new `§N` if scope changes.
- Do not paste corpus writeups, CVE narratives, or PR archaeology into this file.
- New work: append the next free `§N`, add to Active queue, move to Shipped ledger on merge.

---

## 1. Status snapshot

| | |
|---|---|
| **Product arcs** | v0.1 proof · v0.2 usable tool · v0.3 adoptable product — **all exit gates met** |
| **Focus** | Post-corpus hardening and enterprise leftovers |
| **Hard contracts** | EXFIL-tier FP **0.0%**; engine overhead class ~0.5 ms / ~0.1 ms — must not regress |
| **Rates (regen)** | `make fp-corpus`, `make cve-corpus` → live numbers in fp/cve corpus docs |

### Open at a glance

| ID | Title | Status | Tier |
|---|---|---|---|
| §5 leftovers | CEF SIEM export | `[ ]` | 2 |
| §5 leftovers | Cross-session evidence query | `[ ]` | 2 |
| §12 | Shannon entropy detector (dark) | `[ ]` | 2 |
| §13 | Capability drop post-attach | `[ ]` | 2 |
| §21 | Protocol-aware egress parsers | `Named` | 3 |

---

## 2. Active queue

Suggested order: §12 dark measurement → §13 least-privilege closeout → §5 leftovers as demand. §21 stays Named until a deployment shows the MCP family.

### §5 leftovers — Operability

**Status:** `[~]` (fail-closed + dual ringbufs shipped; two items open) · **Tier:** 2

#### CEF SIEM export `[ ]`

| | |
|---|---|
| **Goal** | Extend `internal/siem` beyond OCSF for Splunk/QRadar/ArcSight-class ingest. |
| **Done when** | CEF export path documented and pinned; OCSF path unchanged. |
| **Links** | `internal/siem`, OCSF already in v0.3 Phase 3 |

#### Cross-session evidence dashboard / query `[ ]`

| | |
|---|---|
| **Goal** | Query evidence by `session_id`, verdict, `pod_name` beyond the single-record HTML viewer. |
| **Done when** | Closes `TestEvidenceStore_CrossSessionQuery_KnownGap` (SQLite or JSONL index). |
| **Links** | `web/viewer.html`, evidence sinks |

---

### §12 — Shannon entropy detector `[ ]`

| | |
|---|---|
| **Tier** | 2 |
| **Goal** | Research spike: “sensitive read, then high-entropy undecodable egress” as a **monitor-only** signal. Deliverable is a **measurement**, not an alert. |
| **Done when** | Measurement published in [`fp_corpus.md`](fp_corpus.md). Graduate to SUSPICIOUS discussion only if benign FP surface is clean. |
| **Watch out** | Entropy lights compressed/encrypted/protobuf/hash traffic. If it fires on benign corpus rows, it never leaves dark mode. **Do not wire to any alert tier.** |

---

### §13 — Capability drop post-attach `[ ]`

| | |
|---|---|
| **Tier** | 2 |
| **Goal** | After probes load/attach, drop every capability not needed at runtime; keep `KILL` for containment. |
| **Done when** | Before/after cap set documented and verified on ≥1 supported kernel in [`PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md); residuals named with why. |
| **Watch out** | `BPF`/`PERFMON` may need to stay for re-attach; `SYS_ADMIN` droppability is kernel-version-dependent. |

---

### §21 — Protocol-aware egress parsers `Named`

| | |
|---|---|
| **Tier** | 3 |
| **Goal** | Demand-gated only: lightweight egress dissectors (git pkt-line / smart HTTP, HTTP body + `Content-Encoding`, SMTP DATA) then reuse §20 walker + overlap. |
| **Done when (documentation)** | Named boundary in ROADMAP + detection_boundary + architecture §13; CVE pin still Missed; **no engine code until demand**. |
| **Gate** | Build only if a deployment shows that MCP family in production. |
| **Links** | Pin `cve_2025_68143_mcp_git_push_wire_protocol_gap`; flat zlib/ZIP on ToolArgs/PayloadExcerpt already closed (§20). |

---

## 3. Shipped ledger

Stable IDs for cross-doc refs (`ROADMAP §N`). One row each — no re-litigation.

### Post-corpus build order (§1–§22)

| ID | Title | Status | Tier | Done when (summary) | Links |
|---|---|---|---|---|---|
| §1 | Operational FP remediation | `[x]` | 1 | Any-trip FP down; EXFIL FP 0%; hard contain EXFIL-only | relevance-aware block, leg decay, content-bind; [`fp_corpus.md`](fp_corpus.md) |
| §2 | Close “will cover” gaps | `[x]` | 1 | Fragment buffer, fat-taint benches, payload window, extractResultText, decode depth, inherit-sink via §14 | architecture §13 |
| §3 | Variant B kernel + syscalls | `[x]` | 1 | LSM Slice 1 opt-in; writev/sendmsg; IPv6 dest | `ebpf.lsm_enforce`; Phase 2 notes below |
| §4 | Sensor↔proxy taint bridge | `[x]` | 1 | Unix-socket taint forward + SO_PEERCRED | `internal/bridge`, PRIVILEGE.md |
| §5 | Operability & enterprise | `[~]` | 2 | Fail-closed + dual ringbufs done; CEF + cross-session query open | Active queue |
| §6 | Tamper-evident evidence | `[x]` | 1 | Hash chain + `verify-evidence` | `chain_seq` / `prev_hash` / `hash` |
| §7 | Zero-route netns (proxy) | `[x]` | 1 | `CLONE_NEWNET` opt-in; non-loopback `ENETUNREACH` | `sandbox.netns` |
| §8 | Chunk / substring match | `[x]` | 1 | Long-secret chunk EXFIL; near-chunk TN clean | `trifecta.chunk_match_*` |
| §9 | Standard compressors | `[x]` | 1 | brotli/zstd/lz4 forms; benches in class | `CanonicalEncodings` |
| §10 | Token vaulting | `[x]` | 1 | Dummy-by-default; authorize then scan | `vault.enabled` |
| §11 | Considered and rejected | `[x]` | 3 | Sockmap / SOCKS5 / unbounded trickle / blind EXFIL named | [`detection_boundary.md`](detection_boundary.md) |
| §12 | Shannon entropy (dark) | `[ ]` | 2 | — | Active queue |
| §13 | Cap drop post-attach | `[ ]` | 2 | — | Active queue |
| §14 | Inherit sink suspicion | `[x]` | 1 | Opt-in inherit; allowlist sole exemption | `server_defaults.inherit_sink_suspicion` |
| §15 | Configurable decode depth | `[x]` | 1 | Default 5; FP curve published | `trifecta.max_decode_depth` |
| §16 | Payload capture default 1024 | `[x]` | 2 | Default = compiled max; past-window KnownGap remains | `ebpf.payload_capture_bytes` |
| §17 | Spawn-time launch intercept | `[x]` | 1 | Pinned paths + optional allowlist | `ResolvedSpawnCommands` |
| §18 | Path-driven taint seeding | `[x]` | 1 | Whole-file container relay EXFIL | `path_taint.go` |
| §19 | Egress flow reassembly | `[x]` | 1 | Same-dest DNS/write fragments EXFIL | `SessionState.EgressFlows` |
| §20 | Bounded container descent | `[x]` | 1 | Extracted-xlsx / sink-zip / zlib EXFIL | `container.go` |
| §21 | Protocol egress parsers | `Named` | 3 | Boundary documented; no dissector | Active queue / detection_boundary |
| §22 | Blind side-channel EXFIL | `Rejected` | 3 | Not EXFIL; wrong observation model | detection_boundary; Doris CVE pin |

### v0.3 phases

| Phase | Title | Status | Notes |
|---|---|---|---|
| 1 | K8s DaemonSet (sensor-only) | `[x]` | `deploy/k8s/`; pod attribution; honest limit: full trifecta still prefers proxy+sensor |
| 2 | LSM/KRSI + graceful enforcement | `[~]` | Slice 1 shipped (`ebpf.lsm_enforce`): repeat-connect quarantine after EXFIL. First EXFIL packet stays `contained_by_kill` (architectural). Graceful per-tier responses still open. |
| 3 | Metrics, alerting, SIEM | `[x]` | Prometheus, webhooks, OCSF; CEF deferred to §5 |
| 4 | Trust (threat model, corpus, signed release) | `[x]` | [`threat_model.md`](threat_model.md), corpora, `make release` |

### v0.2 phases

| Phase | Title | Status | Notes |
|---|---|---|---|
| 1 | HTTP/SSE transport | `[x]` | Same `InterceptedEvent` path as STDIO |
| 2 | Multi-session concurrency | `[x]` | PR #9 / #10; PID+start-time; race CI |
| 3 | Real dataflow taint | `[x]` | Encodings + eBPF write/sendto overlap → Variant B EXFIL |
| 4 | Perf + persistent evidence | `[x]` | [`performance.md`](performance.md); JSONL default, SQLite opt-in |

Tags: **`v0.2.0`** / **`v0.2.1`**.

---

## 4. Version history

Exit criteria only. Phase detail lives in the Shipped ledger.

| Version | Intent | Exit state |
|---|---|---|
| **v0.1** | Working proof | Two-plane trifecta catch; STDIO; `connect()`-only eBPF; single session; heuristic overlap; forensic receipt |
| **v0.2** | Usable tool | HTTP/SSE; concurrent sessions; encoded exfil; published overhead; persistent evidence |
| **v0.3** | Adoptable product | DaemonSet deploy; metrics/SIEM; signed release + threat model + published FP rate; LSM Slice 1 opt-in |

---

## 5. Backlog (demand-gated)

Not queued until demand. Do not treat as silent “someday” execution items.

- Unix-socket and file-based exfil paths
- Role-based access and operator audit logs
- ARM support and cross-distro / CO-RE portability
- Managed cloud offering
- Third-party security audit and red-team results
- Comparison benchmarks against static scanners
- Larger compiled `PAYLOAD_MAX` / `tcp_sendmsg` pre-segmentation (beyond §16 improve-not-close)
- Graceful enforcement beyond SIGKILL (block-call / quarantine-session / alert-only per verdict) — pairs with Phase 2 residual
- GKE validation (EKS already validated)
- Protocol dissectors — only via §21 gate

---

## 6. Out of scope

Not backlog. Named so they are not reopened as features.

| Item | Why | Where |
|---|---|---|
| DoH / DoT | Mitigate with network-layer DNS controls | architecture §13 |
| Sockmap / `sk_skb` first-packet prevent | Blast-radius inversion; sync engine on SKB | §11 → detection_boundary |
| SOCKS5 egress stream scanning | Unstructured TCP + TLS MITM; wrong layer | §11 |
| Unbounded slow-trickle reassembly | Any finite window loses to slower trickle | §11; NamedGap pin |
| Blind / query-pattern EXFIL | Secret never on the wire; wrong detector | §22 |
| Protocol parsers without demand | TCB growth; Wireshark-class risk | §21 |

---

## 7. Cross-cutting hazards

| Hazard | Why it matters |
|---|---|
| **Concurrency / races** | PID reuse, namespace translation, shared-map mutation. `go test -race` is not optional. |
| **Performance vs detection depth** | Every taint/payload/session feature taxes the hot path. Benchmark continuously. |
| **Scope-infinity** | Taint and validation are bottomless. Bound with KnownGap tests. |
| **Blast-radius inversion** | In-kernel block turns bugs from “missed detection” into “broke the host.” |

Highest-risk surface remains LSM/KRSI (Phase 2): prototype on throwaway VMs; never hard-prevent on soft `SUSPICIOUS` — EXFIL-tier only (§1).
