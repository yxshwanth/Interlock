# Interlock detection boundary

What Interlock catches at runtime, what it deliberately does not, and why.
This is the **detection-scope** document for adopters and reviewers — distinct
from a full threat model *of Interlock itself* (least-privilege / tamper
resistance of the TCB): [`threat_model.md`](threat_model.md).

Measured rates and scenario inventory: [`fp_corpus.md`](fp_corpus.md) (self-authored corpus) and [`cve_corpus.md`](cve_corpus.md) (reconstructed from published, third-party-disclosed MCP CVEs — the same catches/gaps below, tested against attacks Interlock wasn't built to pass).
Engine gates: [`architecture.md`](architecture.md) §7.

---

## What Interlock is for

Interlock is a **runtime behavioral firewall** for MCP-connected agents. It
correlates session activity across two planes (MCP proxy + eBPF) and trips when
a session looks like Simon Willison's lethal trifecta turning into exfiltration.

| Verdict | Meaning | Hard enforcement (`enforcement: block` / Variant B) |
|---|---|---|
| **EXFIL** (0.95) | A registered tainted secret appears in a sink call or egress payload (literal or canonical encoding) | Yes — `prevented` / `contained_by_kill` |
| **SUSPICIOUS** (0.60) | All three trifecta legs lit, plus (if the sink event carries a payload/args channel) untrusted content shares a long byte substring with it — a bare `connect()` has no such channel, so `AllLit` alone is enough there | No — evidence + `allowed_monitor` / `detected_only` |

EXFIL is the bar for "we proved a secret moved." SUSPICIOUS is a soft signal
for "this session has the shape of risk" — content-bound to untrusted input
when the sink has content to bind against, or a bare anomalous `connect()`
when it doesn't. [`docs/cve_corpus.md`](cve_corpus.md) found the connect-only
case had been silently deleted as a side effect of the ROADMAP §1
content-binding fix (an empty sink string always failed the bind check,
regardless of leg state) — now fixed.

---

## What it catches (programmatic exfil)

Pinned by non-gap malicious corpus scenarios (must stay at 100% EXFIL-tier):

- **Literal secret** in `external_sink` tool args (Variant A)
- **Canonical encodings** — base64, hex, URL, reversal, closed depth-2 nests, `gzip_base64` / `brotli_base64` / `zstd_base64` / `lz4_base64`
- **Long-secret chunk overlap** — when a tainted value is ≥64 bytes, contiguous 32-byte body chunks (PEM/PuTTY armor stripped) are searched in sink args and egress payloads (`match_form=chunk_32`); closes truncated-capture cases that still contain a body chunk
- **Token vaulting (opt-in `vault.enabled`)** — agent-visible sensitive results rewrite to `ilk.vault.*` dummies; authorized sinks detokenize then overlap-scan (`malicious_proxy_a_vault_authorized_wrong_dest`)
- **Same-call JSON string reassembly** (secret split across fields in one tools/call)
- **Cross-call / paginated secret splits** — abutting halves across sensitive results via fragment buffer (`malicious_proxy_a_cross_call_split`)
- **Secrets outside `content[].text`** — bounded string-leaf walk (`malicious_proxy_a_secret_outside_content_text`)
- **Alternate sink tools** on an `external_sink` server (`http_post` as well as `send_message`)
- **Busy-session late exfil** — secret read early, many unrelated tool calls and benign sinks, then late overlap (`malicious_proxy_a_noisy_busy_session_late_exfil`); taint is retained even when sticky legs decay
- **Variant B / sensor** — write/sendto/DNS payload overlap (including near end of the capture window; default **1024** bytes = `PAYLOAD_MAX`); sensor `openat` seed + write EXFIL; dual ringbufs so connect floods cannot drop EXFIL/`lsm_deny` evidence
- **Repeat connect() after EXFIL confirmed** (opt-in `ebpf.lsm_enforce`) — further `connect()` denied in-kernel (`prevented`)
- **Fail-closed health trips** (opt-in `fail_closed.enabled`) — not a detection class, but blocks monitored egress when Interlock itself is degraded (ringbuf drop rate / sink failure / panic)

Complementary soft signal (not hard-block):

- **Content-bound untrusted → sink** paraphrases of *attacker instructions* or product blurbs (natural fetch-then-quote) — soft SUSPICIOUS only

---

## What it does not catch (and why)

These are intentional or catalogued boundaries — each should have a corpus
KnownGap and/or unit `*_KnownGap` where applicable.

### Semantic / paraphrased exfil (the elephant)

**Not detected at EXFIL tier:** the agent reads a secret, then sends natural
language that *conveys* the credential without any registered byte form —

> "The live Stripe key from that ticket starts with sk-live-51Tx and ends in abcdef…"

Pinned: `malicious_gap_semantic_paraphrase_exfil`. Benign twin:
`benign_proxy_a_paraphrase_summary` (TN — no overlap, no content-bind).

**Why:** Interlock's proof is **overlap against precomputed encodings**, not
LLM-judged meaning. Semantic detection would require trusting another model on
the hot path, exploding FP surface, and still losing to clever rewrites. The
product choice is: be excellent and honest at programmable exfil; name the
semantic gap; leave meaning-level DLP to complementary controls (human review,
outbound DLP, allowlists).

Soft SUSPICIOUS may still fire if untrusted content and the sink share a long
*literal* substring — that is byte-bind, not understanding.

### Other catalogued gaps

| Gap | Corpus / test pin |
|---|---|
| Depth-6+ encoding nests (beyond clamp `[3,5]`) | Default `max_decode_depth=5` closes five-layer nests (`malicious_proxy_a_depth4_nested`, `cve_2025_65513_fetch_ssrf_cloud_metadata_depth5_nest`); FP curve at 3/4/5 stayed 0% EXFIL (`TestCorpus_DecodeDepthFPCurve`) |
| Custom ciphers (XOR stand-in) | `malicious_gap_custom_cipher` |
| Container inspect hard-cap abort (zip-bomb / max_parts / depth / encrypted) | `malicious_gap_container_inspect_bomb` — aborted walks never EXFIL; soft `SUSPICIOUS` may fire with `container_inspect_limit` when AllLit (ROADMAP §20). Extracted-cell + sink ZIP/zlib on inspected bytes are closed (`malicious_proxy_a_extracted_from_xlsx_container`, `malicious_proxy_a_sink_zip_contains_secret`, `malicious_ebpf_b_zlib_wrapped_secret`) |
| Git pack / pkt-line / structured-protocol wire (Named §21) | `cve_2025_68143_mcp_git_push_wire_protocol_gap` — §20 closes flat zlib/ZIP on ToolArgs/PayloadExcerpt; framing outside those surfaces (git smart HTTP/SSH, HTTP `Content-Encoding` body, SMTP DATA) is demand-gated — no dissector shipped |
| Blind side-channel / boolean inference (rejected §22) | `cve_2025_66335_doris_blind_sql_injection_exfil_gap` — secret bytes never observed; EXFIL unreachable by construction; do not build query-pattern anomaly as EXFIL |
| Finite egress reassembly window | Normal DNS/write fragmentation is now closed (`cve_2025_65720_gpt_researcher_dns_fragmented_exfil`), but fragments slower than `trifecta.egress_fragment_max_age` or split across different destinations remain misses (`malicious_gap_egress_slow_trickle`, `malicious_gap_egress_cross_destination_split`) |
| Authorized-sink vault rehydration | When `vault.authorize` lists a tool, Interlock rehydrates the real secret after allow — a wrong allow still forwards the secret (`malicious_proxy_a_vault_authorized_wrong_dest` proves wrong-dest EXFIL; correct-dest forward is by design) |
| eBPF payload past capture window (zero secret bytes in excerpt) | Permanent KnownGap even at default 1024 (= `PAYLOAD_MAX`): `malicious_gap_payload_truncated`. `payload_capture_bytes` only reduces from the compiled ceiling |
| Untagged write tool on a sensitive server (default Option C) | `malicious_gap_untagged_tool_on_sensitive_server`; closed under opt-in inherit — exemption is **only** `sink_suspicion_allowlist` (`internal_note: []` still inherits): `malicious_proxy_a_untagged_inherit_sink` |
| Semantic / paraphrased exfil | `malicious_gap_semantic_paraphrase_exfil` |
| First EXFIL-carrying packet is never kernel-prevented — `connect()` has no payload, so even with `ebpf.lsm_enforce` on, detection lands after `connect()` succeeds; only *repeat* attempts get `prevented` | `TestIngestSyscall_FirstPacketStillContained_KnownGap` |

Closing a gap means flipping the scenario out of KnownGap and keeping EXFIL-tier
FP at 0% on the benign corpus.

---

## Considered and rejected

Mechanisms that were evaluated and **will not be built** (or will not reach EXFIL).
Naming the refusal is the product discipline — see ROADMAP §11 / §22.

| Mechanism | Why rejected |
|---|---|
| **Sockmap / `sk_skb` inline first-packet prevention** | Turns Interlock into an inline kernel data-path proxy; maximal blast-radius inversion; runs overlap synchronously per-SKB, breaking async-off-ringbuf design and the sub-millisecond performance story. First-packet limit stays an architectural boundary (`TestIngestSyscall_FirstPacketStillContained_KnownGap`). |
| **SOCKS5 egress stream scanning** | Inline interception on unstructured TCP (message boundaries + TLS MITM) to solve egress already inspected at the tool-call layer. Netns (§7) severs uncontrolled egress; controlled egress is the JSON-RPC path. |
| **Unbounded egress fragment reassembly** | Any finite window is defeated by going slower. Bounded reassembly shipped (§19); slow-trickle past `egress_fragment_max_age` remains NamedGap (`malicious_gap_egress_slow_trickle`) — not a claim of closure. |
| **Blind side-channel / query-pattern → EXFIL** (ROADMAP §22) | Secret is inferred from booleans / timing, never transmitted. Byte-overlap cannot prove what was never on the wire. Sequence-anomaly detection is a different FP-heavy product; if ever researched, SUSPICIOUS-dark only (like §12), never EXFIL. Pin: `cve_2025_66335_doris_blind_sql_injection_exfil_gap`. |

### Named / demand-gated (not rejected forever)

| Mechanism | Status |
|---|---|
| **Protocol-aware egress parsers** (git pkt-line / pack, HTTP body + `Content-Encoding`, SMTP DATA) — ROADMAP §21 | **Named boundary.** Would close family-at-a-time structured-protocol exfil, but each dissector grows untrusted-input TCB (Wireshark-class risk) for poor effort/gap ratio. Build **only** if a deployment shows that MCP family in production. Until then: `cve_2025_68143_mcp_git_push_wire_protocol_gap` stays Missed. §20 already covers flat zlib/ZIP when bytes appear in ToolArgs/PayloadExcerpt. |

---

## Operator implications

- **Tag every egress/write tool** as `external_sink` (do not rely on server
  co-location). See Option C in [`architecture.md`](architecture.md) §7.
- **Fetch-heavy agents** will see soft-SUSPICIOUS noise on long quoted blurbs —
  raise `trifecta.content_bind_min_len` or narrow `untrusted_origins`; do not
  hard-block that class.
- **Token vaulting (`vault.enabled`, default off)** replaces extracted secrets
  with dummies in agent-visible results. Detokenization is off unless
  `vault.authorize` lists the sink tool. Authorized sinks still receive the
  real secret after allow — if the detector wrongly allows, Interlock forwards
  it. Sensor-only / DaemonSet path has no agent-visible rewrite surface.
- **Semantic exfil** needs complementary controls; Interlock will not pretend to
  "understand" outbound prose.
- **`ebpf.lsm_enforce` (opt-in, default off)** requires `CONFIG_BPF_LSM=y` and
  `"bpf"` active in `/sys/kernel/security/lsm` — not on by default on stock
  distro kernels; see [`deploy/k8s/PRIVILEGE.md`](../deploy/k8s/PRIVILEGE.md).
  Attach failure fails soft (logged `[SECURITY]` warning); kill-on-detect is
  unaffected either way. Sensor-mode `fail_closed.enabled` requires a live LSM
  attach (config validation).
- **Regenerate numbers** after detection changes: `make fp-corpus`,
  `go test ./internal/corpus/...`.
- **Evidence integrity:** `make verify-evidence` checks the hash chain; ship
  SIEM/webhook off-node for durability beyond local FS.

---

## Relationship to other docs

| Doc | Role |
|---|---|
| This file | Detection boundary — attack classes in/out of scope |
| [`fp_corpus.md`](fp_corpus.md) | Measured detection / FP rates (self-authored corpus) |
| [`cve_corpus.md`](cve_corpus.md) | Detection rate against reconstructed, published, third-party-disclosed CVEs |
| [`architecture.md`](architecture.md) | Mechanisms (legs, overlap, bind, decay) |
| [`SECURITY.md`](../SECURITY.md) | Vulnerability reporting; points here for defense scope |
| [`threat_model.md`](threat_model.md) | Threats *against Interlock* (root, eBPF, RBAC, bridge, evidence integrity) |
| [`reproducible_builds.md`](reproducible_builds.md) | Signed tags, checksummed binaries, BPF builder |
