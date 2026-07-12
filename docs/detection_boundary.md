# Interlock detection boundary

What Interlock catches at runtime, what it deliberately does not, and why.
This is the **detection-scope** document for adopters and reviewers — distinct
from a full threat model *of Interlock itself* (least-privilege / tamper
resistance of the TCB): [`threat_model.md`](threat_model.md).

Measured rates and scenario inventory: [`fp_corpus.md`](fp_corpus.md).
Engine gates: [`architecture.md`](architecture.md) §7.

---

## What Interlock is for

Interlock is a **runtime behavioral firewall** for MCP-connected agents. It
correlates session activity across two planes (MCP proxy + eBPF) and trips when
a session looks like Simon Willison's lethal trifecta turning into exfiltration.

| Verdict | Meaning | Hard enforcement (`enforcement: block` / Variant B) |
|---|---|---|
| **EXFIL** (0.95) | A registered tainted secret appears in a sink call or egress payload (literal or canonical encoding) | Yes — `prevented` / `contained_by_kill` |
| **SUSPICIOUS** (0.60) | All three trifecta legs lit **and** untrusted content shares a long byte substring with the sink | No — evidence + `allowed_monitor` / `detected_only` |

EXFIL is the bar for "we proved a secret moved." SUSPICIOUS is a soft signal
for "this session has the shape of risk and the sink is content-bound to
untrusted input" — tuned for low uninstall-risk after ROADMAP §1.

---

## What it catches (programmatic exfil)

Pinned by non-gap malicious corpus scenarios (must stay at 100% EXFIL-tier):

- **Literal secret** in `external_sink` tool args (Variant A)
- **Canonical encodings** — base64, hex, URL, reversal, closed depth-2 nests, `gzip_base64`
- **Same-call JSON string reassembly** (secret split across fields in one tools/call)
- **Cross-call / paginated secret splits** — abutting halves across sensitive results via fragment buffer (`malicious_proxy_a_cross_call_split`)
- **Secrets outside `content[].text`** — bounded string-leaf walk (`malicious_proxy_a_secret_outside_content_text`)
- **Alternate sink tools** on an `external_sink` server (`http_post` as well as `send_message`)
- **Busy-session late exfil** — secret read early, many unrelated tool calls and benign sinks, then late overlap (`malicious_proxy_a_noisy_busy_session_late_exfil`); taint is retained even when sticky legs decay
- **Variant B / sensor** — write/sendto/DNS payload overlap (including near end of 512-byte window); sensor `openat` seed + write EXFIL

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
| Depth-4+ encoding nests (beyond recursive decoder) | sink-path decoder caps at depth-3; deeper nests remain out of scope |
| Non-gzip compressors / ciphers | `malicious_gap_non_gzip_compressor` |
| eBPF payload past capture window | `malicious_gap_payload_truncated` |
| Untagged write tool on a sensitive server | `malicious_gap_untagged_tool_on_sensitive_server` |
| Semantic / paraphrased exfil | `malicious_gap_semantic_paraphrase_exfil` |

Closing a gap means flipping the scenario out of KnownGap and keeping EXFIL-tier
FP at 0% on the benign corpus.

---

## Operator implications

- **Tag every egress/write tool** as `external_sink` (do not rely on server
  co-location). See Option C in [`architecture.md`](architecture.md) §7.
- **Fetch-heavy agents** will see soft-SUSPICIOUS noise on long quoted blurbs —
  raise `trifecta.content_bind_min_len` or narrow `untrusted_origins`; do not
  hard-block that class.
- **Semantic exfil** needs complementary controls; Interlock will not pretend to
  "understand" outbound prose.
- **Regenerate numbers** after detection changes: `make fp-corpus`,
  `go test ./internal/corpus/...`.

---

## Relationship to other docs

| Doc | Role |
|---|---|
| This file | Detection boundary — attack classes in/out of scope |
| [`fp_corpus.md`](fp_corpus.md) | Measured detection / FP rates |
| [`architecture.md`](architecture.md) | Mechanisms (legs, overlap, bind, decay) |
| [`SECURITY.md`](../SECURITY.md) | Vulnerability reporting; points here for defense scope |
| [`threat_model.md`](threat_model.md) | Threats *against Interlock* (root, eBPF, RBAC, bridge, evidence integrity) |
| [`reproducible_builds.md`](reproducible_builds.md) | Signed tags, checksummed binaries, BPF builder |
