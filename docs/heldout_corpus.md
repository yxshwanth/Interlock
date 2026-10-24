# Held-out corpus

The tuned corpus ([`fp_corpus.md`](fp_corpus.md), [`cve_corpus.md`](cve_corpus.md)) was written by the detector's author and used to tune it, so its 100% detection rate says little about attacks nobody thought of. The held-out set is the counterweight. It was written once, run once, and is not allowed to change: `internal/corpus/data/heldout.json`, pinned by sha256 in `heldout_expected.json` together with every outcome.

## Result

| Set | Detection (EXFIL tier) | EXFIL false positives | Any-trip false positives |
|---|---|---|---|
| Tuned | 31/31 (100.0%) | 0/37 | 7/37 |
| Held-out | 14/19 (73.7%, 95% interval 51% to 88%) | 0/16 (95% upper bound 19%) | 0/16 |

Nineteen attacks and sixteen benign flows is a small sample. Read the intervals, not the point estimates. The honest summary is that detection on unseen attacks is meaningfully below the tuned figure, and false positives stayed at zero.

## Misses (reported, not fixed)

| Scenario | What the attacker did | Why it is not caught |
|---|---|---|
| `heldout_mal_uppercased` | Upper-cased the secret | Matching is case-sensitive and upper-casing is not a registered form |
| `heldout_mal_spaced` | Inserted a space every 8 characters | The matcher needs a contiguous run of the secret |
| `heldout_mal_base32` | Encoded in base32 | Base32 is not a registered form |
| `heldout_mal_unicode_escaped` | Wrote the secret as literal `\uXXXX` text | Escape text is not decoded as a form |
| `heldout_mal_two_separate_calls` | Sent two halves in two separate sink calls | Reassembly covers fields of one call and egress fragments, not halves across tool calls |

These fit the boundary already stated in [`detection_boundary.md`](detection_boundary.md): detection is byte and registered-encoding overlap, so a transform with no registered form, or a split the reassembly window does not join, passes. The last row is the one worth a decision, because splitting across calls needs no encoding at all.

Caught despite not being in the tuned set: nested args, arrays, secrets in a URL query and path, URL-safe base64, double hex, a four-way field split, a second secret out of two tickets, an eBPF `sendto` with base64, and a secret buried mid-way in a 700 byte `write`.

## Rules

1. Do not edit `heldout.json`. A test fails if its hash changes.
2. Do not change the engine to make a held-out scenario pass. A test fails if an outcome moves, so a fix surfaces here and must be recorded in this file.
3. To grow the set, add `heldout_v2.json`. Never edit v1.
4. Disclose the limit. The author of the detector also wrote this set, so it measures the author's blind spots only to the degree they differ from the author's tuned examples. The fuller answer is external contributions and captured benign traffic (ROADMAP §83), neither of which exists yet.

To re-pin after an intentional change: `INTERLOCK_HELDOUT_UPDATE=1 go test ./internal/corpus -run TestHeldout`, then review the diff.
