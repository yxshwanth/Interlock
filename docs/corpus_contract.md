# Corpus contract

The corpus is the specification of Interlock's detection behavior and the acceptance test for any other implementation of it, including the Rust port. It lives in data, not code: [`internal/corpus/data/`](../internal/corpus/data/).

| File | Contents |
|---|---|
| `malicious.json`, `benign.json` | Self-authored scenarios, replayed against profile `fp` (43 and 37) |
| `cve.json` | Reconstructions of published MCP CVEs, replayed against profile `cve` (16) |
| `heldout.json` | Frozen held-out scenarios, never tuned against (35); see [`heldout_corpus.md`](heldout_corpus.md) |
| `profiles.json` | The fixture config each profile replays against: servers, their tags, tool tags |
| `gap_tags.json` | The closed set of reasons a scenario may be a known gap |
| `heldout_expected.json` | The held-out file's sha256 and every pinned outcome |

## Scenario

A scenario is an id, a category (`malicious` or `benign`), a variant naming the detection plane (`proxy_variant_a`, `ebpf_variant_b`, `sensor_variant_b`), optional config switches (`enforcement`, `vault_enabled`, `vault_authorize`, `inherit_sink_suspicion`, `sink_suspicion_allowlist`, `max_decode_depth`), the gap fields, and an ordered list of steps. A fresh engine and session store replay the steps of one scenario; nothing is shared between scenarios.

A step is a tagged union on `kind`:

| kind | Fields used | Engine call |
|---|---|---|
| `result` | `session_id`, `seq`, `direction`, `method`, `tool_name`, `server_id`, `result` | `IngestResult` |
| `request` | the same, with `tool_args` | `EvaluateRequest` |
| `syscall` | `session_id`, `ts_mono_ns`, `pid`, `comm`, `syscall`, `dest_ip`, `dest_port`, `path`, `payload` | `IngestSyscall` |
| `syscall_sensor` | the same, plus `file_contents` | `IngestSyscallSensor` |
| `advance_time` | `session_id`, `advance_by` (a duration such as `31m`) | rewinds leg clocks |

`result` and `tool_args` are JSON values. `payload` and `file_contents` are text; when the bytes are not valid UTF-8 the same field with a `_b64` suffix carries them as base64. Unknown fields are an error in every language.

## What an implementation must reproduce

For every scenario, the verdicts it produces in order and the scored outcome. The outcome rules are in `runner.go` (`classify`): a non-gap malicious scenario must reach EXFIL, a benign one must never reach EXFIL, and a known gap must miss EXFIL (reaching it is reported as a bonus catch). The published numbers in [`fp_corpus.md`](fp_corpus.md) and [`cve_corpus.md`](cve_corpus.md) are generated from these files and must not change when the implementation changes.

## Gap tags

Every `known_gap` scenario carries a `gap_tag` from `gap_tags.json`, and every tag must be used. `TestData_GapTagsAreClosedAndUsed` enforces both, so a new reason is a deliberate edit to the closed set.

## Rules for changing the data

1. Ids are stable and unique across all files.
2. `seq` is an ordering label for humans and evidence output. Its numbering is not part of the contract.
3. The held-out files are append-only. See the rules in [`heldout_corpus.md`](heldout_corpus.md).
4. A change to `malicious.json`, `benign.json` or `cve.json` that moves a published number regenerates the report (`make fp-corpus cve-corpus`) in the same pull request.

## Status

The Go runner (`internal/corpus`) and a stub Rust loader (`rust/corpus-stub`, run in CI) read the same files. The stub proves the format parses in a second language with unknown fields rejected; it does not replay scenarios. That is the first job of the Rust engine port (ROADMAP §76).

The report generators (`report.go`, `cve_report.go`) stay in Go for now and consume replay results. Moving them into a per-language runner is only worth doing once there are two runners producing results to compare.
