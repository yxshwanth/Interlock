# Rust engine port (§76)

The corpus and the vector files generated from the Go engine are the specification. A Rust module is written under its vectors, not before them, and it passes them byte for byte. Values are bytes, not strings: the Go engine slices and compares bytes, so the Rust side takes `&[u8]` wherever Go takes a `string` that may hold arbitrary data.

## Pieces

Status is what is on `main` today.

| Piece | Go source | Vectors (`internal/engine/testdata`) | Rust (`rust/interlock-engine/src`) | Status |
|---|---|---|---|---|
| Canonical encodings | `encoding.go` | `encoding_vectors.json` | `encoding.rs` | done |
| Taint extraction | `taint.go` | `overlap_vectors.json` | `taint.rs` | done |
| Chunking and plain overlap | `chunk.go`, `overlap.go` | `chunk_vectors.json`, `overlap_vectors.json` | `chunk.rs`, `overlap.rs` | done |
| Decode helpers | `decode.go` | `decode_vectors.json` | `decode.rs`, `decode/json.rs` | done |
| Container inspection | `container.go` | `container_vectors.json` | `container.rs` | done |
| Evidence hash chain | `evidence_chain.go` | `evidence_chain_vectors.json` | `evidence.rs` | done |
| Tool tags and path taint | `tagger.go`, `path_taint.go` | `tagger_vectors.json`, `path_taint_vectors.json` | `tagger.rs`, `path_taint.rs`, `path_taint/json.rs` | done |
| JSON leaf joining and the overlap composition | `decode.go`, `overlap.go` | `decode_vectors.json`, `overlap_vectors.json`, `overlap_args_vectors.json` | `decode.rs`, `overlap.rs` | done, except the gzip, brotli, zstd and lz4 forms (blocked on #81) |
| Session state and leg decay | `session_store.go`, `engine.go` | none | `legs.rs` | leg lighting, pruning and clock rewind only |
| Verdict and action classifier | `engine.go`, `bind.go` | none | `verdict.rs`, `bind.rs` | trip classification, action mapping and content bind only |
| Compressor forms | `encoding.go` | none | none | not started, blocked on #81 |

The two partial rows are only the leg decay and trip classification half. Not ported: `IngestResult`, `EvaluateRequest`, the session store, egress reassembly and evidence building. `legs.rs` and `verdict.rs` have unit tests but no vector file.

The compressor forms (gzip, brotli, zstd and lz4, each as base64) wait on an open decision, GitHub issue 81, about how the Rust engine matches them.

The corpus under `internal/corpus/data` is read by the stub loader in `rust/corpus-stub`. It is not yet run through the Rust engine.

## Known differences from Go

- `taint.rs`: patterns use ASCII word boundaries, digits and whitespace as Go does, but case-insensitive matching keeps Unicode simple folding.
- `taint.rs`: mask boundaries count bytes. A cut inside a code point turns each invalid byte into a replacement character.
- `evidence.rs`: raw arguments must be UTF-8. The constructor rejects invalid bytes that Go can keep in a `json.RawMessage`.
- `evidence.rs`: chain verification reads the wire JSON and keeps its number spellings and key order. Go decodes and re-marshals.
- `container.rs`: when a compressed read fills the byte budget, Rust and Go can disagree on whether EOF or corruption landed on the last bytes.
- `container.rs`: a positive depth limit is used as given, so a large custom value is the caller's stack risk.
- `decode.rs`: base64 accepts nonzero unused bits in the last symbol, as Go does, through an explicit config.

## Regenerate a vector file

```
go test ./internal/engine -run <Name>Vectors -update
```

`<Name>` is `Encoding`, `Overlap`, `Chunk`, `Decode`, `Container`, `EvidenceChain`, `Tagger` or `PathTaint`. Review the diff of the JSON before committing it: a changed vector is a changed contract.

## Run the Rust side

From `rust/`:

```
cargo test --workspace --locked
```

CI also runs `cargo fmt --all --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings`.
