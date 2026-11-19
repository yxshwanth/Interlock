# Rust engine port (§76)

The corpus and the vector files generated from the Go engine are the specification. A Rust module is written under its vectors, not before them, and it passes them byte for byte. Values are bytes, not strings: the Go engine slices and compares bytes, so the Rust side takes `&[u8]` wherever Go takes a `string` that may hold arbitrary data.

## Pieces

Status is what is on `main` today.

| Piece | Go source | Vectors (`internal/engine/testdata`) | Rust (`rust/interlock-engine/src`) | Status |
|---|---|---|---|---|
| Canonical encodings | `encoding.go` | `encoding_vectors.json` | `encoding.rs` | done |
| Taint extraction | `taint.go` | `overlap_vectors.json` | `taint.rs` | done |
| Chunking and plain overlap | `chunk.go`, `overlap.go` | `overlap_vectors.json` | none | vectors only |
| Decode helpers | `decode.go` | none | none | not started |
| Container inspection | `container.go` | none | none | not started |
| Evidence hash chain | `evidence_chain.go` | none | none | not started |
| Tool tags and path taint | `tagger.go`, `path_taint.go` | none | none | not started |
| JSON leaf joining and the overlap composition | `decode.go`, `overlap.go` | none | none | not started |
| Session state and leg decay | `session_store.go`, `engine.go` | none | none | not started |
| Verdict and action classifier | `engine.go` | none | none | not started |
| Compressor forms | `encoding.go` | none | none | not started, blocked on #81 |

The compressor forms (gzip, brotli, zstd and lz4, each as base64) wait on an open decision, GitHub issue 81, about how the Rust engine matches them.

The corpus under `internal/corpus/data` is read by the stub loader in `rust/corpus-stub`. It is not yet run through the Rust engine.

## Regenerate a vector file

```
go test ./internal/engine -run <Name>Vectors -update
```

`<Name>` is `Encoding` or `Overlap` today. Review the diff of the JSON before committing it: a changed vector is a changed contract.

## Run the Rust side

From `rust/`:

```
cargo test --workspace --locked
```

CI also runs `cargo fmt --all --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings`.
