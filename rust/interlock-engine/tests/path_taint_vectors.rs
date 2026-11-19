// SPDX-License-Identifier: Apache-2.0

use interlock_engine::{
    canonical_encodings,
    path_taint::{
        extract_paths_from_tool_args, is_sensitive_resource_path, taint_path_driven_content,
    },
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    sensitive_paths: Vec<SensitivePath>,
    extract_paths: Vec<ExtractPaths>,
    taint: Vec<Taint>,
}

#[derive(Deserialize)]
struct SensitivePath {
    path: String,
    prefixes: Vec<String>,
    result: bool,
}

#[derive(Deserialize)]
struct ExtractPaths {
    args_json: String,
    paths: Vec<String>,
}

#[derive(Deserialize)]
struct Taint {
    content: String,
    path: String,
    source: String,
    seq: u64,
    tainted: Vec<ExpectedValue>,
}

#[derive(Deserialize)]
struct ExpectedValue {
    value_hex: String,
    hash: String,
    preview: String,
    forms: Vec<String>,
    source: String,
    seq: u64,
}

#[test]
fn path_taint_vectors() {
    let vectors: Vectors = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../internal/engine/testdata/path_taint_vectors.json"
    )))
    .expect("path_taint_vectors.json");

    for case in vectors.sensitive_paths {
        assert_eq!(
            is_sensitive_resource_path(&case.path, &case.prefixes),
            case.result,
            "sensitive_paths({:?}, {:?}).result",
            case.path,
            case.prefixes
        );
    }

    for mut case in vectors.extract_paths {
        let mut paths = extract_paths_from_tool_args(&case.args_json);
        paths.sort_unstable();
        case.paths.sort_unstable();
        assert_eq!(
            paths, case.paths,
            "extract_paths({:?}).paths",
            case.args_json
        );
    }

    for case in vectors.taint {
        let name = format!("taint({:?}, seq={})", case.path, case.seq);
        let actual = taint_path_driven_content(&case.content, &case.path, &case.source, case.seq);
        assert_eq!(
            usize::from(actual.is_some()),
            case.tainted.len(),
            "{name}.tainted count"
        );
        for (actual, expected) in actual.into_iter().zip(case.tainted) {
            let value_hex: String = actual
                .value
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(value_hex, expected.value_hex, "{name}.value_hex");
            assert_eq!(actual.hash, expected.hash, "{name}.hash");
            assert_eq!(actual.preview, expected.preview, "{name}.preview");
            assert_eq!(actual.source, expected.source, "{name}.source");
            assert_eq!(actual.seq, expected.seq, "{name}.seq");
            assert!(
                actual.variants.is_empty(),
                "{name}.variants before registration"
            );

            // Go records the compressor forms after the shared canonical forms.
            // Rust compressor support is tracked separately.
            let variants = canonical_encodings(&actual.value);
            let mut forms: Vec<_> = variants
                .iter()
                .map(|variant| variant.form.as_str())
                .collect();
            forms.extend(["gzip_base64", "brotli_base64", "zstd_base64", "lz4_base64"]);
            assert_eq!(forms, expected.forms, "{name}.forms");
        }
    }
}

#[test]
fn taint_cap_splits_utf8_sequence() {
    let cap = 64 * 1024;
    let mut content = "x".repeat(cap - 2);
    content.push_str("✓tail");
    let tainted = taint_path_driven_content(&content, "/file", "read", 0).unwrap();
    assert_eq!(tainted.value, content.as_bytes()[..cap]);
    assert_eq!(tainted.preview, "xxx...xx��");
    assert_eq!(
        tainted.hash,
        "e720e9b0bc83056d98e7d2db1dfd54631c5397090f76084352577bba0a4742af"
    );
}

#[test]
fn extracts_paths_with_go_json_semantics() {
    let args = b"{\"path\":[[\"\\ud800\"],\"\xe2\x82\"],\"file\":\"old\",\"file\":null}";
    assert_eq!(extract_paths_from_tool_args(args), ["�", "��"]);
    assert!(extract_paths_from_tool_args(br#"{"path":"x","n":1e999}"#).is_empty());

    for depth in [10_000, 10_001] {
        let args = format!("{}\"a/b.txt\"{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(
            extract_paths_from_tool_args(args).len(),
            usize::from(depth == 10_000)
        );
    }
}

#[test]
fn taint_trims_around_invalid_utf8() {
    let tainted = taint_path_driven_content(b" \xffabcdef\xe2\x82 \t", "/file", "read", 0).unwrap();
    assert_eq!(tainted.value, b"\xffabcdef\xe2\x82");
    assert_eq!(tainted.preview, "�a...��");
}
