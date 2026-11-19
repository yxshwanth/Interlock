// SPDX-License-Identifier: Apache-2.0

use interlock_engine::decode::{
    decode_candidates_from_args, decode_candidates_from_payload, looks_like_base64, looks_like_hex,
    plausible_decoded, try_base64, try_hex,
};
use serde_json::{json, Value};
use std::path::Path;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

fn attempt(decoded: Option<Vec<u8>>) -> Value {
    json!({
        "decoded_hex": hex(decoded.as_deref().unwrap_or_default()),
        "ok": decoded.is_some(),
    })
}

fn candidates(decoded: Option<Vec<Vec<u8>>>) -> Value {
    json!(decoded.map(|items| items.iter().map(|item| hex(item)).collect::<Vec<_>>()))
}

fn compare(case: &str, field: &str, actual: &Value, expected: &Value) {
    if let (Some(actual), Some(expected)) = (actual.as_object(), expected.as_object()) {
        for (key, value) in actual {
            let path = if field.is_empty() {
                key.clone()
            } else {
                format!("{field}.{key}")
            };
            let want = expected
                .get(key)
                .unwrap_or_else(|| panic!("case {case}, field {path}: missing fixture value"));
            compare(case, &path, value, want);
        }
        for key in expected.keys() {
            assert!(
                actual.contains_key(key),
                "case {case}, field {field}: unexpected key {key}"
            );
        }
    } else {
        assert_eq!(actual, expected, "case {case}, field {field}");
    }
}

#[test]
fn decode_vectors() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../internal/engine/testdata/decode_vectors.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    let vectors: Vec<Value> = serde_json::from_slice(&bytes).expect("decode vectors");
    assert!(!vectors.is_empty(), "decode vectors are empty");
    for expected in vectors {
        let name = expected["name"].as_str().expect("case name");
        let encoded = expected["input_hex"]
            .as_str()
            .unwrap_or_else(|| panic!("case {name}, field input_hex: expected a string"));
        assert!(
            encoded.len().is_multiple_of(2),
            "case {name}, field input_hex: odd length"
        );
        let input: Vec<u8> = encoded
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                    .unwrap_or_else(|| panic!("case {name}, field input_hex: invalid hex"))
            })
            .collect();
        let actual = json!({
            "name": name,
            "input_hex": hex(&input),
            "try_base64": attempt(try_base64(&input)),
            "try_hex": attempt(try_hex(&input)),
            "plausible_decoded": plausible_decoded(&input),
            "looks_like_hex": looks_like_hex(&input),
            "looks_like_base64": looks_like_base64(&input),
            "payload_candidates": candidates(decode_candidates_from_payload(&input)),
            "args_candidates": candidates(decode_candidates_from_args(&input)),
        });
        compare(name, "", &actual, &expected);
    }
}

#[test]
fn go_base64_accepts_unused_bits() {
    assert_eq!(try_base64(b"Zh==").as_deref(), Some(b"f".as_slice()));
    assert_eq!(try_base64(b"Zm9v\nZh").as_deref(), Some(b"foof".as_slice()));
}

#[test]
fn json_leaves_unescape_unicode() {
    use interlock_engine::decode::json_string_leaves;

    let input = br#"{"z":"\u00e9\u4e2d \ud83d\ude00","a":"first","\u0061":"last"}"#;
    assert_eq!(
        json_string_leaves(input),
        Some(vec![b"last".to_vec(), "é中 😀".as_bytes().to_vec()])
    );
}
