// SPDX-License-Identifier: Apache-2.0

use interlock_engine::canonical_encodings;
use serde_json::Value;

const FORM_ORDER: [&str; 9] = [
    "literal",
    "base64",
    "hex",
    "url_encoded",
    "reversed",
    "base64_hex",
    "hex_base64",
    "base64_url",
    "base64_reversed",
];

#[test]
fn matches_go_encoding_vectors() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../internal/engine/testdata/encoding_vectors.json"
    ));
    let cases: Vec<Value> = serde_json::from_str(fixture).expect("parse Go encoding vectors");
    for (index, case) in cases.iter().enumerate() {
        let input = decode_hex(&case["input_hex"], index, "input_hex");
        let expected = case["forms"]
            .as_object()
            .unwrap_or_else(|| panic!("input {index}: expected a forms object"));
        let actual = canonical_encodings(&input);
        let order = if input.is_empty() {
            &[][..]
        } else {
            &FORM_ORDER[..]
        };
        assert_eq!(
            actual
                .iter()
                .map(|variant| variant.form.as_str())
                .collect::<Vec<_>>(),
            order,
            "input {index}: form order"
        );
        assert_eq!(
            actual.len(),
            expected.len(),
            "input {index}: fixture form count"
        );
        for variant in actual {
            let form = variant.form.as_str();
            let value = expected
                .get(form)
                .unwrap_or_else(|| panic!("input {index}: missing form {form}"));
            assert_eq!(
                variant.value,
                decode_hex(value, index, form),
                "input {index}: form {form}"
            );
        }
    }
}

fn decode_hex(value: &Value, index: usize, form: &str) -> Vec<u8> {
    let hex = value
        .as_str()
        .unwrap_or_else(|| panic!("input {index}: expected hex string for {form}"));
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    assert!(
        remainder.is_empty(),
        "input {index}: odd hex length for {form}"
    );
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("input {index}: invalid hex digit for {form}"),
    };
    pairs
        .iter()
        .map(|pair| digit(pair[0]) << 4 | digit(pair[1]))
        .collect()
}
