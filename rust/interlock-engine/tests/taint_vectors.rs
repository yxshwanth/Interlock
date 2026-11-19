// SPDX-License-Identifier: Apache-2.0

use interlock_engine::extract_tainted_values;
use serde_json::Value;

#[test]
fn matches_go_taint_vectors() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../internal/engine/testdata/overlap_vectors.json"
    ));
    let cases: Vec<Value> = serde_json::from_str(fixture).expect("parse Go overlap vectors");
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let text = |field: &str| {
            case[field]
                .as_str()
                .unwrap_or_else(|| panic!("{name}: expected string for {field}"))
        };
        let seq = case["seq"]
            .as_u64()
            .unwrap_or_else(|| panic!("{name}: expected unsigned seq"));
        let expected = case["tainted"]
            .as_array()
            .unwrap_or_else(|| panic!("{name}: expected tainted array"));
        let actual = extract_tainted_values(text("result_text"), text("source"), seq);
        assert_eq!(actual.len(), expected.len(), "{name}: tainted count");
        for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
            let hex: String = actual
                .value
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(hex, expected["value_hex"], "{name}[{index}]: value_hex");
            assert_eq!(actual.hash, expected["hash"], "{name}[{index}]: hash");
            assert_eq!(
                actual.preview, expected["preview"],
                "{name}[{index}]: preview"
            );
            assert_eq!(actual.source, expected["source"], "{name}[{index}]: source");
            assert_eq!(actual.seq, expected["seq"], "{name}[{index}]: seq");
            // The encoding port provides the nine non-compressor forms.
            let forms = expected["forms"]
                .as_array()
                .unwrap_or_else(|| panic!("{name}[{index}]: expected forms array"))
                .iter()
                .map(|form| {
                    form.as_str()
                        .unwrap_or_else(|| panic!("{name}[{index}]: expected form name"))
                })
                .filter(|form| {
                    !matches!(
                        *form,
                        "gzip_base64" | "brotli_base64" | "zstd_base64" | "lz4_base64"
                    )
                })
                .collect::<Vec<_>>();
            let actual_forms = actual
                .variants
                .iter()
                .map(|variant| variant.form.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual_forms, forms, "{name}[{index}]: forms");
        }
    }
}

#[test]
fn matches_go_ascii_boundaries_and_unicode_case_folding() {
    let result = "toKen: aK01234567890123456789 ésk-live-0123456789é";
    let values = extract_tainted_values(result, "test", 1);
    assert_eq!(values.len(), 2);
    assert_eq!(values[0].value, b"sk-live-0123456789");
    assert_eq!(values[1].value, "aK01234567890123456789".as_bytes());
    assert_eq!(values[1].preview, "a��...6789");
}
