// SPDX-License-Identifier: Apache-2.0

use interlock_engine::{default_container_limits, inspect_container, looks_like_container};
use serde_json::Value;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../internal/engine/testdata/container_vectors.json"
));

#[test]
fn matches_go_container_vectors() {
    let cases: Vec<Value> = serde_json::from_str(VECTORS).expect("parse Go container vectors");
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let input = decode_hex(&case["input_hex"], name, "input_hex");
        let limits = &case["limits"];
        let number = |field: &str| {
            limits[field]
                .as_i64()
                .and_then(|n| isize::try_from(n).ok())
                .unwrap_or_else(|| panic!("{name}: invalid limits.{field}"))
        };
        let mut config = default_container_limits();
        config.enabled = limits["enabled"]
            .as_bool()
            .unwrap_or_else(|| panic!("{name}: invalid limits.enabled"));
        config.max_decompressed_bytes = number("max_decompressed_bytes");
        config.max_descent_depth = number("max_descent_depth");
        config.max_parts = number("max_parts");

        let result = inspect_container(&input, &config);
        assert_eq!(
            Value::from(looks_like_container(&input)),
            case["looks_like_container"],
            "{name}: looks_like_container"
        );
        assert_eq!(
            Value::from(result.abort.as_str()),
            case["abort"],
            "{name}: abort"
        );
        assert_eq!(Value::from(result.bytes), case["bytes"], "{name}: bytes");
        assert_eq!(
            Value::from(result.parts_n),
            case["parts_n"],
            "{name}: parts_n"
        );
        let expected = case["parts_hex"]
            .as_array()
            .unwrap_or_else(|| panic!("{name}: invalid parts_hex"));
        assert_eq!(
            result.parts.len(),
            expected.len(),
            "{name}: parts_hex length"
        );
        for (index, (actual, expected)) in result.parts.iter().zip(expected).enumerate() {
            let field = format!("parts_hex[{index}]");
            assert_eq!(
                *actual,
                decode_hex(expected, name, &field),
                "{name}: {field}"
            );
        }
    }
}

#[test]
fn inspects_random_and_truncated_containers_without_panicking() {
    let limits = default_container_limits();
    let cases: Vec<Value> = serde_json::from_str(VECTORS).expect("parse Go container vectors");
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let input = decode_hex(&case["input_hex"], name, "input_hex");
        for end in 0..input.len() {
            inspect_container(&input[..end], &limits);
        }
    }

    let mut state = 0x243f_6a88_u32;
    for _ in 0..64 {
        let mut input = [0; 600];
        for byte in &mut input {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state.to_le_bytes()[0];
        }
        for (offset, signature) in [
            (0, &b"PK\x03\x04"[..]),
            (0, &b"\x1f\x8b"[..]),
            (0, &b"\x78\x9c"[..]),
            (257, &b"ustar"[..]),
        ] {
            let mut container = input;
            container[offset..offset + signature.len()].copy_from_slice(signature);
            inspect_container(&container, &limits);
        }
    }
}

fn decode_hex(value: &Value, name: &str, field: &str) -> Vec<u8> {
    let hex = value
        .as_str()
        .unwrap_or_else(|| panic!("{name}: expected hex string for {field}"));
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "{name}: odd hex length for {field}");
    let digit = |byte| match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("{name}: invalid hex digit for {field}"),
    };
    pairs
        .iter()
        .map(|pair| digit(pair[0]) << 4 | digit(pair[1]))
        .collect()
}
