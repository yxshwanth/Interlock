// SPDX-License-Identifier: Apache-2.0

use interlock_engine::{
    check_overlap_string, contiguous_chunks, extract_tainted_values, shannon_entropy, OverlapHit,
};
use serde_json::Value;

const PENDING: &[(&str, &str)] = &[
    ("hex_of_hex", "recursive decoding"),
    ("base64_nest_3", "recursive decoding"),
    ("gzip_base64", "compressor form"),
];

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "odd-length fixture hex");
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("fixture hex byte"))
        .collect()
}

#[test]
fn matches_go_overlap_vectors() {
    let fixture = include_str!("../../../internal/engine/testdata/overlap_vectors.json");
    let cases: Vec<Value> = serde_json::from_str(fixture).expect("parse Go overlap vectors");
    let mut pending_seen = 0;
    for case in &cases {
        let name = case["name"].as_str().expect("case name");
        let tainted = extract_tainted_values(
            case["result_text"].as_str().expect("result text"),
            case["source"].as_str().expect("source"),
            case["seq"].as_u64().expect("sequence number"),
        );
        let expected = case["tainted"].as_array().expect("tainted values");
        assert_eq!(tainted.len(), expected.len(), "{name}: tainted count");
        for (index, (actual, expected)) in tainted.iter().zip(expected).enumerate() {
            assert_eq!(
                actual.chunks.len(),
                expected["chunk_count"],
                "{name}[{index}]: chunk count"
            );
        }

        let payload = decode_hex(case["payload_hex"].as_str().expect("payload hex"));
        let actual = check_overlap_string(&tainted, &payload);
        let hit = &case["hit"];
        let expected = (!hit.is_null()).then(|| OverlapHit {
            tainted_hash: hit["tainted_hash"].as_str().expect("hit hash"),
            preview: hit["preview"].as_str().expect("hit preview"),
            match_form: hit["match_form"].as_str().expect("hit form"),
        });
        let unsupported = expected.as_ref().and_then(|hit| {
            let form = hit.match_form;
            if form.starts_with("decoded_") {
                Some("recursive decoding")
            } else if form.starts_with("container_") {
                Some("container descent")
            } else if form == "gzip_base64" {
                Some("compressor form")
            } else {
                None
            }
        });
        let pending = PENDING.iter().find(|&&(case, _)| case == name);
        assert_eq!(pending.map(|&(_, reason)| reason), unsupported, "{name}");
        if let Some((_, reason)) = pending {
            pending_seen += 1;
            assert_ne!(actual, expected, "{name}: now passes ({reason})");
            assert_eq!(actual, None, "{name}: unexpected plain hit");
        } else {
            assert_eq!(actual, expected, "{name}");
        }
    }
    assert_eq!(pending_seen, PENDING.len(), "pending case count");
    for (name, _) in PENDING {
        assert_eq!(
            cases.iter().filter(|case| case["name"] == *name).count(),
            1,
            "{name}: pending case must occur exactly once"
        );
    }
}

#[test]
fn matches_go_chunk_vectors() {
    let fixture = include_str!("../../../internal/engine/testdata/chunk_vectors.json");
    let cases: Vec<Value> = serde_json::from_str(fixture).expect("parse Go chunk vectors");
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let input = decode_hex(case["input_hex"].as_str().expect("input hex"));
        let n = case["n"].as_u64().expect("chunk size") as usize;
        let min_len = case["min_len"].as_u64().expect("minimum length") as usize;
        let actual = contiguous_chunks(&input, n, min_len);
        let expected = case["chunks"].as_array().expect("chunks");
        assert_eq!(actual.len(), expected.len(), "{name}: chunk count");
        for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
            assert_eq!(actual.form, expected["form"], "{name}[{index}]: form");
            let value = decode_hex(expected["value_hex"].as_str().expect("chunk hex"));
            assert_eq!(actual.value, value, "{name}[{index}]: bytes");
        }

        // The same three inputs also pin chunk admission in the Go fixture.
        let ordering = shannon_entropy(&input).total_cmp(&3.0);
        match name {
            "below_floor" => assert!(ordering.is_lt()),
            "at_floor" => assert!(ordering.is_eq()),
            "above_floor" => assert!(ordering.is_gt()),
            _ => {}
        }
    }
}
