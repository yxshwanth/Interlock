// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, time::Duration};

use interlock_engine::{
    check_overlap_limited, check_overlap_payload_limited, default_container_limits,
    extract_tainted_values, ContainerLimits, OverlapHit,
};
use serde::Deserialize;

const PENDING: &[(&str, &str)] = &[(
    "payload_gzip_base64_canonical",
    "gzip_base64 canonical form (#81)",
)];

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    result_text: String,
    source: String,
    seq: u64,
    kind: Kind,
    args_json: String,
    payload_hex: String,
    limits: Limits,
    hit: Option<Hit>,
    abort: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Args,
    Payload,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Limits {
    Named(DefaultLimits),
    Explicit {
        enabled: bool,
        max_decompressed_bytes: isize,
        max_descent_depth: isize,
        max_parts: isize,
        max_inspect: i64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DefaultLimits {
    Default,
}

impl Limits {
    fn expand(&self) -> ContainerLimits {
        match *self {
            Self::Named(DefaultLimits::Default) => default_container_limits(),
            Self::Explicit {
                enabled,
                max_decompressed_bytes,
                max_descent_depth,
                max_parts,
                max_inspect,
            } => ContainerLimits {
                enabled,
                max_decompressed_bytes,
                max_descent_depth,
                max_parts,
                max_inspect: Duration::from_nanos(u64::try_from(max_inspect).unwrap_or(0)),
            },
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Hit {
    tainted_hash: String,
    preview: String,
    where_found: String,
    match_form: String,
}

impl From<OverlapHit<'_>> for Hit {
    fn from(hit: OverlapHit<'_>) -> Self {
        Self {
            tainted_hash: hit.tainted_hash.to_owned(),
            preview: hit.preview.to_owned(),
            where_found: hit.where_found.to_owned(),
            match_form: hit.match_form.into_owned(),
        }
    }
}

#[test]
fn matches_go_overlap_args_vectors() {
    let fixture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../internal/engine/testdata/overlap_args_vectors.json"
    ));
    let cases: Vec<Case> =
        serde_json::from_str(fixture).expect("parse Go sink-args overlap vectors");
    let mut seen = HashSet::new();
    for case in &cases {
        let context = || format!("{} input: {case:?}", case.name);
        assert!(seen.insert(case.name.as_str()), "duplicate {}", context());

        // Extraction in Rust also computes the canonical variants and default
        // chunks, which Go attaches when adding the values to a fresh session.
        let tainted = extract_tainted_values(&case.result_text, &case.source, case.seq);
        let limits = case.limits.expand();
        let (hit, abort) = match case.kind {
            Kind::Args => check_overlap_limited(&tainted, case.args_json.as_bytes(), &limits),
            Kind::Payload => {
                let hex = &case.payload_hex;
                assert!(
                    hex.is_ascii() && hex.len() % 2 == 0,
                    "payload_hex: {}",
                    context()
                );
                let payload: Vec<_> = (0..hex.len())
                    .step_by(2)
                    .map(|i| {
                        u8::from_str_radix(&hex[i..i + 2], 16)
                            .unwrap_or_else(|err| panic!("payload_hex: {err}; {}", context()))
                    })
                    .collect();
                check_overlap_payload_limited(&tainted, &payload, &limits)
            }
        };
        assert_eq!(abort.as_str(), case.abort, "abort: {}", context());
        let actual = hit.map(Hit::from);
        let pending = PENDING.iter().find(|&&(name, _)| name == case.name);
        let expected = case.hit.as_ref();
        if let Some((_, reason)) = pending {
            assert_ne!(
                actual.as_ref(),
                expected,
                "now passes ({reason}): {}",
                context()
            );
            assert_eq!(
                expected.map(|hit| hit.match_form.as_str()),
                Some("gzip_base64"),
                "match_form: {}",
                context()
            );
            assert!(actual.is_none(), "pending hit: {actual:?}; {}", context());
            continue;
        }
        assert_eq!(
            actual.is_some(),
            expected.is_some(),
            "hit: actual {actual:?}, expected {expected:?}; {}",
            context()
        );
        if let (Some(actual), Some(expected)) = (actual, expected) {
            assert_eq!(
                actual.tainted_hash,
                expected.tainted_hash,
                "tainted_hash: {}",
                context()
            );
            assert_eq!(actual.preview, expected.preview, "preview: {}", context());
            assert_eq!(
                actual.where_found,
                expected.where_found,
                "where_found: {}",
                context()
            );
            assert_eq!(
                actual.match_form,
                expected.match_form,
                "match_form: {}",
                context()
            );
        }
    }
    for (name, _) in PENDING {
        assert!(seen.contains(name), "{name}: missing pending case");
    }
}
