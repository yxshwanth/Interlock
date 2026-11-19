// SPDX-License-Identifier: Apache-2.0

use interlock_engine::evidence::{
    hash_evidence_record, seal_evidence_record, EvidenceError, EvidenceRecord, GoString, SinkValue,
};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Deserialize)]
struct Vectors {
    hashes: Vec<HashVector>,
    chain: Vec<SealVector>,
}

#[derive(Deserialize)]
struct HashVector {
    name: String,
    record: Box<RawValue>,
    hash: String,
}

#[derive(Deserialize)]
struct SealVector {
    chain_seq: u64,
    prev_hash: String,
    hash: String,
    record: Box<RawValue>,
}

fn parse<T: serde::de::DeserializeOwned>(json: &str, case: &str, field: &str) -> T {
    serde_json::from_str(json).unwrap_or_else(|error| panic!("{case}: {field}: {error}"))
}

// Decode the fixture's sink as Go's original types. The wire read below
// separately covers retaining the original sink JSON when reading a record.
fn typed_sink(json: &str, case: &str) -> SinkValue {
    let field = "sink_call";
    match json.as_bytes()[0] {
        b'n' => SinkValue::Null,
        b't' | b'f' => SinkValue::Bool(parse(json, case, field)),
        b'"' => SinkValue::Text(parse(json, case, field)),
        b'[' => SinkValue::List(
            parse::<Vec<Box<RawValue>>>(json, case, field)
                .iter()
                .map(|item| typed_sink(item.get(), case))
                .collect(),
        ),
        b'{' => SinkValue::Map(
            parse::<BTreeMap<String, Box<RawValue>>>(json, case, field)
                .into_iter()
                .rev()
                .map(|(key, value)| {
                    let value = match (case, key.as_str()) {
                        ("unicode_nested_args", "args") => SinkValue::from_raw_json(
                            r#"{ "z": {"message":"<>& café","items":[null,false,42,1.25,{},[]]}, "a": true }"#.as_bytes()
                        ).unwrap(),
                        ("escaped_raw_args", "args") => SinkValue::from_raw_json(
                            "{ \"message\": \"quote\\\" slash\\\\ \u{2028} <>&\" }".as_bytes()
                        ).unwrap(),
                        ("escaped_map_value", "payload_excerpt") => SinkValue::Text(GoString(
                            b"quote\" slash\\ newline\n tab\t nul\x00 bad\xff\xe2\x82".to_vec()
                        )),
                        _ => typed_sink(value.get(), case),
                    };
                    (key, value)
                })
                .collect(),
        ),
        _ if matches!(case, "float_format" | "float_limit") => {
            SinkValue::Float(parse(json, case, field))
        }
        b'-' => SinkValue::Signed(parse(json, case, field)),
        _ => SinkValue::Unsigned(parse(json, case, field)),
    }
}

fn assert_record(record: &EvidenceRecord, expected: &RawValue, case: &str) {
    let json = record.to_json().unwrap();
    let actual = std::str::from_utf8(&json).unwrap();
    // Fixture indentation is outside strings. Strip it while retaining number
    // spellings, field order and all literal characters inside strings.
    let mut quoted = false;
    let mut escaped = false;
    let compact: String = expected
        .get()
        .chars()
        .filter(|&ch| {
            if quoted {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    quoted = false;
                }
                true
            } else {
                quoted = ch == '"';
                !matches!(ch, ' ' | '\r' | '\n' | '\t')
            }
        })
        .collect();
    assert_eq!(actual, compact, "{case}: record JSON");
}

#[test]
fn evidence_chain_vectors() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../internal/engine/testdata/evidence_chain_vectors.json");
    let input =
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let vectors: Vectors = parse(&input, "vectors", "fixture");
    assert_eq!(vectors.hashes.len(), vectors.chain.len(), "chain length");

    let mut prev_hash = String::new();
    for (seq, (hash, seal)) in vectors.hashes.iter().zip(&vectors.chain).enumerate() {
        let name = &hash.name;
        let mut record: EvidenceRecord = parse(hash.record.get(), name, "record");
        assert_eq!(
            hash_evidence_record(&record).unwrap(),
            hash.hash,
            "{name}: wire hash"
        );

        let fields: BTreeMap<String, Box<RawValue>> = parse(hash.record.get(), name, "record");
        record.sink_call = typed_sink(fields["sink_call"].get(), name);
        if name == "invalid_utf8" {
            record.session_id.0 = b"a\xff\xfe\xef\xbf\xbd".to_vec();
            record.sink_call = SinkValue::Text(GoString(b"b\xe2\x82".to_vec()));
        }
        assert_eq!(
            hash_evidence_record(&record).unwrap(),
            hash.hash,
            "{name}: hash"
        );
        assert_record(&record, &hash.record, name);

        seal_evidence_record(&mut record, seq as u64, prev_hash).unwrap();
        assert_eq!(record.chain_seq, seal.chain_seq, "{name}: chain_seq");
        assert_eq!(
            record.prev_hash.0,
            seal.prev_hash.as_bytes(),
            "{name}: prev_hash"
        );
        assert_eq!(record.hash.0, seal.hash.as_bytes(), "{name}: sealed hash");
        assert_record(&record, &seal.record, name);
        prev_hash = String::from_utf8(record.hash.0).unwrap();
    }
}

#[test]
fn invalid_raw_utf8_returns_error() {
    assert!(matches!(
        SinkValue::from_raw_json(b"\"\xff\""),
        Err(EvidenceError::InvalidRawUtf8(_))
    ));
}

#[test]
fn non_finite_numbers_return_errors() {
    for number in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let records = [
            EvidenceRecord {
                confidence: number,
                ..EvidenceRecord::default()
            },
            EvidenceRecord {
                sink_call: SinkValue::List(vec![SinkValue::Float(number)]),
                ..EvidenceRecord::default()
            },
        ];
        for mut record in records {
            assert!(
                matches!(hash_evidence_record(&record), Err(EvidenceError::Json(_))),
                "{number}"
            );
            assert!(
                matches!(
                    seal_evidence_record(&mut record, 0, ""),
                    Err(EvidenceError::Json(_))
                ),
                "{number}"
            );
        }
    }
}
