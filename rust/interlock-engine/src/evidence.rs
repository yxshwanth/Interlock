// SPDX-License-Identifier: Apache-2.0

//! Evidence records use Go's JSON field order and omission rules. Serde writes
//! the typed fields and sorted maps. The formatter applies Go's escaping,
//! decimal notation, and raw JSON compaction before SHA-256 is computed.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::ser::{CompactFormatter, Formatter};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io, io::Write};

/// Go strings can contain invalid UTF-8, which is escaped once per bad byte.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GoString(pub Vec<u8>);

impl From<&str> for GoString {
    fn from(text: &str) -> Self {
        Self(text.as_bytes().to_vec())
    }
}

impl From<String> for GoString {
    fn from(text: String) -> Self {
        Self(text.into_bytes())
    }
}

impl GoString {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for GoString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Ok(text) = std::str::from_utf8(&self.0) {
            return serializer.serialize_str(text);
        }

        let mut quoted = String::from("\"");
        for chunk in self.0.utf8_chunks() {
            let valid = serde_json::to_string(chunk.valid()).expect("string serialization");
            quoted.push_str(&valid[1..valid.len() - 1]);
            for _ in chunk.invalid() {
                quoted.push_str(r"\ufffd");
            }
        }
        quoted.push('"');
        RawValue::from_string(quoted)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GoString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        let wire = raw.get();
        let decoded: String = serde_json::from_str(wire).map_err(serde::de::Error::custom)?;
        if !wire.contains(r"\ufffd") {
            return Ok(decoded.into());
        }

        // Go emits literal U+FFFD for valid text and \ufffd for bad bytes.
        // Keep that distinction when reading a record already written by Go.
        let mut bytes = Vec::new();
        let mut start = 1;
        let mut i = 1;
        while i < wire.len() - 1 {
            if wire.as_bytes()[i] != b'\\' {
                i += 1;
            } else if wire[i..].starts_with(r"\ufffd") {
                let part: String = serde_json::from_str(&format!("\"{}\"", &wire[start..i]))
                    .map_err(serde::de::Error::custom)?;
                bytes.extend(part.bytes());
                bytes.push(0xff);
                i += 6;
                start = i;
            } else {
                i += 2;
            }
        }
        let tail: String = serde_json::from_str(&format!("\"{}", &wire[start..]))
            .map_err(serde::de::Error::custom)?;
        bytes.extend(tail.bytes());
        Ok(Self(bytes))
    }
}

/// A sink value built from typed values or read as JSON. Wire input keeps
/// number spellings and key order because a raw argument may occur anywhere
/// inside a sink value.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(untagged)]
pub enum SinkValue {
    #[default]
    Null,
    Bool(bool),
    Signed(i64),
    Unsigned(u64),
    Float(#[serde(serialize_with = "serialize_finite")] f64),
    Text(GoString),
    List(Vec<SinkValue>),
    Map(BTreeMap<String, SinkValue>),
    Raw(Box<RawValue>),
}

impl<'de> Deserialize<'de> for SinkValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Box::<RawValue>::deserialize(deserializer).map(Self::Raw)
    }
}

fn serialize_finite<S: Serializer>(value: &f64, serializer: S) -> Result<S::Ok, S::Error> {
    if value.is_finite() {
        serializer.serialize_f64(*value)
    } else {
        Err(serde::ser::Error::custom("non-finite evidence number"))
    }
}

fn is_zero<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Leg {
    pub lit: bool,
    #[serde(skip_serializing_if = "is_zero")]
    pub trigger_seq: u64,
    #[serde(skip_serializing_if = "GoString::is_empty")]
    pub detail: GoString,
    #[serde(skip_serializing_if = "is_zero")]
    pub lit_at_ns: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TrifectaLegs {
    pub sensitive_source_touched: Leg,
    pub untrusted_content_present: Leg,
    pub external_sink_invoked: Leg,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OverlapHit {
    pub tainted_hash: GoString,
    pub preview: GoString,
    pub where_found: GoString,
    #[serde(skip_serializing_if = "GoString::is_empty")]
    pub match_form: GoString,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TimelineItem {
    pub timeline_seq: i64,
    pub ts_mono_ns: i64,
    pub kind: GoString,
    pub label: GoString,
    #[serde(skip_serializing_if = "is_zero")]
    pub r#ref: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PodContext {
    pub namespace: GoString,
    pub pod_name: GoString,
    pub pod_uid: GoString,
    #[serde(skip_serializing_if = "GoString::is_empty")]
    pub node_name: GoString,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EvidenceRecord {
    pub session_id: GoString,
    pub trip_ts_ns: i64,
    pub verdict: GoString,
    pub action: GoString,
    pub variant: GoString,
    #[serde(serialize_with = "serialize_finite")]
    pub confidence: f64,
    pub legs: TrifectaLegs,
    pub sink_call: SinkValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_overlap: Option<OverlapHit>,
    pub timeline: Option<Vec<TimelineItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_context: Option<PodContext>,
    pub chain_seq: u64,
    pub prev_hash: GoString,
    pub hash: GoString,
}

impl EvidenceRecord {
    /// Encode the record in the same form used by the evidence hash.
    ///
    /// Panics if a float in the record is non-finite.
    pub fn to_json(&self) -> Vec<u8> {
        let mut json = Vec::new();
        self.serialize(&mut serde_json::Serializer::with_formatter(
            &mut json,
            GoFormatter,
        ))
        .expect("serializing evidence into memory");
        json
    }
}

pub fn hash_evidence_record(record: &EvidenceRecord) -> String {
    let mut json = record.to_json();
    // Hash is the final field. The encoded string length also accounts for
    // escapes, so it can be cleared without searching inside the record.
    let mut hash = Vec::new();
    record
        .hash
        .serialize(&mut serde_json::Serializer::with_formatter(
            &mut hash,
            GoFormatter,
        ))
        .expect("serializing hash into memory");
    json.truncate(json.len() - hash.len() - 1);
    json.extend_from_slice(b"\"\"}");
    format!("{:x}", Sha256::digest(json))
}

pub fn seal_evidence_record(record: &mut EvidenceRecord, seq: u64, prev_hash: impl Into<GoString>) {
    record.chain_seq = seq;
    record.prev_hash = prev_hash.into();
    record.hash = hash_evidence_record(record).into();
}

struct GoFormatter;

impl Formatter for GoFormatter {
    fn write_f64<W: Write + ?Sized>(&mut self, writer: &mut W, value: f64) -> io::Result<()> {
        let mut shortest = Vec::new();
        CompactFormatter.write_f64(&mut shortest, value)?;
        let shortest = std::str::from_utf8(&shortest).expect("ASCII number");
        let magnitude = shortest.trim_start_matches('-');
        let (mantissa, exponent) = magnitude
            .split_once('e')
            .map_or((magnitude, 0), |(digits, exponent)| {
                (digits, exponent.parse::<i32>().expect("decimal exponent"))
            });
        let point = mantissa.find('.').unwrap_or(mantissa.len()) as i32 + exponent;
        let digits = mantissa.replace('.', "");
        let significant = digits.trim_start_matches('0');
        let point = point - (digits.len() - significant.len()) as i32;
        let significant = significant.trim_end_matches('0');

        if value.is_sign_negative() {
            writer.write_all(b"-")?;
        }
        if significant.is_empty() {
            return writer.write_all(b"0");
        }
        if !(1e-6..1e21).contains(&value.abs()) {
            writer.write_all(&significant.as_bytes()[..1])?;
            if significant.len() > 1 {
                write!(writer, ".{}", &significant[1..])?;
            }
            return write!(writer, "e{:+}", point - 1);
        }
        if point <= 0 {
            return write!(
                writer,
                "0.{:0>width$}{significant}",
                "",
                width = -point as usize
            );
        }

        let point = point as usize;
        if point >= significant.len() {
            write!(writer, "{significant:0<point$}")
        } else {
            write!(
                writer,
                "{}.{}",
                &significant[..point],
                &significant[point..]
            )
        }
    }

    fn write_string_fragment<W: Write + ?Sized>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        write_escaped(writer, fragment, false)
    }

    fn write_raw_fragment<W: Write + ?Sized>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        write_escaped(writer, fragment, true)
    }
}

fn write_escaped<W: Write + ?Sized>(
    writer: &mut W,
    fragment: &str,
    raw_json: bool,
) -> io::Result<()> {
    let mut in_string = false;
    let mut escaped = false;
    let mut start = 0;
    for (index, ch) in fragment.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if raw_json {
            match ch {
                '"' => in_string = !in_string,
                '\\' if in_string => escaped = true,
                _ => {}
            }
        }
        let replacement = match ch {
            '<' => r"\u003c",
            '>' => r"\u003e",
            '&' => r"\u0026",
            '\u{2028}' => r"\u2028",
            '\u{2029}' => r"\u2029",
            ' ' | '\t' | '\r' | '\n' if raw_json && !in_string => "",
            _ => continue,
        };
        writer.write_all(&fragment.as_bytes()[start..index])?;
        writer.write_all(replacement.as_bytes())?;
        start = index + ch.len_utf8();
    }
    writer.write_all(&fragment.as_bytes()[start..])
}
