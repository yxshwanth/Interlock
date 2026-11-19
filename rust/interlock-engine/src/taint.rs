// SPDX-License-Identifier: Apache-2.0

//! Go uses ASCII word boundaries, digits, and whitespace classes. The patterns
//! scope ASCII mode to boundaries and spell out the digit and whitespace sets.
//! Case-insensitive matching keeps Unicode simple folding, so K matches k as
//! it does in Go. Mask boundaries count bytes. When a cut splits a code point,
//! each invalid byte becomes a replacement character, as in Go JSON output.

use std::{collections::HashSet, sync::LazyLock};

use regex::Regex;
use sha2::{Digest, Sha256};

use crate::{canonical_encodings, contiguous_chunks, Chunk, Variant};

static SECRET_PATTERNS: LazyLock<[Regex; 6]> = LazyLock::new(|| {
    [
        r"(?-u:\b)(sk[-_](?:live|test)[-_][A-Za-z0-9]{10,})(?-u:\b)",
        r"(?-u:\b)(api[-_]?key[-_]?[A-Za-z0-9]{16,})(?-u:\b)",
        r#"(?i)(?:auth[_ ]?token|bearer|token)[:\t\n\f\r ]+["']?([A-Za-z0-9+/=_-]{20,})["']?"#,
        r"(?-u:\b)(acct_[A-Za-z0-9_]{8,})(?-u:\b)",
        r"(?s)(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)",
        r"(?s)(PuTTY-User-Key-File-[0-9]+:.*?Private-MAC:[\t\n\f\r ]*[0-9a-fA-F]+)",
    ]
    .map(|pattern| Regex::new(pattern).expect("valid secret pattern"))
});

pub struct TaintedValue {
    pub value: Vec<u8>,
    pub variants: Vec<Variant>,
    pub chunks: Vec<Chunk>,
    pub hash: String,
    pub preview: String,
    pub source: String,
    pub seq: u64,
}

impl TaintedValue {
    pub fn attach_chunks(&mut self, n: usize, min_len: usize) {
        if !self.value.is_empty() {
            self.chunks = contiguous_chunks(&self.value, n, min_len);
        }
    }
}

pub fn extract_tainted_values(result_text: &str, source: &str, seq: u64) -> Vec<TaintedValue> {
    let mut seen = HashSet::new();
    let mut values = Vec::new();

    for pattern in SECRET_PATTERNS.iter() {
        for captures in pattern.captures_iter(result_text) {
            let (_, [value]) = captures.extract();
            if seen.insert(value) {
                let mut tainted = TaintedValue {
                    value: value.as_bytes().to_vec(),
                    variants: canonical_encodings(value.as_bytes()),
                    chunks: Vec::new(),
                    hash: format!("{:x}", Sha256::digest(value.as_bytes())),
                    preview: mask_value(value),
                    source: source.to_owned(),
                    seq,
                };
                tainted.attach_chunks(0, 0);
                values.push(tainted);
            }
        }
    }

    values
}

fn mask_value(value: &str) -> String {
    let bytes = value.as_bytes();
    let (prefix, suffix) = match bytes.len() {
        0..=4 => return "****".to_owned(),
        5..=10 => (2, 2),
        _ => (3, 4),
    };
    let mut preview = String::new();
    for (index, part) in [&bytes[..prefix], &bytes[bytes.len() - suffix..]]
        .into_iter()
        .enumerate()
    {
        if index == 1 {
            preview.push_str("...");
        }
        for chunk in part.utf8_chunks() {
            preview.push_str(chunk.valid());
            for _ in chunk.invalid() {
                preview.push('�');
            }
        }
    }
    preview
}
