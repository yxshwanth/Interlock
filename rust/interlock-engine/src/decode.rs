// SPDX-License-Identifier: Apache-2.0

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde_json::Value;

pub const MAX_DECODE_BYTES: usize = 8 * 1024;
pub const MAX_DECODE_INPUT_BYTES: usize = 64 * 1024;
pub const MIN_DECODE_CANDIDATE: usize = 4;

// Go's standard decoders allow nonzero unused bits in the final symbol.
const BASE64_CONFIG: GeneralPurposeConfig =
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true);
const PADDED_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    BASE64_CONFIG.with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);
const RAW_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    BASE64_CONFIG.with_decode_padding_mode(DecodePaddingMode::RequireNone),
);

fn trim_space(input: &[u8]) -> &[u8] {
    let text = String::from_utf8_lossy(input);
    let start = text.len() - text.trim_start().len();
    let trailing = text.trim_start().len() - text.trim().len();
    // Trimmed whitespace occupies the same bytes in the original input.
    &input[start..input.len() - trailing]
}

pub fn try_base64(input: &[u8]) -> Option<Vec<u8>> {
    let input = trim_space(input);
    if input.len() < MIN_DECODE_CANDIDATE {
        return None;
    }

    let cleaned;
    let input = if input.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
        cleaned = input
            .iter()
            .copied()
            .filter(|byte| !matches!(byte, b'\r' | b'\n'))
            .collect::<Vec<_>>();
        cleaned.as_slice()
    } else {
        input
    };

    PADDED_BASE64
        .decode(input)
        .or_else(|_| RAW_BASE64.decode(input))
        .ok()
}

pub fn try_hex(input: &[u8]) -> Option<Vec<u8>> {
    let input = trim_space(input);
    if !looks_like_hex(input) {
        return None;
    }

    fn digit(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            _ => byte.to_ascii_lowercase() - b'a' + 10,
        }
    }

    Some(
        input
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| digit(pair[0]) << 4 | digit(pair[1]))
            .collect(),
    )
}

pub fn plausible_decoded(input: &[u8]) -> bool {
    !input.is_empty()
        && input.len() <= MAX_DECODE_BYTES
        && (looks_like_hex(input) || looks_like_base64(input) || mostly_printable(input))
}

pub fn looks_like_hex(input: &[u8]) -> bool {
    input.len() >= MIN_DECODE_CANDIDATE
        && input.len().is_multiple_of(2)
        && input.iter().all(u8::is_ascii_hexdigit)
}

pub fn looks_like_base64(input: &[u8]) -> bool {
    let input = trim_space(input);
    let padding = input.iter().rev().take_while(|&&byte| byte == b'=').count();
    input.len() >= MIN_DECODE_CANDIDATE
        && padding <= 2
        && input[..input.len() - padding]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

pub fn mostly_printable(input: &[u8]) -> bool {
    let (printable, total) = match std::str::from_utf8(input) {
        Ok(text) => {
            let mut total = 0;
            let printable = text
                .chars()
                .inspect(|_| total += 1)
                .filter(|&ch| (ch >= ' ' && ch != '\x7f') || matches!(ch, '\r' | '\n' | '\t'))
                .count();
            (printable, total)
        }
        Err(_) => (
            input
                .iter()
                .filter(|&&byte| matches!(byte, b' '..=b'~' | b'\r' | b'\n' | b'\t'))
                .count(),
            input.len(),
        ),
    };
    total != 0 && printable >= total - total / 5
}

pub fn json_string_leaves(input: &[u8]) -> Option<Vec<Vec<u8>>> {
    let value = serde_json::from_slice(input).ok()?;
    let mut leaves = Vec::new();
    collect_json_string_leaves(value, &mut leaves);
    (!leaves.is_empty()).then_some(leaves)
}

fn collect_json_string_leaves(value: Value, leaves: &mut Vec<Vec<u8>>) {
    match value {
        Value::String(text) => leaves.push(text.into_bytes()),
        Value::Array(items) => {
            for item in items {
                collect_json_string_leaves(item, leaves);
            }
        }
        Value::Object(object) => {
            // Sort explicitly so workspace feature unification cannot change the walk order.
            let mut entries: Vec<_> = object.into_iter().collect();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            for (_, item) in entries {
                collect_json_string_leaves(item, leaves);
            }
        }
        _ => {}
    }
}

pub fn decode_candidates_from_args(input: &[u8]) -> Option<Vec<Vec<u8>>> {
    json_string_leaves(input).or_else(|| (!input.is_empty()).then(|| vec![input.to_vec()]))
}

pub fn decode_candidates_from_payload(input: &[u8]) -> Option<Vec<Vec<u8>>> {
    if input.is_empty() {
        return None;
    }
    let mut candidates = vec![input.to_vec()];
    candidates.extend(json_string_leaves(input).into_iter().flatten());
    Some(candidates)
}
