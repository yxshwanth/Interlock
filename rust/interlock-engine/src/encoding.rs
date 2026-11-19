// SPDX-License-Identifier: Apache-2.0

use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Form {
    Literal,
    Base64,
    Hex,
    UrlEncoded,
    Reversed,
    Base64Hex,
    HexBase64,
    Base64Url,
    Base64Rev,
}

impl Form {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::Base64 => "base64",
            Self::Hex => "hex",
            Self::UrlEncoded => "url_encoded",
            Self::Reversed => "reversed",
            Self::Base64Hex => "base64_hex",
            Self::HexBase64 => "hex_base64",
            Self::Base64Url => "base64_url",
            Self::Base64Rev => "base64_reversed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Variant {
    pub form: Form,
    pub value: Vec<u8>,
}

// The four compressor forms are out of scope here (issue #75).
pub fn canonical_encodings(value: &[u8]) -> Vec<Variant> {
    if value.is_empty() {
        return Vec::new();
    }

    let base64 = STANDARD.encode(value).into_bytes();
    let hex = hex_encode(value);
    let url_encoded = query_escape(value);
    let reversed: Vec<u8> = value.iter().rev().copied().collect();

    let base64_hex = STANDARD.encode(&hex).into_bytes();
    let hex_base64 = hex_encode(&base64);
    let base64_url = STANDARD.encode(&url_encoded).into_bytes();
    let base64_rev = STANDARD.encode(&reversed).into_bytes();

    [
        (Form::Literal, value.to_vec()),
        (Form::Base64, base64),
        (Form::Hex, hex),
        (Form::UrlEncoded, url_encoded),
        (Form::Reversed, reversed),
        (Form::Base64Hex, base64_hex),
        (Form::HexBase64, hex_base64),
        (Form::Base64Url, base64_url),
        (Form::Base64Rev, base64_rev),
    ]
    .into_iter()
    .map(|(form, value)| Variant { form, value })
    .collect()
}

fn hex_encode(value: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Vec::with_capacity(value.len() * 2);
    for &byte in value {
        encoded.push(HEX[usize::from(byte >> 4)]);
        encoded.push(HEX[usize::from(byte & 0xf)]);
    }
    encoded
}

fn query_escape(value: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut escaped = Vec::with_capacity(value.len());
    for &byte in value {
        match byte {
            b' ' => escaped.push(b'+'),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                escaped.push(byte)
            }
            _ => escaped.extend_from_slice(&[
                b'%',
                HEX[usize::from(byte >> 4)],
                HEX[usize::from(byte & 0xf)],
            ]),
        }
    }
    escaped
}
