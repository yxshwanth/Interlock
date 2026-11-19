// SPDX-License-Identifier: Apache-2.0

const DEFAULT_CHUNK_BYTES: usize = 32;
const DEFAULT_MIN_LEN: usize = 64;
const MIN_ENTROPY: f64 = 3.0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Chunk {
    pub form: String,
    pub value: Vec<u8>,
}

/// Computes Shannon entropy in bits per byte, accumulating in byte order as
/// Go does. Power-of-two probabilities have exact base-2 logarithms, keeping
/// the common boundary case of eight equally frequent bytes at exactly 3.0.
/// Chunking compares directly against the floor with no tolerance.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    let mut frequencies = [0usize; 256];
    for &byte in data {
        frequencies[usize::from(byte)] += 1;
    }
    let mut entropy = 0.0;
    for count in frequencies.into_iter().filter(|&count| count != 0) {
        let p = count as f64 / data.len() as f64;
        entropy -= p * p.log2();
    }
    entropy
}

pub fn contiguous_chunks(value: &[u8], n: usize, min_len: usize) -> Vec<Chunk> {
    let n = if n == 0 { DEFAULT_CHUNK_BYTES } else { n };
    let min_len = if min_len == 0 {
        DEFAULT_MIN_LEN
    } else {
        min_len
    };
    if value.len() < min_len {
        return Vec::new();
    }

    let form = format!("chunk_{n}");
    chunkable_body(value)
        .chunks_exact(n)
        .filter(|chunk| shannon_entropy(chunk) >= MIN_ENTROPY)
        .map(|chunk| Chunk {
            form: form.clone(),
            value: chunk.to_vec(),
        })
        .collect()
}

fn chunkable_body(value: &[u8]) -> &[u8] {
    pem_interior(value)
        .or_else(|| putty_interior(value))
        .unwrap_or(value)
}

fn pem_interior(value: &[u8]) -> Option<&[u8]> {
    let begin = value.windows(11).position(|part| part == b"-----BEGIN ")?;
    let body_start = begin + value[begin..].iter().position(|&byte| byte == b'\n')? + 1;
    let end = value.windows(9).rposition(|part| part == b"-----END ")?;
    let body = value.get(body_start..end)?;
    let last = body
        .iter()
        .rposition(|&byte| !matches!(byte, b'\r' | b'\n'))?;
    Some(&body[..=last])
}

fn putty_interior(value: &[u8]) -> Option<&[u8]> {
    if !value.starts_with(b"PuTTY-User-Key-File-") {
        return None;
    }
    if let Some(blank) = value.windows(2).position(|part| part == b"\n\n") {
        if blank + 2 < value.len() {
            return Some(&value[blank + 2..]);
        }
    }
    let marker = b"Private-Lines:";
    let start = value
        .windows(marker.len())
        .position(|part| part == marker)?
        + marker.len();
    let rest = &value[start..];
    let line_end = rest.iter().position(|&byte| byte == b'\n')?;
    (line_end + 1 < rest.len()).then_some(&rest[line_end + 1..])
}
