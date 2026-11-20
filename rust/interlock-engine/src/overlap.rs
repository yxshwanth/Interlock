// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::decode::{
    decode_candidates_from_payload, json_string_leaves, plausible_decoded, try_base64, try_hex,
    MAX_DECODE_INPUT_BYTES, MIN_DECODE_CANDIDATE,
};
use crate::{
    canonical_encodings, inspect_container, looks_like_container, ContainerAbortReason,
    ContainerLimits, Form, TaintedValue, Variant,
};

pub const DEFAULT_MAX_DECODE_DEPTH: usize = 5;
static ACTIVE_DECODE_DEPTH: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_DECODE_DEPTH);

pub fn set_max_decode_depth(depth: isize) {
    ACTIVE_DECODE_DEPTH.store(clamp_max_decode_depth(depth), Ordering::Relaxed);
}

pub fn current_max_decode_depth() -> usize {
    ACTIVE_DECODE_DEPTH.load(Ordering::Relaxed)
}

fn clamp_max_decode_depth(depth: isize) -> usize {
    if depth <= 0 {
        DEFAULT_MAX_DECODE_DEPTH
    } else {
        depth.clamp(3, 5) as usize
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct OverlapHit<'a> {
    pub tainted_hash: &'a str,
    pub preview: &'a str,
    pub match_form: Cow<'a, str>,
    pub where_found: &'static str,
}

pub fn match_tainted_value<'a>(
    haystack: &[u8],
    tainted: &'a TaintedValue,
) -> Option<OverlapHit<'a>> {
    let variants = variants_for(tainted);
    let match_form = variants
        .iter()
        .find(|variant| contains(haystack, &variant.value))
        .map(|variant| Cow::Borrowed(variant.form.as_str()))
        .or_else(|| {
            tainted
                .chunks
                .iter()
                .find(|chunk| contains(haystack, &chunk.value))
                .map(|chunk| Cow::Borrowed(chunk.form.as_str()))
        })?;
    Some(OverlapHit {
        tainted_hash: &tainted.hash,
        preview: &tainted.preview,
        match_form,
        where_found: "",
    })
}

pub fn check_overlap_string<'a>(
    tainted: &'a [TaintedValue],
    haystack: &[u8],
) -> Option<OverlapHit<'a>> {
    if haystack.is_empty() {
        return None;
    }
    tainted
        .iter()
        .find_map(|value| match_tainted_value(haystack, value))
}

fn variants_for(tainted: &TaintedValue) -> Cow<'_, [Variant]> {
    if tainted.variants.is_empty() {
        Cow::Owned(canonical_encodings(&tainted.value))
    } else {
        Cow::Borrowed(&tainted.variants)
    }
}

fn contains(haystack: &[u8], value: &[u8]) -> bool {
    !value.is_empty() && haystack.windows(value.len()).any(|window| window == value)
}

pub fn check_overlap_limited<'a>(
    tainted: &'a [TaintedValue],
    args: &[u8],
    limits: &ContainerLimits,
) -> (Option<OverlapHit<'a>>, ContainerAbortReason) {
    let mut hit = check_overlap_string(tainted, args);
    let mut abort = ContainerAbortReason::None;
    if hit.is_none() {
        let leaves = json_string_leaves(args).unwrap_or_default();
        let joined = leaves.concat();
        if joined != args {
            hit = check_overlap_string(tainted, &joined);
        }
        if hit.is_none() {
            let candidates = || {
                leaves
                    .iter()
                    .map(Vec::as_slice)
                    .chain((leaves.is_empty() && !args.is_empty()).then_some(args))
            };
            hit = check_overlap_decoded(tainted, candidates(), current_max_decode_depth());
            if hit.is_none() && limits.enabled {
                (hit, abort) = check_overlap_container_candidates(
                    tainted,
                    candidates().chain(std::iter::once(args)),
                    limits,
                );
            }
        }
    }
    if let Some(hit) = &mut hit {
        hit.where_found = "sink args";
    }
    (hit, abort)
}

pub fn check_overlap_payload_limited<'a>(
    tainted: &'a [TaintedValue],
    payload: &[u8],
    limits: &ContainerLimits,
) -> (Option<OverlapHit<'a>>, ContainerAbortReason) {
    let mut hit = check_overlap_string(tainted, payload);
    let mut abort = ContainerAbortReason::None;
    if hit.is_none() {
        let candidates = decode_candidates_from_payload(payload).unwrap_or_default();
        hit = check_overlap_decoded(
            tainted,
            candidates.iter().map(Vec::as_slice),
            current_max_decode_depth(),
        );
        if hit.is_none() && limits.enabled {
            // Payload candidates already start with the raw payload.
            (hit, abort) = check_overlap_container_candidates(
                tainted,
                candidates.iter().map(Vec::as_slice),
                limits,
            );
        }
    }
    if let Some(hit) = &mut hit {
        hit.where_found = "egress payload";
    }
    (hit, abort)
}

fn check_overlap_decoded<'a, 'b>(
    tainted: &'a [TaintedValue],
    candidates: impl IntoIterator<Item = &'b [u8]>,
    max_depth: usize,
) -> Option<OverlapHit<'a>> {
    if tainted.is_empty() {
        return None;
    }
    candidates
        .into_iter()
        .filter(|c| (MIN_DECODE_CANDIDATE..=MAX_DECODE_INPUT_BYTES).contains(&c.len()))
        .find_map(|c| decode_match_candidates(c, tainted, &mut Vec::new(), max_depth))
}

fn decode_match_candidates<'a>(
    input: &[u8],
    tainted: &'a [TaintedValue],
    path: &mut Vec<&'static str>,
    max_depth: usize,
) -> Option<OverlapHit<'a>> {
    if path.len() >= max_depth || input.is_empty() || input.len() > MAX_DECODE_INPUT_BYTES {
        return None;
    }
    for (layer, decoded) in [
        (Form::Base64, try_base64(input)),
        (Form::Hex, try_hex(input)),
    ] {
        let Some(decoded) = decoded.filter(|d| !d.is_empty() && d.len() <= MAX_DECODE_INPUT_BYTES)
        else {
            continue;
        };
        path.push(layer.as_str());
        let hit = match_single_layer(&decoded, tainted, path).or_else(|| {
            if plausible_decoded(&decoded) {
                decode_match_candidates(&decoded, tainted, path, max_depth)
            } else {
                None
            }
        });
        path.pop();
        if hit.is_some() {
            return hit;
        }
    }
    None
}

fn is_single_layer_form(form: Form) -> bool {
    matches!(
        form,
        Form::Literal | Form::Base64 | Form::Hex | Form::UrlEncoded | Form::Reversed
    )
}

fn match_single_layer<'a>(
    haystack: &[u8],
    tainted: &'a [TaintedValue],
    path: &[&str],
) -> Option<OverlapHit<'a>> {
    tainted.iter().find_map(|value| {
        let variants = variants_for(value);
        (variants
            .iter()
            .any(|v| is_single_layer_form(v.form) && contains(haystack, &v.value))
            || contains(haystack, &value.value))
        .then(|| OverlapHit {
            tainted_hash: &value.hash,
            preview: &value.preview,
            match_form: Cow::Owned(format!("decoded_{}", path.join("_"))),
            where_found: "",
        })
    })
}

fn unwrap_container_blob(raw: &[u8]) -> Option<Cow<'_, [u8]>> {
    if looks_like_container(raw) {
        Some(Cow::Borrowed(raw))
    } else {
        try_base64(raw)
            .filter(|blob| looks_like_container(blob))
            .map(Cow::Owned)
    }
}

fn check_overlap_container_candidates<'a, 'b>(
    tainted: &'a [TaintedValue],
    candidates: impl IntoIterator<Item = &'b [u8]>,
    limits: &ContainerLimits,
) -> (Option<OverlapHit<'a>>, ContainerAbortReason) {
    let mut seen = HashSet::new();
    let mut last_abort = ContainerAbortReason::None;
    for blob in candidates.into_iter().filter_map(unwrap_container_blob) {
        if seen.contains(&blob) {
            continue;
        }
        let (hit, abort) = check_overlap_container(tainted, &blob, limits);
        if hit.is_some() {
            return (hit, ContainerAbortReason::None);
        }
        if abort != ContainerAbortReason::None {
            last_abort = abort;
        }
        seen.insert(blob);
    }
    (None, last_abort)
}

fn check_overlap_container<'a>(
    tainted: &'a [TaintedValue],
    raw: &[u8],
    limits: &ContainerLimits,
) -> (Option<OverlapHit<'a>>, ContainerAbortReason) {
    let result = inspect_container(raw, limits);
    if result.abort != ContainerAbortReason::None {
        return (None, result.abort);
    }
    let hit = result.parts.iter().find_map(|part| {
        let mut hit = check_overlap_string(tainted, part)?;
        let form = if hit.match_form.is_empty() {
            Form::Literal.as_str()
        } else {
            hit.match_form.as_ref()
        };
        hit.match_form = Cow::Owned(format!("container_{form}"));
        Some(hit)
    });
    (hit, ContainerAbortReason::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{default_container_limits, extract_tainted_values};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    const SECRET: &str = "sk-live-0123456789abcdef";

    fn tainted() -> Vec<TaintedValue> {
        extract_tainted_values(SECRET, "source", 1)
    }

    fn hex(input: &[u8]) -> Vec<u8> {
        canonical_encodings(input)
            .into_iter()
            .find(|variant| variant.form == Form::Hex)
            .unwrap()
            .value
    }

    #[test]
    fn decode_depth_limit_and_clamp() {
        let tainted = tainted();
        let mut encoded = tainted[0].value.clone();
        assert_eq!(current_max_decode_depth(), DEFAULT_MAX_DECODE_DEPTH);
        for layers in 1..=7 {
            encoded = hex(&encoded);
            for (setting, limit) in [(0, 5), (1, 3), (3, 3), (5, 5), (6, 5)] {
                set_max_decode_depth(setting);
                let depth = current_max_decode_depth();
                assert_eq!(depth, limit, "setting {setting}");
                let hit = check_overlap_decoded(&tainted, [encoded.as_slice()], depth);
                // The final hex variant matches one layer before the literal.
                let expected = (layers <= limit + 1)
                    .then(|| format!("decoded{}", "_hex".repeat((layers - 1).max(1))));
                assert_eq!(
                    hit.map(|hit| hit.match_form.into_owned()),
                    expected,
                    "setting {setting}, layers {layers}"
                );
            }
        }
    }

    #[test]
    fn implausible_layer_matches_but_does_not_recurse() {
        let mut tainted = tainted();
        tainted[0].variants.retain(|v| v.form == Form::Literal);
        let mut padded = hex(SECRET.as_bytes());
        padded.resize(crate::decode::MAX_DECODE_BYTES + 1, b' ');
        assert!(!plausible_decoded(&padded));
        assert_eq!(try_hex(&padded).as_deref(), Some(SECRET.as_bytes()));
        let encoded = STANDARD.encode(&padded);
        assert!(check_overlap_decoded(&tainted, [encoded.as_bytes()], 5).is_none());
        padded.extend_from_slice(SECRET.as_bytes());
        let encoded = STANDARD.encode(&padded);
        let hit = check_overlap_decoded(&tainted, [encoded.as_bytes()], 5).unwrap();
        assert_eq!(hit.match_form, "decoded_base64");
    }

    #[test]
    fn base64_decodes_to_hex() {
        let mut tainted = tainted();
        tainted[0].variants.retain(|v| v.form == Form::Literal);
        let encoded = STANDARD.encode(hex(SECRET.as_bytes()));
        let hit = check_overlap_decoded(&tainted, [encoded.as_bytes()], 5).unwrap();
        assert_eq!(hit.match_form, "decoded_base64_hex");
    }

    #[test]
    fn joins_go_json_leaves_in_key_order() {
        let args = br#"{"z":["56789abcdef"],"a":"ignored","a":"sk-live-01234"}"#;
        let tainted = tainted();
        let (hit, abort) = check_overlap_limited(&tainted, args, &default_container_limits());
        let hit = hit.unwrap();
        assert_eq!(hit.match_form, "literal");
        assert_eq!(hit.where_found, "sink args");
        assert_eq!(abort, ContainerAbortReason::None);
    }

    #[test]
    fn container_prefix_and_abort_order() {
        let gzip = |body: &[u8]| {
            let mut writer = GzEncoder::new(Vec::new(), Compression::default());
            writer.write_all(body).unwrap();
            STANDARD.encode(writer.finish().unwrap())
        };
        let tainted = tainted();
        let limits = ContainerLimits {
            max_decompressed_bytes: 128,
            ..default_container_limits()
        };
        let corrupt = STANDARD.encode([0x1f, 0x8b, 0x08]);
        let oversized = gzip(&[b'x'; 129]);
        let valid = gzip(&hex(SECRET.as_bytes()));
        let args = format!(r#"["{corrupt}","{oversized}","{corrupt}"]"#);
        assert_eq!(
            check_overlap_limited(&tainted, args.as_bytes(), &limits),
            (None, ContainerAbortReason::MaxDecompressedBytes)
        );
        let args = format!(r#"["{corrupt}","{oversized}","{valid}"]"#);
        let (hit, abort) = check_overlap_limited(&tainted, args.as_bytes(), &limits);
        assert_eq!(hit.unwrap().match_form, "container_hex");
        assert_eq!(abort, ContainerAbortReason::None);
    }
}
