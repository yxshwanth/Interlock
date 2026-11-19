// SPDX-License-Identifier: Apache-2.0

use crate::{canonical_encodings, TaintedValue};

#[derive(Debug, Eq, PartialEq)]
pub struct OverlapHit<'a> {
    pub tainted_hash: &'a str,
    pub preview: &'a str,
    pub match_form: &'a str,
}

pub fn match_tainted_value<'a>(
    haystack: &[u8],
    tainted: &'a TaintedValue,
) -> Option<OverlapHit<'a>> {
    let contains = |value: &[u8]| {
        !value.is_empty() && haystack.windows(value.len()).any(|window| window == value)
    };
    let variants = if tainted.variants.is_empty() {
        &canonical_encodings(&tainted.value)
    } else {
        &tainted.variants
    };
    let match_form = variants
        .iter()
        .find(|variant| contains(&variant.value))
        .map(|variant| variant.form.as_str())
        .or_else(|| {
            tainted
                .chunks
                .iter()
                .find(|chunk| contains(&chunk.value))
                .map(|chunk| chunk.form.as_str())
        })?;
    Some(OverlapHit {
        tainted_hash: &tainted.hash,
        preview: &tainted.preview,
        match_form,
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
