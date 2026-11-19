// SPDX-License-Identifier: Apache-2.0

mod json;

use std::{collections::HashSet, str};

use crate::taint::{tainted_value, TaintedValue};

const SENSITIVE_EXTENSIONS: &[&str] = &[
    ".p12", ".pfx", ".kdbx", ".xlsx", ".xlsm", ".xls", ".pem", ".key", ".crt", ".cer", ".jks",
];

const SENSITIVE_BASENAME_SUBSTRINGS: &[&str] = &[
    "credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "secrets",
    "kubeconfig",
    ".aws",
    "service-account",
];

const PATH_ARG_KEYS: &[&str] = &[
    "path",
    "file",
    "filepath",
    "file_path",
    "excel_file",
    "filename",
    "source",
    "target",
];

const MAX_PATH_TAINT_BYTES: usize = 64 * 1024;

pub fn is_sensitive_resource_path(path: impl AsRef<[u8]>, prefixes: &[String]) -> bool {
    let path = trim_space(path.as_ref());
    if path.is_empty() {
        return false;
    }
    if prefixes
        .iter()
        .any(|p| !p.is_empty() && path.starts_with(p.as_bytes()))
    {
        return true;
    }
    let lower = go_lowercase(&String::from_utf8_lossy(path));
    if SENSITIVE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
        return true;
    }
    let base = lower
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default();
    SENSITIVE_BASENAME_SUBSTRINGS
        .iter()
        .any(|part| base.contains(part))
}

pub fn extract_paths_from_tool_args(args_json: impl AsRef<[u8]>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    json::json_string_leaves(args_json.as_ref(), |key, value| {
        let trimmed = value.trim();
        if !trimmed.is_empty()
            && (PATH_ARG_KEYS.contains(&go_lowercase(key).as_str())
                || (trimmed.contains('/')
                    && (trimmed.contains('.') || go_lowercase(trimmed).contains("credential"))))
            && seen.insert(value.to_owned())
        {
            paths.push(value.to_owned());
        }
    });
    paths
}

pub fn taint_path_driven_content(
    content: impl AsRef<[u8]>,
    path: &str,
    source: &str,
    seq: u64,
) -> Option<TaintedValue> {
    let content = trim_space(content.as_ref());
    (!content.is_empty()).then(|| {
        tainted_value(
            &content[..content.len().min(MAX_PATH_TAINT_BYTES)],
            format!("{source} (path:{path})"),
            seq,
        )
    })
}

fn go_lowercase(text: &str) -> String {
    // Go applies simple lowercase mappings per rune.
    text.chars()
        .map(|ch| ch.to_lowercase().next().unwrap_or(ch))
        .collect()
}

fn trim_space(bytes: &[u8]) -> &[u8] {
    // Invalid bytes are non-space in Go. Trim only valid UTF-8 at either edge.
    let leading = bytes.utf8_chunks().next().map_or("", |chunk| chunk.valid());
    let start = leading.len() - leading.trim_start().len();
    let bytes = &bytes[start..];
    let mut end = bytes.len();
    while let Some(&last) = bytes.get(end.wrapping_sub(1)) {
        let width = if last.is_ascii() {
            1
        } else {
            let Some(lead) = bytes[..end]
                .iter()
                .rev()
                .take(4)
                .position(|byte| byte & 0xc0 != 0x80)
            else {
                break;
            };
            lead + 1
        };
        if !str::from_utf8(&bytes[end - width..end])
            .is_ok_and(|text| text.chars().all(char::is_whitespace))
        {
            break;
        }
        end -= width;
    }
    &bytes[..end]
}
