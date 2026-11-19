// SPDX-License-Identifier: Apache-2.0

//! Wire types for `internal/corpus/data/*.json`. `deny_unknown_fields` mirrors the
//! Go loader: a typo in a data file must fail loudly, in every language.

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub profile: String,
    pub scenarios: Vec<Scenario>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub description: String,
    pub category: String,
    pub variant: String,
    #[serde(default)]
    pub enforcement: String,
    #[serde(default)]
    pub known_gap: bool,
    #[serde(default)]
    pub gap_tag: String,
    #[serde(default)]
    pub gap_note: String,
    #[serde(default)]
    pub pre_existing_gap: bool,
    #[serde(default)]
    pub expect_trip_by_design: bool,
    #[serde(default)]
    pub design_note: String,
    pub cve_ref: Option<CveRef>,
    #[serde(default)]
    pub vault_enabled: bool,
    #[serde(default)]
    pub vault_authorize: Vec<Vault>,
    #[serde(default)]
    pub inherit_sink_suspicion: bool,
    #[serde(default)]
    pub sink_suspicion_allowlist: Vec<String>,
    #[serde(default)]
    pub max_decode_depth: u32,
    pub steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CveRef {
    pub id: String,
    pub source: String,
    pub real_world: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    pub tool: String,
    #[serde(default)]
    pub secret_classes: Vec<String>,
}

/// A tagged union on `kind`: result and request use the event fields, syscall and
/// syscall_sensor the syscall fields, advance_time uses session_id and advance_by.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub kind: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub direction: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub server_id: String,
    pub tool_args: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub decision: String,
    #[serde(default)]
    pub ts_mono_ns: i64,
    #[serde(default)]
    pub pid: i64,
    #[serde(default)]
    pub comm: String,
    #[serde(default)]
    pub syscall: String,
    #[serde(default)]
    pub dest_ip: String,
    #[serde(default)]
    pub dest_port: i64,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub payload: String,
    #[serde(default)]
    pub file_contents: String,
    #[serde(default)]
    pub payload_b64: String,
    #[serde(default)]
    pub file_contents_b64: String,
    #[serde(default)]
    pub advance_by: String,
}

pub type GapTags = BTreeMap<String, String>;

pub fn data_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../internal/corpus/data")
}

pub fn load(name: &str) -> File {
    let raw = std::fs::read_to_string(data_dir().join(name)).unwrap();
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{name}: {e}"))
}

pub fn load_gap_tags() -> GapTags {
    let raw = std::fs::read_to_string(data_dir().join("gap_tags.json")).unwrap();
    serde_json::from_str(&raw).unwrap()
}
