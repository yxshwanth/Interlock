// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Deserializer};

const SOURCE: &str = "sensitive_source";
const SINK: &str = "external_sink";

#[derive(Default, Deserialize)]
pub struct TaggerConfig {
    #[serde(deserialize_with = "nullable")]
    pub tool_tags: Option<HashMap<String, Option<Vec<String>>>>,
    #[serde(deserialize_with = "nullable")]
    pub servers: Option<Vec<ServerTags>>,
    pub inherit_sink_suspicion: bool,
    #[serde(deserialize_with = "nullable")]
    pub sink_suspicion_allowlist: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct ServerTags {
    pub id: String,
    #[serde(deserialize_with = "nullable")]
    pub provides_tags: Option<Vec<String>>,
}

fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(de: D) -> Result<Option<T>, D::Error> {
    Option::deserialize(de)
}

#[derive(Default)]
pub struct Tagger {
    tool_tags: HashMap<String, Vec<String>>,
    server_tags: HashMap<String, Vec<String>>,
    inherit_sink_suspicion: bool,
    sink_allowlist: HashSet<String>,
}

impl Tagger {
    pub fn new(config: TaggerConfig) -> Self {
        Self {
            tool_tags: config
                .tool_tags
                .unwrap_or_default()
                .into_iter()
                .map(|(tool, tags)| (tool, tags.unwrap_or_default()))
                .collect(),
            server_tags: config
                .servers
                .into_iter()
                .flatten()
                .filter_map(|server| {
                    let tags = server.provides_tags?;
                    (!tags.is_empty()).then_some((server.id, tags))
                })
                .collect(),
            inherit_sink_suspicion: config.inherit_sink_suspicion,
            sink_allowlist: config
                .sink_suspicion_allowlist
                .into_iter()
                .flatten()
                .filter(|name| !name.is_empty())
                .collect(),
        }
    }

    fn tags(&self, tool: &str, server: &str) -> &[String] {
        self.tool_tags
            .get(tool)
            .or_else(|| self.server_tags.get(server))
            .map_or(&[], Vec::as_slice)
    }

    pub fn tags_for(&self, tool: &str, server: &str) -> Vec<String> {
        self.tags(tool, server).to_vec()
    }

    pub fn is_sensitive_source(&self, tool: &str, server: &str) -> bool {
        has_tag(self.tags(tool, server), SOURCE)
    }

    pub fn is_external_sink(&self, tool: &str, server: &str) -> bool {
        has_tag(self.tags(tool, server), SINK)
            || (self.inherit_sink_suspicion
                && !self.sink_allowlist.contains(tool)
                && self
                    .server_tags
                    .get(server)
                    .is_some_and(|tags| has_tag(tags, SOURCE)))
    }

    pub fn has_sensitive_source(&self) -> bool {
        self.has_any_tag(SOURCE)
    }

    pub fn has_external_sink(&self) -> bool {
        self.has_any_tag(SINK)
            || (self.inherit_sink_suspicion
                && self.server_tags.values().any(|tags| has_tag(tags, SOURCE)))
    }

    fn has_any_tag(&self, tag: &str) -> bool {
        self.tool_tags
            .values()
            .chain(self.server_tags.values())
            .any(|tags| has_tag(tags, tag))
    }
}

fn has_tag(tags: &[String], target: &str) -> bool {
    tags.iter().any(|tag| tag == target)
}
