// SPDX-License-Identifier: Apache-2.0

use interlock_engine::tagger::{Tagger, TaggerConfig};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    name: String,
    config: TaggerConfig,
    queries: Vec<Query>,
    has_sensitive_source: bool,
    has_external_sink: bool,
}

#[derive(Deserialize)]
struct Query {
    tool: String,
    server: String,
    tags: Vec<String>,
    sensitive_source: bool,
    external_sink: bool,
}

#[test]
fn tagger_vectors() {
    let cases: Vec<Case> = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../internal/engine/testdata/tagger_vectors.json"
    )))
    .expect("tagger_vectors.json");
    for case in cases {
        let tagger = Tagger::new(case.config);
        let name = case.name;
        assert_eq!(
            tagger.has_sensitive_source(),
            case.has_sensitive_source,
            "{name}.has_sensitive_source"
        );
        assert_eq!(
            tagger.has_external_sink(),
            case.has_external_sink,
            "{name}.has_external_sink"
        );
        for (i, query) in case.queries.into_iter().enumerate() {
            let (tool, server) = (&query.tool, &query.server);
            assert_eq!(
                tagger.tags_for(tool, server),
                query.tags,
                "{name}.queries[{i}].tags"
            );
            assert_eq!(
                tagger.is_sensitive_source(tool, server),
                query.sensitive_source,
                "{name}.queries[{i}].sensitive_source"
            );
            assert_eq!(
                tagger.is_external_sink(tool, server),
                query.external_sink,
                "{name}.queries[{i}].external_sink"
            );
        }
    }
}

#[test]
fn null_tool_override_shadows_server_tags() {
    let config = serde_json::from_str(
        r#"{
        "tool_tags": {"quiet": null},
        "servers": [{"id": "vault", "provides_tags": ["sensitive_source"]}],
        "inherit_sink_suspicion": true,
        "sink_suspicion_allowlist": null
    }"#,
    )
    .unwrap();
    let tagger = Tagger::new(config);
    assert!(tagger.tags_for("quiet", "vault").is_empty());
    assert!(tagger.is_external_sink("quiet", "vault"));
    assert!(tagger.is_sensitive_source("other", "vault"));
}
