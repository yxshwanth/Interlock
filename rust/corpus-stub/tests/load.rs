// SPDX-License-Identifier: Apache-2.0

use corpus_stub::{load, load_gap_tags};
use std::collections::BTreeSet;

#[test]
fn every_data_file_loads_and_is_consistent() {
    let tags = load_gap_tags();
    let mut ids = BTreeSet::new();
    let mut total = 0;
    for name in ["malicious.json", "benign.json", "cve.json"] {
        let f = load(name);
        assert!(!f.scenarios.is_empty(), "{name} is empty");
        for sc in &f.scenarios {
            assert!(ids.insert(sc.id.clone()), "duplicate id {}", sc.id);
            assert!(!sc.steps.is_empty(), "{}: no steps", sc.id);
            if sc.known_gap {
                assert!(tags.contains_key(&sc.gap_tag), "{}: gap_tag {:?} not defined", sc.id, sc.gap_tag);
            } else {
                assert!(sc.gap_tag.is_empty(), "{}: gap_tag on a non-gap", sc.id);
            }
            for s in &sc.steps {
                assert!(
                    ["result", "request", "syscall", "syscall_sensor", "advance_time"].contains(&s.kind.as_str()),
                    "{}: step kind {}",
                    sc.id,
                    s.kind
                );
            }
        }
        total += f.scenarios.len();
    }
    // Pinned in Go by TestData_* and docs/budgets.json; a stub must agree on the count.
    assert_eq!(total, 96);
}
