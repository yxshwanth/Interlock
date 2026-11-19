# Carried over from Wave 0 into Wave 1

Items Wave 0 could not finish on a dev laptop, plus follow-ups its checks surfaced. Each has the evidence that closes it.

## Needs infrastructure or history

- [x] **Kernel replay run once** (Linux 7.0 AWS, root, BTF, BPF LSM; see `baseline_wave0.md`). Kernel 6.1 run also done (Debian 12, Linux 6.1.0-54-cloud, 40 tests, 0 skipped).
- [x] **Dashboard of the last 30 CI runs** (§29): `scripts/ci-dashboard.sh` writes `docs/ci_dashboard.md`.
- [x] **PR-tier p90 under 15 minutes** (§80): p90 is 149 s over the last 30 runs (`docs/ci_dashboard.md`). It predates the coverage, govulncheck and gitleaks steps, so re-run the script after they have run a few times.
- [x] **Re-derive benchmark ceilings on the VM** (done; CI-runner numbers still unmeasured). Original item: `docs/budgets.json` ceilings are 2x the worst of repeated laptop runs; they are not tight and are not comparable across machines.
- [ ] **Rust workspace `license` field** (§30). Do when the workspace is created (Wave 3).

## Follow-ups from the A1 review check (`docs/security_review_status.md`)

- [ ] For each finding marked Fixed (8, 10, 11, 12, 13, 15, 19, 23), confirm a regression test exists that fails without the fix; add one where missing.
- [ ] Finding 20 (partial): make the `IngestResult` recover fail closed, not "FAIL-OPEN for this result".
- [x] Finding 22: confirm whether the hostname entry `api.anthropic.com` in `egress_allowlist` is ever matched; fix or document. It is not matched. `buildAllowlist` drops it and logs a warning (`TestUpdateAllowlist_DropsHostnamesWithWarning`). `examples/configs/interlock-ebpf-local.yaml` no longer lists it. `127.0.0.1` still exempts loopback in `examples/configs/interlock-http.yaml`, `interlock-http-monitor.yaml`, and `interlock-monitor.yaml`. `interlock.yaml` does not list it.
- [x] Triage findings 16, 17, 18, 21: the DNS label split, slow trickle, decoy-flow eviction and padded nested layer are pinned `KnownGap` scenarios with gap tags (`egress_reassembly_limit`, `decode_size_limit`); 21 is pinned by its containment tests.
- [ ] Findings 1–7, 9, 14 are the planned Wave 1 scope (§24–§26).

## Gate and test hygiene

- [x] A per-package coverage floor file (`scripts/coverage_floor.tsv`, CI step) so the "coverage may not drop" ratchet (`docs/testing.md`) is enforced, not just stated.
- [x] Merge-queue (`merge_group` trigger) and nightly (`nightly.yml`) CI tiers. Both are unexercised until they run on GitHub.
- [x] Secret scanner (gitleaks) and `govulncheck` in the PR tier. Pinned versions are unverified until CI runs.
- [x] Confirm the two git author identities ("Yashwanth Reddy Mali", "Yash") are the same copyright holder, as `GOVERNANCE.md` asserts. Confirmed by the maintainer on 2026-10-24.
