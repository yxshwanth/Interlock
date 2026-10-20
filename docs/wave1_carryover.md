# Carried over from Wave 0 into Wave 1

Items Wave 0 could not finish on a dev laptop, plus follow-ups its checks surfaced. Each has the evidence that closes it.

## Needs infrastructure or history

- [ ] **Kernel replay never run.** Run `REQUIRE_KERNEL=1 scripts/verify-all.sh` on the `deploy/ec2` VM (root + BTF) and record the result and skipped-test count in `docs/baseline_wave0.md`. Do this before touching §24. Also run on kernel 6.1 and the current Ubuntu LTS (verifier acceptance differs).
- [ ] **Dashboard of the last 30 CI runs** (§29). Needs CI history; build once the gate has run on main for a while.
- [ ] **PR-tier p90 under 15 minutes** (§80). Measure over real CI runs; only the laptop figure (about 86 s for `go test ./...`) exists.
- [ ] **Re-derive benchmark ceilings on the CI runner or the VM.** `docs/budgets.json` ceilings are 2x the worst of repeated laptop runs; they are not tight and are not comparable across machines.
- [ ] **Rust workspace `license` field** (§30). Do when the workspace is created (Wave 3).

## Follow-ups from the A1 review check (`docs/security_review_status.md`)

- [ ] For each finding marked Fixed (8, 10, 11, 12, 13, 15, 19, 23), confirm a regression test exists that fails without the fix; add one where missing.
- [ ] Finding 20 (partial): make the `IngestResult` recover fail closed, not "FAIL-OPEN for this result".
- [ ] Finding 22: confirm whether the hostname entry `api.anthropic.com` in `egress_allowlist` is ever matched; fix or document.
- [ ] Triage findings 16, 17, 18, 21: fix, or pin as `KnownGap` with a machine-readable tag. Each pin changes the exact counts in `docs/budgets.json`: edit it in the same PR.
- [ ] Findings 1–7, 9, 14 are the planned Wave 1 scope (§24–§26).

## Gate and test hygiene

- [ ] A per-package coverage floor file so the "coverage may not drop" ratchet (`docs/testing.md`) is enforced, not just stated.
- [ ] Merge-queue and nightly CI tiers (only the PR tier exists).
- [ ] Add a secret scanner and `govulncheck` to the PR tier (L0).
- [ ] Confirm the two git author identities ("Yashwanth Reddy Mali", "Yash") are the same copyright holder, as `GOVERNANCE.md` asserts.
