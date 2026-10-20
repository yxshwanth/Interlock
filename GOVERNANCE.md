# Governance

Interlock is a single-maintainer project under the Apache License 2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). This file says how decisions are made and how that changes as contributors arrive.

## Roles

- **Maintainer** (currently [@yxshwanth](https://github.com/yxshwanth)): merges changes, cuts and signs releases, owns the roadmap ([docs/ROADMAP.md](docs/ROADMAP.md)), and handles security reports ([SECURITY.md](SECURITY.md)).
- **Contributor**: anyone who sends a change. Contributors sign off each commit under the DCO (below).
- **Reviewer / area owner**: named in [`.github/CODEOWNERS`](.github/CODEOWNERS). Today every path has the maintainer; owners are added per area when someone has made sustained contributions there.

## How decisions get made

1. Changes go through pull requests. CI must pass: build, vet, tests, race, the corpus and budget gate, DCO, SPDX and test-layer checks.
2. Detection and security-relevant changes also need the tests the [known-gap discipline](CONTRIBUTING.md#known-gap-discipline) requires.
3. Changing a pinned number in [`docs/budgets.json`](docs/budgets.json) (corpus counts, benchmark ceilings) is a deliberate edit that needs the maintainer's review and a stated reason in the PR. A gate failure is never fixed by loosening a budget without that.
4. Architectural decisions are recorded as ADRs in [`docs/adr/`](docs/adr/).
5. Disagreements: the maintainer decides and writes the reason in the PR or ADR.

## Becoming an owner

After several merged, non-trivial changes in an area and a review record the maintainer trusts, the maintainer may add the contributor to CODEOWNERS for that area. Owners can be removed after a long absence. If the project gains a second maintainer, this file is updated before any change to release signing, the licence, or the trademark policy.

## Developer Certificate of Origin

Contributions are accepted under the [DCO 1.1](https://developercertificate.org/). Add a sign-off to every commit:

```
git commit -s -m "fix(engine): ..."
```

which appends `Signed-off-by: Your Name <you@example.com>` using your git identity. A CI check rejects pull requests with unsigned commits (merge commits and bot commits from `dependabot[bot]` are exempt). By signing off you certify you have the right to submit the change under Apache-2.0.

## Licence and copyright

- Current releases: Apache-2.0. Releases before the relicense stay MIT; the CHANGELOG states the change.
- The relicense was done while the repository had one copyright holder. Authors in the git history at the relicense point: the maintainer (committing as "Yashwanth Reddy Mali" and as "Yash") and `dependabot[bot]` (dependency version bumps). Any future outside contribution comes in under the DCO and Apache-2.0.
- Source files carry `SPDX-License-Identifier: Apache-2.0`, except `internal/ebpf/bpf/connect.c`, which is `GPL-2.0` because the kernel requires a GPL-compatible licence for the BPF helpers it calls. `scripts/check-spdx.sh` enforces both.

## Trademarks

See [TRADEMARKS.md](TRADEMARKS.md).

## Security

Report vulnerabilities as described in [SECURITY.md](SECURITY.md) (acknowledgment within 72 hours, assessment within 7 days, fix or mitigation plan within 30 days, severity-dependent).
