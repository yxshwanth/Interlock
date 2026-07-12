# Repository Hygiene — Interlock

A reference for how this repo is structured, versioned, and contributed to. Several sections below are written to become their own standalone files when you set up the repo (marked **→ file: `X`**). The rest is guidance.

The governing idea: a well-groomed repo is a credibility signal to exactly the senior/security audience Interlock targets. They read the repo the way they read code — looking for whether the person is rigorous. Every convention here exists to answer "is this serious?" with yes.

---

## 1. Essential files (the checklist)

A repo that has these reads as maintained; one that's missing them reads as a weekend dump. In rough priority order:

- `README.md` — the front door. GIF first, quickstart high, honest limitations visible. (See the README plan; not repeated here.)
- `LICENSE` — MIT, as planned. Without it, the code is legally "all rights reserved" and nobody can use it.
- `.gitignore` — critical for this project specifically (see §7).
- `CONTRIBUTING.md` — how to build, test, and submit changes (§4).
- `SECURITY.md` — vulnerability disclosure policy. **Non-optional for a security tool** (§6).
- `CODE_OF_CONDUCT.md` — standard, signals a governed community (§5).
- `CHANGELOG.md` — what changed between versions (§9).
- `ROADMAP.md` — already written. Signals direction.
- `.github/` — issue templates, PR template, CI workflows (§8, §11).

---

## 2. Repository structure

Keep the layout legible so a stranger can navigate without a guide. Interlock's is already sound:

```
interlock/
├── cmd/                  # entrypoints (interlock, demo, k8s-exfil-demo, ebpf-test)
├── internal/             # private packages (proxy, engine, ebpf, k8s, observability,
│                         #   alerting, siem, reload, model, config)
├── servers/              # toy MCP servers (tickets, messenger, exfil)
├── web/                  # evidence viewer
├── deploy/k8s/           # DaemonSet, RBAC, ConfigMap, metrics Service, PRIVILEGE.md, eks/, gke/
├── deploy/systemd/       # bare-metal/VM units, SIGHUP reload notes
├── docs/                 # architecture.md, project_overview.md, task_list.md
├── .github/              # workflows, templates
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGELOG.md
├── ROADMAP.md
├── Dockerfile
├── Makefile
└── go.mod
```

Two conventions worth stating in the README or CONTRIBUTING: `internal/` means "not a public API — import at your own risk" (Go enforces this), and `cmd/ebpf-test` is a throwaway verification tool, not a product surface. Naming the throwaway as throwaway prevents someone treating it as supported.

---

## 3. Versioning — Semantic Versioning (SemVer)

Format: `MAJOR.MINOR.PATCH`, e.g. `v0.1.0`. The rules:

- **MAJOR** — incompatible/breaking changes.
- **MINOR** — new functionality, backward-compatible.
- **PATCH** — backward-compatible bug fixes.

**The `0.x` rule that matters for you:** while you're pre-1.0 (`v0.x.y`), the public API is considered unstable, and *minor* version bumps are allowed to break things. This is the correct posture for Interlock right now — it tells users "this is early, expect change," which is both honest and protective. Your v0.1 → v0.2 → v0.3 roadmap maps cleanly onto minor bumps under a `0.` major.

Reach `v1.0.0` only when you're committing to API stability — when breaking changes become a real cost to users. Don't rush to 1.0; `v0.x` is a feature, not an embarrassment. It signals "moving fast, not yet frozen."

Tag releases with a leading `v`: `git tag v0.1.0`. Go tooling expects the `v` prefix.

**Pre-release tags** for anything not production-ready: `v0.2.0-alpha.1`, `v0.2.0-rc.1`. Useful when you want people to test v0.2 before you bless it.

---

## 4. Contributing → file: `CONTRIBUTING.md`

This file lowers the barrier for the first contributor and sets expectations. Include:

**Build & run.** The exact commands — the `sudo make demo-quiet-ebpf GO=$(which go)` invocation, the kernel/BTF requirement, the Go version. A contributor who can't build in five minutes doesn't contribute. Call out the platform constraint plainly: Linux with a recent kernel and BTF; eBPF paths won't build or run on macOS/Windows.

**Test.** How to run the suite (`go test ./...`), that `go vet` must be clean, and — specific to this project — that `go test -race` should pass, because concurrency is a real hazard here (the roadmap's PID→session work will lean on this). State the current test count as a baseline expectation: new features come with tests.

**The known-gap discipline.** State it explicitly as a contribution norm: detection features ship with tests that name what they *don't* catch (like `TestCheckOverlap_EncodedExfil_KnownGap`). This is Interlock's signature standard — make it a written rule so contributors uphold it.

**Commit and PR conventions.** Point to §8. Small, focused PRs. One logical change per PR. A PR that does three things is three PRs.

**What to work on.** Point to `ROADMAP.md` and to issues labeled `good first issue` / `help wanted`. Tell people where the edges are.

**The eBPF caution.** A contributor touching `internal/ebpf/` should know it's kernel-version-sensitive and that changes need testing on a real kernel, not just a passing compile. Note the bpftrace-first prototyping discipline.

---

## 5. Code of Conduct → file: `CODE_OF_CONDUCT.md`

Adopt the **Contributor Covenant** (the de facto standard — copy their template, fill in a contact email). It's boilerplate, but its absence is noticed and its presence signals a governed, welcoming project. Two minutes to add; don't skip it.

---

## 6. Security policy → file: `SECURITY.md`

**This one matters more for Interlock than for almost any other project, for two reasons:** it's a security tool (people expect you to model threats), and it runs as root loading kernel code (a vulnerability in Interlock is a serious vulnerability in the host). Include:

- **How to report a vulnerability** — a private channel (email, or GitHub's private security advisories), *not* a public issue. Public disclosure of a bug in a root-privileged tool before a fix is dangerous.
- **What's in scope** — the proxy, the engine, the eBPF probes, the privilege model.
- **Response expectations** — a rough timeline for acknowledgment and fix. Even "best-effort, this is a solo v0.x project" is better than silence, and honest.
- **A pointer to the tool's own threat model** — [`docs/threat_model.md`](threat_model.md). Detection scope remains in [`detection_boundary.md`](detection_boundary.md).

Enable **GitHub's private vulnerability reporting** in repo settings so researchers have a proper channel.

---

## 7. `.gitignore` — read this one carefully

Interlock has **two categories of files that must never be committed**, and one genuinely ambiguous case.

**Must ignore — build artifacts:**
```
/interlock
/servers/*/tickets
/servers/*/messenger
/servers/*/exfil
*.test
```
Compiled binaries don't belong in git.

**Must ignore — the sensitive runtime output (this is the important one):**
```
evidence.jsonl
evidence.json
evidence-*.jsonl
events.jsonl
events-*.jsonl
```
These files contain full tool-result bodies — the poisoned ticket text, and (per the redaction scope) known secrets are masked but fixture PII like the customer email is not. **Committing them would put sensitive-shaped data in your public git history permanently.** Even for the demo fixture it reads as careless to a security audience, and if Interlock is ever run against real data, an un-ignored evidence file is a live leak into a public repo. Ignore them, and say in `CONTRIBUTING.md` that evidence/event logs are runtime output and never committed.

**The ambiguous case — generated eBPF files:**
```
internal/ebpf/connect_x86_bpfel.o
internal/ebpf/vmlinux.h
```
You currently *commit* these (they're in your Week 3 file list), and that's a legitimate choice: committing the `bpf2go`-generated `.o` and the generated `vmlinux.h` means users can `go build` without installing clang/llvm/bpf2go. The trade-off: the repo carries generated artifacts (and `vmlinux.h` is enormous — 160k+ lines). Two valid postures, pick one and document it:
- **Commit them** (current) → easier builds, larger repo, generated files in diffs. If so, note in CONTRIBUTING that they're generated by `go generate ./...` and shouldn't be hand-edited.
- **Ignore them** → smaller/cleaner repo, but contributors need the full eBPF toolchain and must run `go generate` before building. Higher barrier.
For a project whose whole point is being easy to try, committing them (current choice) is defensible — just document *why*, so it doesn't look accidental.

Standard Go additions: `vendor/` (if not vendoring), editor dirs, `*.log`.

---

## 8. Commit conventions — Conventional Commits

Adopt **Conventional Commits**. Format:
```
<type>(<scope>): <short summary>
```
Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`. Examples from your actual work:
```
feat(engine): add verdict/action split for eBPF containment
fix(demo): resolve pass-3 deadlock via demo-side timeout
test(overlap): add known-gap test for encoded exfil
docs(readme): document sudo requirement and probe transparency
```
Why bother: it makes history readable, enables automated changelog generation, and signals discipline. `BREAKING CHANGE:` in a commit footer flags an API break for versioning.

Keep commits atomic — one logical change each. A reviewer (and future you) should be able to read the log as a story, which is exactly how your week-summaries already read. That instinct, applied per-commit, is the standard.

---

## 9. Changelog → file: `CHANGELOG.md`

Follow **Keep a Changelog** format. Structure:
```
## [Unreleased]
### Added
### Changed
### Fixed

## [0.1.0] - 2026-07-04
### Added
- Two-plane trifecta detection: userspace MCP proxy + eBPF connect() sensor.
- Variant A (chained-tool exfil) blocked at the proxy.
- Variant B (server side-channel) detected at the kernel, contained by kill.
- Self-contained evidence viewer with fused proxy+kernel timeline.
### Known limitations
- Value-overlap is raw-substring (misses encoded exfil).
- Variant B is legs-only SUSPICIOUS, detect-and-contain (not prevent).
- STDIO transport only; single session; IPv4-only connect() tracing.
```
Group by version, newest first; each version dated; changes grouped by Added/Changed/Fixed/Removed. The `[Unreleased]` section at top collects changes as you make them, then gets renamed on release. Including a **Known limitations** block per release is unusual and it's a credibility move — the same honesty that runs through the whole project.

---

## 10. Branching

For a solo project, keep it simple — don't cargo-cult git-flow. Recommended:

- `main` is always releasable and always green (CI passes).
- Feature work happens on short-lived branches: `feat/http-transport`, `fix/session-race`.
- Merge to `main` via PR (even solo — it runs CI and creates a reviewable record).
- Tag releases off `main`.

Avoid long-lived divergent branches; they rot. When v0.2 is a multi-phase effort, still merge each phase to `main` as it lands (as you did with the weekly builds) rather than holding a giant `v0.2` branch open for a month.

---

## 11. CI/CD — GitHub Actions

A green CI badge on the README is instant credibility with the audience that checks. Minimum viable workflow (`.github/workflows/ci.yml`):

- On every push and PR: `go build ./...`, `go vet ./...`, `go test ./...`.
- The badge in the README proving it passes.

**The eBPF caveat for CI:** the eBPF paths need a Linux runner with a suitable kernel and privileges, and GitHub's hosted runners may not load your probes. Realistic approach: run the full non-eBPF suite in CI (which is most of the current 178 tests — see `make test` for the live count), and either gate the eBPF integration tests behind a self-hosted runner or a build tag, or document them as "run locally on a BTF-enabled kernel." Don't claim CI covers the eBPF path if it can't — that's the honesty discipline applied to your own badges. A passing badge that quietly skips the kernel tests, unstated, is a small dishonesty a sharp reviewer will catch.

Add later as the project matures: `golangci-lint`, race detector in CI (`go test -race`), release automation.

---

## 12. Releases & tags

Use **GitHub Releases**, not just bare tags. For each release:

- A git tag (`v0.1.0`) — annotated, ideally **signed** (`git tag -s`; see §13).
- A GitHub Release with notes drawn from the changelog.
- Attached build artifacts if you ship binaries.

Release notes should lead with the headline capability and *include the known limitations* — every release, not just the first. A release that only lists wins reads as marketing; one that lists wins and honest gaps reads as engineering.

---

## 13. Security-tool hygiene (the extras that matter because people run this as root)

This is the section a normal project's hygiene guide doesn't have, and it's where you earn the trust of the audience that will run privileged kernel code:

- **Signed tags and releases.** `git tag -s` and signed release artifacts give provenance. The run-as-root crowd wants to verify the release came from you and wasn't tampered with. Set up a signing key and note the fingerprint in SECURITY.md.
- **Reproducible builds** (aspirational for v0.x, real by v1.0). If someone can rebuild your binary and get the same bytes, they can trust it matches the source. High bar; worth noting as a goal.
- **Privilege transparency, in the repo.** The README's "here's exactly what the eBPF probe does, read `internal/ebpf/connect.c`" is itself hygiene — it turns "why does this need root" from suspicion into a documented, auditable answer. Keep that probe small and readable *as a trust artifact*, not just as code.
- **Dependency hygiene.** Keep `go.mod` minimal and current; enable Dependabot (GitHub setting) so dependency vulnerabilities get flagged. A security tool with a known-vulnerable dependency is an easy, embarrassing finding.
- **No secrets in history, ever.** Beyond the evidence-file gitignore: never commit a real token, key, or credential even in a test fixture. Your fixtures use `sk-live-...` fake tokens and RFC 5737 IPs — that's correct. Keep it that way; git history is forever.

---

## 14. Repo settings (the GitHub UI, not files)

Configure once, in Settings:

- **Branch protection on `main`** — require CI to pass before merge, even for yourself. Prevents a red `main`.
- **Private vulnerability reporting** — enable it (pairs with SECURITY.md).
- **Dependabot alerts** — on.
- **Issue labels** — at minimum: `bug`, `enhancement`, `good first issue`, `help wanted`, `security`, plus per-area labels (`ebpf`, `proxy`, `engine`) so contributors can find their lane.
- **Topics/tags** on the repo — `ebpf`, `mcp`, `ai-security`, `llm-security`, `agent-security`, `go`. These drive discovery; the right topics put you in front of the right people.
- **A clear repo description and the demo GIF/link** in the About sidebar.

---

## 15. Issue & PR templates → files in `.github/`

Lower friction and raise signal:

- **`.github/ISSUE_TEMPLATE/bug_report.md`** — asks for kernel version, distro, how it was run (which matters enormously for an eBPF tool — most "it doesn't work" issues are kernel/BTF/privilege environment problems).
- **`.github/ISSUE_TEMPLATE/feature_request.md`** — points at the roadmap first ("is this already planned?").
- **`.github/PULL_REQUEST_TEMPLATE.md`** — a checklist: tests added, `go vet` clean, `go test -race` clean, changelog updated, known-gap tests for new detection.

The bug-report template asking for kernel/distro/privilege up front will save you enormous back-and-forth, because for a kernel tool, "works on my machine" failures are the default first issue.

---

## Priority order, if you're doing this before launch

Not everything at once. The launch-critical set, in order: `LICENSE`, `.gitignore` (especially the evidence-file exclusions — that's a leak risk, not just tidiness), `README`, `SECURITY.md`, and a CI workflow with a passing badge. Those five make the repo safe to publish and credible on arrival. `CONTRIBUTING.md`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, templates, and signed releases can follow in the first days after — their absence at launch is forgivable; a leaked evidence file or missing license is not.
