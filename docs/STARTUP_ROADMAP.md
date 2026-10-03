# Interlock — Startup Roadmap

Working execution plan, not a pitch deck. Decisions below are made, not open questions — revise by editing this file, not by re-litigating in chat.

---

## 0. Positioning (decided)

- **Model:** open-core. Proxy + engine + eBPF sensor stay OSS (this is the credibility engine — an honest gap ledger and a published FP/CVE corpus are marketing you can't fake). Enterprise layer is what's already half-built: managed SIEM/webhook fan-out, RBAC + audit logs, a hosted policy-prover/simulator, managed cloud DaemonSet fleet.
- **Wedge:** MCP has no incumbent security standard (first CVEs are ~8 months old per README). Be the Falco/Trivy of AI-agent runtime security — trusted OSS tool first, company second.
- **Differentiator vs. NVIDIA OpenShell:** they're a hard perimeter (default-deny sandbox + formal policy verification); Interlock is a behavioral tripwire for the case a perimeter can't cover — a *permitted* destination that turns out to carry a secret. Say this explicitly in every pitch: "OpenShell answers 'can this agent reach X'; Interlock answers 'is this agent's session shaped like exfiltration, even through something it was allowed to reach.'"
- **Funding stance:** bootstrap-first. No fundraising motion until there's a traction signal (OSS stars, 1+ design partner, or a paying pilot). Chasing money before proof wastes the one thing this project has going for it — honest, measured claims.

---

## 1. Engineering roadmap

### Phase 1 — Refactor (0–2 months): fix trust-eroding bugs before anything else

Source: [`security_review.md`](security_review.md) — already triaged, in priority order. Ship in this order, each as its own PR with the corpus re-run attached as evidence:

1. **Kernel evasions (findings 1–6):** `sendto` NULL-`sa` fallback, drop the `fd < 3` skip, unroll iovecs beyond `iov[0]`, replace the 5s connect→write TTL with fd-keyed correlation, memset the full payload buffer and check `bpf_probe_read_user`'s return.
2. **Privilege model (7–10):** drop privileges on spawned children (uid + `NoNewPrivs` + userns), `openat2(RESOLVE_BENEATH)` in `ReadContainerFile`, cap `Tainted`/sessions with eviction, entropy-gate chunk minting (finding 19/10 — this is the one confirmed benign-input → root `SIGKILL` path, fix first within this phase).
3. **Concrete bugs (11–15, 20–23):** origin-validation via `url.Parse`, blocking `select` → add `default:`, evidence files `0600`, bridge minimum-length + hash verification, `RedactJSON` via unmarshal/remarshal, wrap `IngestResult` in `recover()`, narrow the process-group kill, fix the shipped egress-allowlist semantics (hostname vs IP, don't ship `127.0.0.1` as trusted).

Each fix should land with: the existing `go test ./internal/corpus/...` staying green, a new `KnownGap` → passing-test flip where applicable, and an update to `fp_corpus.md`/`cve_corpus.md` numbers via `make fp-corpus`/`make cve-corpus`.

### Phase 2 — Rust migration (2–8 months, staged, never big-bang)

Full rewrite is the stated goal, but staged so nothing stalls mid-migration:

1. **Stage 1 — eBPF loader + probes → `aya`.** This is where the memory-safety bugs actually live (unzeroed buffer, unchecked reads, TOCTOU). Rust's ownership model kills these classes by construction. Ships as a drop-in replacement for `internal/ebpf`; Go control plane unchanged, talks to it the same way.
2. **Stage 2 — engine hot path (taint/overlap/decode/container) → a Rust crate.** This is the correctness-critical, CPU-bound core. Expose it to the still-Go proxy via FFI or a local gRPC/UDS boundary — don't rewrite the proxy yet. Prove the crate against the existing corpus before cutting over (corpus becomes the migration's acceptance test, for free).
3. **Stage 3 — proxy layer → full Rust**, once Stage 1+2 are stable in production. This is the highest-risk, lowest-payoff stage (the proxy's bugs in the review were logic bugs, not memory-safety bugs) — do it last, and only if Stage 1+2 already justified the investment.

Each stage ships independently and is individually a complete, working system — never "half migrated, nothing works."

### Phase 3 — Feature additions (parallel with Phase 2, not blocking it)

Priority order (highest leverage first):

1. **Policy dry-run / blast-radius simulator** — run a proposed config change against `fp_corpus`/`cve_corpus` before applying it. Cheapest version of OpenShell's formal-verification pitch; reuses infrastructure that already exists.
2. **Local/dev mode** — proxy-only, no k8s/no privileged eBPF, for someone running Claude Desktop + MCP servers on a laptop. This is the OSS-adoption unlock; nobody spins up a DaemonSet to try a tool.
3. **Dark-signal semantic scorer** — cheap embedding/n-gram similarity against tainted values, wired like `ShannonEntropy` already is (measurement-only, never hard-block). Directly answers the "semantic exfil" gap the docs already admit.
4. **Non-MCP SDK hooks** (Claude Agent SDK callbacks, LangChain middleware) — third observation plane for teams that can't run a sidecar.
5. **Cross-session correlation** — flag overlapping taint hashes across sessions sharing a bridge connection.
6. **Credential-injection mode (opt-in)** — Interlock holds real credentials, injects only into policy-matched requests, agent never sees them. Biggest lift, biggest gap-closer vs. OpenShell; candidate to build directly in the Rust proxy (Stage 3) rather than retrofitting into Go.
7. **Rekor/Sigstore evidence signing** — replaces "no WORM, no external signing" in `threat_model.md` T5 with an existing, trusted tool instead of DIY.

---

## 2. Business layer

- **Packaging:** OSS (proxy, engine, eBPF sensor, CLI, viewer) vs. Enterprise (managed SIEM/PagerDuty integrations, RBAC + audit log, hosted policy simulator, managed DaemonSet fleet across clusters, SLA-backed support).
- **Trust artifacts:** commission one independent pentest once Phase 1 lands (turn `security_review.md`'s pattern into a published, dated trust page — "here's what an outside reviewer found, here's what we fixed, here's the corpus proving it"). SOC 2 only after a paying customer asks for it — don't pre-spend on compliance theater.
- **Content/marketing:** the FP-rate journey (46.7% → 18.9% any-trip, 0% EXFIL-tier) and the connect-only-tripwire regression-and-fix story are genuinely good technical blog posts — publish them. Security engineers trust vendors who show their false-positive math and their own bugs.

## 3. GTM

- Launch OSS on HN / security Twitter with the honest gap ledger as the hook — "a security tool that tells you what it can't catch" is unusual enough to travel.
- Target early adopters: teams running Claude Agent SDK or internal MCP servers in production today (small pool, but exactly who needs this and who can give real feedback fast).
- Design-partner criteria: already running >1 MCP server in a real deployment, has a security/platform team who'll actually read `threat_model.md`, willing to run the DaemonSet or proxy in a non-prod environment first.

## 4. Interview-prep appendix

Talking points this project already earns, mapped to what they demonstrate:

- **Systems design** — two-plane architecture (proxy = enforcement, eBPF = ground truth), verdict/action separation, session state machine with leg decay.
- **Security engineering** — threat modeling own TCB (T1–T6), fail-open vs. fail-closed tradeoffs, least-privilege capability dropping, tamper-evident hash chains.
- **Kernel/eBPF** — tracepoints vs. LSM hooks, ring-buffer design (dual severity-class rings), CO-RE/BTF reality vs. `bpf_probe_read_user`, verifier constraints (bounded iovec unrolling).
- **Distributed systems** — PID/cgroup attribution across clock domains, session concurrency races, `go test -race` discipline.
- **Data/detection engineering** — precision/recall tradeoffs measured with a real corpus, false-positive remediation story (46.7% → 18.9%), the discipline of `KnownGap` tests as living documentation of scope.
- **Product judgment** — verdict vs. action as a load-bearing abstraction, explicit "considered and rejected" mechanisms (sockmap, SOCKS5 scanning) with reasoning, not just features shipped.
- **STAR story candidates:** (1) the connect-only tripwire silently deleted by an unrelated fix, found by building a CVE corpus — debugging via building the test, not staring at code; (2) the sensor-only `AllLit` structural gap that had been wrong in the docs since v0.3.0 — a case of verifying an assumption instead of trusting existing documentation.

## 5. Immediate next actions

1. Fix Phase 1, item 1 findings (kernel evasions) first — they're the ones an attacker who reads the README would find in twenty minutes, per the review's own framing.
2. Draft an ADR for the Rust eBPF migration (Stage 1) before writing any Rust — pin the `aya` API surface and the Go/Rust boundary contract.
3. Turn this file's Phase 1 list into tracked issues/PRs one at a time — don't batch them into one giant refactor PR.
