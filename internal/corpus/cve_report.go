package corpus

import (
	"fmt"
	"sort"
	"strings"
)

// isCVEReconstruction reports whether sc is a faithful reconstruction of a
// disclosed CVE's own attack shape, as opposed to a scenario built solely to
// demonstrate a fix on a session shape the CVE doesn't naturally produce
// (see cveFigmaProxyTiedConnectOnlyDemo in scenarios_cve.go). Reconstructions
// count toward family coverage and the EXFIL fraction; demonstrations are
// reported separately so they can't inflate either.
func isCVEReconstruction(sc Scenario) bool {
	return sc.ID != "cve_2025_53967_figma_proxy_tied_connect_only_demo"
}

// CVEReport is the published report for the CVE-derived corpus. Kept as a
// distinct type from Report (report.go) — and rendered by a distinct
// Markdown() — so this corpus's narrative can cite real disclosures and
// compute its headline differently (see below) without touching
// docs/fp_corpus.md or Report's existing self-authored-corpus prose.
type CVEReport struct {
	Results    []Result
	Base       Report
	OutOfScope []OutOfScopeCVE
}

// BuildCVEReport scores the reconstructed scenarios exactly like the
// self-authored corpus (reusing Build) and attaches the out-of-scope table.
func BuildCVEReport(results []Result, outOfScope []OutOfScopeCVE) CVEReport {
	return CVEReport{
		Results:    results,
		Base:       Build(results),
		OutOfScope: outOfScope,
	}
}

// ExfilCaught is TruePositives / total genuine CVE reconstructions —
// deliberately computed differently from Report.DetectionRate(). fp_corpus.md
// excludes KnownGap scenarios from its denominator because those gaps are
// already documented and separately regression-tested elsewhere. This
// corpus's entire point is the opposite question: of the attacks a third
// party has already disclosed, how many does Interlock actually catch?
// Excluding the misses from the denominator here would silently launder the
// number back toward 100% — exactly the self-grading problem this corpus
// exists to avoid. Every reconstructed scenario counts, including the ones
// that miss. The fix-demonstration scenario (isCVEReconstruction == false)
// is excluded from this fraction entirely — it isn't a CVE reconstruction
// and including it would misrepresent what was actually tested.
//
// This is reported as a raw fraction, not a percentage — "50.0%" invites a
// precision the sample can't support, and worse, invites the wrong question.
// The denominator itself is an authored choice: the set of CVE families and
// variants reconstructed as of this writing. An eighth family, or another
// variant on an existing one, moves the fraction again. The fraction is real
// (every scenario in it is independently sourced and run against the actual
// engine, not graded by hand) but it is not a statistically meaningful rate,
// and presenting it as one would be the same self-grading problem the
// self-authored 100.0% has, one level up. Grow the denominator further before
// trusting the fraction itself to mean much beyond "more than a coincidence."
func (r CVEReport) ExfilCaught() (n, total int) {
	for _, res := range r.Results {
		if !isCVEReconstruction(res.Scenario) {
			continue
		}
		total++
		if res.Outcome == OutcomeTruePositive || res.Outcome == OutcomeBonusCatch {
			n++
		}
	}
	return n, total
}

// cveFamilyKey groups reconstructions that share a disclosure ID. The
// fix-demonstration scenario is excluded by callers via isCVEReconstruction.
func cveFamilyKey(sc Scenario) string {
	if sc.CVERef == nil {
		return sc.ID
	}
	return sc.CVERef.ID
}

// preExistingGapLabels names each PreExistingGap reconstruction for the
// headline prose. TestCVECorpus_ReportNarrativePremises fails if a
// PreExistingGap scenario is missing here (or if a stale label outlives its
// scenario) — same drift class as TestCVECorpus_PreExistingGapPremises.
var preExistingGapLabels = map[string]string{}

// openProbeMissLabels names open-ground (non-PreExistingGap) escape misses
// that landed as expected. Soft-catches are called out separately in prose.
var openProbeMissLabels = map[string]string{
	"cve_2025_68143_mcp_git_push_wire_protocol_gap":       "`mcp-server-git`'s wire-protocol transfer",
	"cve_2025_53967_figma_reverse_shell_connect_only_gap": "Figma's sensor-mode structural gap",
	"cve_2025_66335_doris_blind_sql_injection_exfil_gap":  "Doris's blind-SQLi taint gap",
}

type cveEscapeStats struct {
	Total        int
	FullMiss     int
	SoftCaught   int
	ReachedExfil int
	PreExisting  int
	OpenProbe    int

	PreExistingIDs []string
	OpenProbeMiss  []string // full-miss open probes (not soft-caught)
	SoftCaughtIDs  []string
}

func (r CVEReport) escapeStats() cveEscapeStats {
	var s cveEscapeStats
	for _, res := range r.Results {
		if !isCVEReconstruction(res.Scenario) || !res.Scenario.KnownGap {
			continue
		}
		s.Total++
		if res.Scenario.PreExistingGap {
			s.PreExisting++
			s.PreExistingIDs = append(s.PreExistingIDs, res.Scenario.ID)
		}
		switch res.Outcome {
		case OutcomeBonusCatch:
			s.ReachedExfil++
		case OutcomeKnownGapMiss:
			if res.TrippedAny {
				s.SoftCaught++
				s.SoftCaughtIDs = append(s.SoftCaughtIDs, res.Scenario.ID)
			} else {
				s.FullMiss++
				if !res.Scenario.PreExistingGap {
					s.OpenProbeMiss = append(s.OpenProbeMiss, res.Scenario.ID)
				}
			}
		}
	}
	s.OpenProbe = s.Total - s.PreExisting
	sort.Strings(s.PreExistingIDs)
	sort.Strings(s.OpenProbeMiss)
	sort.Strings(s.SoftCaughtIDs)
	return s
}

type cveFamilyStats struct {
	FamilyCount       int
	MaxPerFamily      int
	MaxFamilyKey      string
	ExfilFamilyCount  int // families with ≥1 non-gap EXFIL catch
	EscapeFamilyCount int
	PerFamily         map[string]int
}

func (r CVEReport) familyStats() cveFamilyStats {
	perFamily := map[string]int{}
	exfilFamilies := map[string]bool{}
	escapeFamilies := map[string]bool{}
	for _, res := range r.Results {
		if !isCVEReconstruction(res.Scenario) {
			continue
		}
		key := cveFamilyKey(res.Scenario)
		perFamily[key]++
		if res.Scenario.KnownGap {
			escapeFamilies[key] = true
		} else if res.Outcome == OutcomeTruePositive || res.Outcome == OutcomeBonusCatch {
			exfilFamilies[key] = true
		}
	}
	s := cveFamilyStats{
		FamilyCount:       len(perFamily),
		ExfilFamilyCount:  len(exfilFamilies),
		EscapeFamilyCount: len(escapeFamilies),
		PerFamily:         perFamily,
	}
	for key, n := range perFamily {
		if n > s.MaxPerFamily {
			s.MaxPerFamily = n
			s.MaxFamilyKey = key
		}
	}
	return s
}

// fpCorpusAnyTrip returns the live any-trip FP count from the self-authored
// corpus — the same Build(Run(All())) numbers docs/fp_corpus.md publishes.
// CVE report prose that cites the current rate must use this, not a
// hand-maintained fraction.
func fpCorpusAnyTrip() (fp, total int, rate float64) {
	rep := Build(Run(All()))
	fp = rep.FalsePositiveTripwire + rep.FalsePositiveExfil
	total = rep.BenignTotal()
	rate = rep.FalsePositiveRate()
	return fp, total, rate
}

func joinProse(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
	}
}

func (r CVEReport) Markdown() string {
	var b strings.Builder

	caught, total := r.ExfilCaught()
	esc := r.escapeStats()
	fam := r.familyStats()
	fpN, fpTotal, fpRate := fpCorpusAnyTrip()

	fmt.Fprintf(&b, "# CVE-Derived Detection Corpus\n\n")
	fmt.Fprintf(&b, "Generated by `internal/corpus` (also exercised in `internal/corpus/cve_corpus_test.go`, CI-safe — no root/BTF/kind required). Regenerate with `make cve-corpus`.\n\n")
	fmt.Fprintf(&b, "[`docs/fp_corpus.md`](fp_corpus.md) reports 100%% EXFIL-tier detection against a corpus the person who built the detector also wrote. A 100%% rate against self-authored scenarios is close to uninformative about how the tool performs against attacks it wasn't built to pass; a result against attacks a third party actually disclosed is a real data point. This report reconstructs the *attack shape* of published, independently-disclosed MCP CVEs — cited to their real writeups — and runs each one against the actual `internal/engine.Engine`, exactly as `internal/corpus`'s self-authored scenarios do. **Building this report found two live bugs, both now fixed, and one of them changed one of `docs/fp_corpus.md`'s own published numbers** — that change is disclosed here, not hidden by a claim that the two corpora \"never mix.\" The development narrative behind all of this is below the data; read the numbers first.\n\n")

	fmt.Fprintf(&b, "## Headline\n\n")
	fmt.Fprintf(&b, "**Where the escape-shaped variants land — the number that matters, not a coverage stat** (one KnownGap escape per family in the table below; see the methodology section's denominator note before treating this as a rate):\n\n")
	fmt.Fprintf(&b, "| Outcome | Count |\n|---|---:|\n")
	fmt.Fprintf(&b, "| Full miss (no verdict at all) | %d/%d |\n", esc.FullMiss, esc.Total)
	fmt.Fprintf(&b, "| Soft-caught (`SUSPICIOUS`, not `EXFIL`) | %d/%d |\n", esc.SoftCaught, esc.Total)
	fmt.Fprintf(&b, "| Reaching `EXFIL` | %d/%d |\n\n", esc.ReachedExfil, esc.Total)

	preLabels := make([]string, 0, len(esc.PreExistingIDs))
	for _, id := range esc.PreExistingIDs {
		if label, ok := preExistingGapLabels[id]; ok {
			preLabels = append(preLabels, label)
		} else {
			preLabels = append(preLabels, "`"+id+"`")
		}
	}
	openLabels := make([]string, 0, len(esc.OpenProbeMiss))
	for _, id := range esc.OpenProbeMiss {
		if label, ok := openProbeMissLabels[id]; ok {
			openLabels = append(openLabels, label)
		} else {
			openLabels = append(openLabels, "`"+id+"`")
		}
	}

	fmt.Fprintf(&b, "Of those %d, **%d land on a gap `docs/architecture.md` already catalogued before this corpus reconstructed them**: %s. Those %d misses were entailed the moment the scenario shape was chosen, not discovered by running it — a real result (it confirms the gap catalogue predicts actual disclosed-CVE shapes), just a different claim from \"this independently-disclosed CVE revealed something we didn't already know.\" The other %d probed open ground not named in the catalogue. Of those, **one came back different from what it was built to prove**: the GPT Researcher DNS-fragmented variant was authored expecting a full miss and instead still soft-caught on the reverse shell's initial `connect()` — the one genuine a-priori surprise in this batch (see Methodology). The remaining open-ground misses (%s) landed exactly where expected, but on boundaries not previously named in `docs/architecture.md` — novel, but not surprises. Filesystem's original PEM-never-tainted escape was promoted to `EXFIL` on the proxy plane (see \"A taint-extraction gap this corpus found and closed\" below); its eBPF capture-ceiling twin (`cve_2025_53109_filesystem_escaperoute_pem_ebpf_capture_ceiling_gap`) was later promoted too when ROADMAP §8 chunk matching closed truncated-excerpt overlap for long secrets — Filesystem now contributes three catching reconstructions and no escape-shaped KnownGap.\n\n",
		esc.Total, esc.PreExisting, joinProse(preLabels), esc.PreExisting, esc.OpenProbe, joinProse(openLabels))
	fmt.Fprintf(&b, "A separate fix-demonstration scenario (`cve_2025_53967_figma_proxy_tied_connect_only_demo`) also soft-catches, but is not one of the %d above and not a CVE reconstruction — see Correction below.\n\n", esc.Total)

	fmt.Fprintf(&b, "**Coverage per CVE family** (a different claim from the above — how many families have a scenario at all, not how they scored):\n\n")
	fmt.Fprintf(&b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| CVE families reconstructed | %d (`mcp-server-git`, Figma MCP, GPT Researcher, Fetch MCP, Apache Doris MCP, excel-mcp-server, Anthropic Filesystem MCP) |\n", fam.FamilyCount)
	fmt.Fprintf(&b, "| Families with an exfil-shaped variant reaching `EXFIL` | **%d/%d** |\n", fam.ExfilFamilyCount, fam.FamilyCount)
	fmt.Fprintf(&b, "| Families with an escape-shaped variant authored | **%d/%d** — most families carry both; max reconstructions in one family is %d of the %d genuine reconstructions (Filesystem: JSON exfil + PEM proxy catch + PEM eBPF chunk catch — three catching, no remaining escape KnownGap) |\n", fam.EscapeFamilyCount, fam.FamilyCount, fam.MaxPerFamily, total)
	fmt.Fprintf(&b, "| Genuine CVE reconstructions, raw fraction reaching `EXFIL` | %d/%d |\n", caught, total)
	fmt.Fprintf(&b, "| **Architecturally out of scope** (not attempted — separate tally, never blended in) | %d disclosure groups |\n\n", len(r.OutOfScope))

	fmt.Fprintf(&b, "## Reconstructed scenarios\n\n")
	fmt.Fprintf(&b, "| Scenario | CVE(s) | Real-world mechanism | Outcome |\n|---|---|---|---|\n")
	for _, res := range r.Results {
		sc := res.Scenario
		cveID, realWorld := "—", "—"
		if sc.CVERef != nil {
			cveID = fmt.Sprintf("[%s](%s)", sc.CVERef.ID, sc.CVERef.Source)
			realWorld = sc.CVERef.RealWorld
		}
		outcome := scenarioOutcomeLabel(res)
		if !isCVEReconstruction(sc) {
			outcome += " — *not a CVE reconstruction, see Correction below*"
		} else if sc.KnownGap {
			if sc.PreExistingGap {
				outcome += " (pre-existing KnownGap)"
			} else {
				outcome += " (open probe)"
			}
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", sc.ID, cveID, realWorld, outcome)
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "## Missed (or partially caught), and why (code-traced)\n\n")
	fmt.Fprintf(&b, "| Scenario | Gap |\n|---|---|\n")
	for _, res := range r.Results {
		if res.Outcome == OutcomeKnownGapMiss || res.Outcome == OutcomeBonusCatch {
			marker := ""
			if res.Outcome == OutcomeBonusCatch {
				marker = " — **BONUS CATCH, gap closed, promote this scenario and update this report**"
			}
			fmt.Fprintf(&b, "| `%s` | %s%s |\n", res.Scenario.ID, res.Scenario.GapNote, marker)
		}
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "## Architecturally out of scope (not attempted)\n\n")
	fmt.Fprintf(&b, "These were never built as scenarios — not attempted-and-missed, just outside what a post-session behavioral monitor can observe at all. See `internal/corpus/scenarios_cve.go`'s `CVEOutOfScope()`.\n\n")
	fmt.Fprintf(&b, "| CVE(s) | Real-world mechanism | Why out of scope |\n|---|---|---|\n")
	for _, cve := range r.OutOfScope {
		fmt.Fprintf(&b, "| [%s](%s) | %s | %s |\n", cve.ID, cve.Source, cve.RealWorld, cve.WhyOutOfScope)
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "## Methodology and its limits\n\n")
	fmt.Fprintf(&b, "**Reconstruction, not exploitation.** These scenarios reproduce the *data-flow shape* a disclosed CVE produces once exploited — what untrusted input arrived, what got read, what left and how — cited to the real CVE and mechanism. They are not working exploit proofs-of-concept of the underlying parser bug, argument-injection flaw, or command-injection primitive; Interlock's threat model is runtime behavior *after* an MCP session is already running, so that is the layer these scenarios are built at. The self-authored corpus already operates at this same abstraction level (`ticketResult()` is not a real support-desk API payload) — this corpus holds itself to the identical standard, just anchored to real disclosures instead of an author's own imagination.\n\n")
	fmt.Fprintf(&b, "**Reconstructions are not refit to make fixes visible.** See the Correction section below — a reconstruction reports the faithful shape's real outcome; a scenario built to demonstrate a fix on a different session shape is labeled as exactly that and kept separate.\n\n")
	fmt.Fprintf(&b, "**Outcomes are observed, not asserted — including when the a-priori guess was wrong.** Every scenario was run against the real engine before being classified, and several escape-shaped variants here didn't land where they were expected to on the first run: the DNS-fragmented GPT Researcher variant was built expecting a full miss and instead still soft-caught on the shell's initial `connect()`; an early Filesystem EscapeRoute draft accidentally shared a 16-byte phrase between its untrusted excerpt and its sink text, tripping content-bind by construction-bug rather than by design, and was reworded once the mismatch between intent and result surfaced it. Both are reported as actually observed, not as originally guessed. Where a reconstruction misses, the gap note traces the exact code path responsible rather than describing the miss in the abstract — and names every independent cause found, not just the first one located.\n\n")
	fmt.Fprintf(&b, "**The Filesystem PEM accident is a finding, not just a scenario bug that got corrected.** The draft wasn't trying to trip anything — it tripped anyway, on a coincidental 16-byte substring shared between two unrelated strings (an untrusted excerpt and ordinary sink prose), which was enough to satisfy `CheckContentBind`'s default minimum. `docs/architecture.md` §7 already names `content_bind_min_len: 16` as a noise source for fetch-heavy agents that deliberately quote long excerpts; this is sharper evidence of the same ceiling firing on pure coincidence, not deliberate quoting — found by writing a single, otherwise-unrelated scenario, not by looking for it. See `docs/fp_corpus.md`'s Discussion for the operational note; raising the default is a candidate change this finding motivates, not one this report makes unilaterally. The PEM taint fix later made a stronger version of the same ceiling unavoidable: `-----BEGIN PRIVATE KEY-----` is a universal 27-byte constant that always clears the content-bind floor whenever an untrusted excerpt and a sink both merely reference PEM format — measured as `benign_proxy_a_pem_header_universal_collision` (see Operational consequences).\n\n")
	fmt.Fprintf(&b, "**The denominator is authored, and that matters — even grown, even unbalanced.** %d CVE families are reconstructed here as of this writing, totaling %d genuine reconstructions (plus one explicitly labeled fix-demonstration). Most families carry both an exfil-shaped and an escape-shaped variant; Filesystem carries three catching reconstructions (JSON + PEM proxy + PEM eBPF chunk). That mix is itself a choice — an eighth family, or another variant on an existing one, moves the raw fraction again. Endor Labs and CSA's catalogues name more usable shapes than are reconstructed here; this corpus should keep growing rather than being treated as settled at %d families, or at %d scenarios.\n\n", fam.FamilyCount, total, fam.FamilyCount, total)
	fmt.Fprintf(&b, "**Two buckets, kept visually separate.** \"Reconstructed & run\" scenarios were built and scored. \"Architecturally out of scope\" disclosures were *not* attempted, because their mechanism has no faithful representation in `model.InterceptedEvent` / `model.SyscallEvent` — the inputs Interlock's proxy and eBPF sensor actually observe. Forcing those into a scenario that \"fails\" would misrepresent what was tested.\n\n")

	fmt.Fprintf(&b, "## A live bug this corpus found on its first run\n\n")
	fmt.Fprintf(&b, "Before this corpus existed, docs including `README.md`, `docs/architecture.md` §5, and `CHANGELOG.md` (v0.2.2) asserted that a connect-only eBPF trip — no corroborating write, no proven payload — still reaches verdict `SUSPICIOUS`. `cve_2025_53967_figma_reverse_shell_connect_only_gap` (modeling a bare reverse-shell `connect()`, the canonical case the eBPF plane exists for) found that claim was false on a proxy-tied session: `internal/engine/bind.go`'s `CheckContentBind` rejected an empty sink string before any comparison, so a payload-less `connect()` could never reach `SUSPICIOUS` — not a downgrade, a silent deletion of the tripwire, introduced as an unintended side effect of the ROADMAP §1 content-binding fix. Tracing further: the eBPF sensor's ~100 ms \"deferred kill\" window, also documented in those same places, turned out to be **unreachable dead code independent of the bug above** — it only ever armed on `ActionContained`, which `SUSPICIOUS` has not produced since §1, and a bare `connect()` cannot itself produce `EXFIL` (it carries no payload at the kernel level), so the scheduling path could never fire regardless.\n\n")
	fmt.Fprintf(&b, "Both are now fixed, not just documented around. `classifyTrip` (`internal/engine/engine.go`) now distinguishes an event with no payload channel at all (`connect()`) from one with a payload channel that's merely unrelated (`write`/`sendto`/tool-call args) — the former restores the soft `SUSPICIOUS` tripwire on `AllLit` alone, the latter keeps requiring `CheckContentBind` exactly as §1 intended. The now-confirmed-dead deferred-kill subsystem (`scheduleContain`/`scheduleKill`/`flushDeferredKills`/`killLoop`, `internal/ebpf/sensor.go`) was removed rather than left as unreachable code describing a mechanism that cannot fire. `TestEngine_IngestSyscall_ConnectOnly_AllLit_Suspicious` (`internal/engine/engine_test.go`) pins the fix. This is the same shape as the 46.7%% false-positive finding that drove ROADMAP §1 itself: the corpus's job is to find exactly this, and it did, on the first run.\n\n")
	fmt.Fprintf(&b, "**A second, deeper finding surfaced while investigating the first — now fixed too, opt-in.** `cve_2025_53967_figma_reverse_shell_connect_only_gap` is a *sensor-only* reconstruction (`IngestSyscallSensor`, matching the DaemonSet's own deploy shape — CVE-2025-53967 is server-side command injection with no natural proxy-visible untrusted-content step). Sensor-only mode never lights `untrusted_content_present` on its own — a privileged, proxy-less DaemonSet pod genuinely has no MCP untrusted-content plane to observe — so `AllLit()` was *permanently false* there, independent of the fix above. **The entire soft-`SUSPICIOUS` tier was inert on that specific deploy shape**, for every syscall type, not just connect. This was never implemented, not a regression: the code and `docs/architecture.md` §13's description of it had both been unchanged (and mismatched) since sensor-only mode's introduction (v0.3.0) — confirmed by git history, not assumed. Shipped remediation: `Engine.RegisterRemoteUntrusted` + the taint bridge's new `register_untrusted` message let a proxy that *does* observe MCP traffic (the same sidecar shape `taint_bridge` was already built for) forward \"untrusted content observed\" alongside taint — `TestEngine_RegisterRemoteUntrusted_ClosesSensorSuspiciousGap`, `TestBridge_ClientToEngine_UntrustedClosesSensorSuspiciousGap` (`internal/bridge`). It forwards no excerpt text, so it restores the payload-less connect-only tripwire specifically, not content-bound `SUSPICIOUS` on a payload-bearing sensor write (still a named gap, `docs/architecture.md` §13). **This new capability has its own residual named in `docs/threat_model.md` T2**: an allowlisted-but-compromised bridge peer can now light `untrusted_content_present` for an arbitrary `pod_uid` with no secret knowledge at all, which combined with the sensor's own automatic `sensitive_source_touched` seeding turns a pod's ordinary egress into an alert-flood primitive — bounded to alert volume, since no excerpt text is forwarded, so it cannot fabricate a false `EXFIL`. A genuinely proxy-less sensor-only deployment — no sidecar anywhere — still cannot reach `SUSPICIOUS` at all; there is no untrusted-content observer to forward from, by construction, not by omission.\n\n")

	fmt.Fprintf(&b, "## A taint-extraction gap this corpus found and closed\n\n")
	fmt.Fprintf(&b, "`cve_2025_53109_filesystem_escaperoute_pem_never_tainted_gap` (now `cve_2025_53109_filesystem_escaperoute_pem_exfil`) was not an encoding miss and not a channel miss — the two categories every other gap in this corpus falls into. `internal/engine/taint.go`'s `secretPatterns` looked for token-SHAPED text (`sk-live-`, `api_key_`, a `bearer`/`token:` prefix followed by 20+ chars); a PEM private key's base64 body is effectively random-looking bytes with no such textual marker, and `-----BEGIN PRIVATE KEY-----` itself matched nothing. `ExtractTaintedValues` registered **zero** tainted values from the read, so `CheckOverlap` had nothing to compare against even though the agent relayed the exact, unmodified key bytes verbatim to the sink — the most literal exfiltration shape possible, defeated at the first step, before any decode/encoding logic downstream ever got a chance to run.\n\n")
	fmt.Fprintf(&b, "**Fixed, not just documented.** `secretPatterns` now includes a `(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:...)PRIVATE KEY-----` pattern (capturing the whole block, since — unlike a token — there's no shorter sub-value worth isolating) and a matching pattern for PuTTY's `PuTTY-User-Key-File-N: ...Private-MAC: <hex>` text format. `TestExtractTaintedValues_PEMPrivateKey`, `TestExtractTaintedValues_PEMPrivateKey_TypedVariants`, and `TestExtractTaintedValues_PuTTYPrivateKey` (`internal/engine/taint_test.go`) pin extraction directly; `cve_2025_53109_filesystem_escaperoute_pem_exfil` now reaches `EXFIL` end-to-end and is asserted like any other catching reconstruction (`TestCVECorpus_DetectionRate`). This was prioritized ahead of the alert-dedup work below: compared to this corpus's other misses — the git wire-protocol transfer is a demand-gated Named boundary (ROADMAP §21; §20 only closes flat zlib/ZIP on inspected bytes), blind SQL injection is structurally outside byte-overlap proof (ROADMAP §22 reject) — a fixed BEGIN/END anchor is close to free, and \"read a private key and send it somewhere\" is closer to the canonical exfiltration shape a buyer is afraid of than most of what this corpus tests. (Fetch's five-layer nest was later closed by ROADMAP §15's FP-driven default raise to `max_decode_depth=5`; ZIP/xlsx extracted-cell and sink-wrapped containers by ROADMAP §20.)\n\n")
	fmt.Fprintf(&b, "**eBPF plane closed for truncated long secrets (ROADMAP §8).** `cve_2025_53109_filesystem_escaperoute_pem_exfil` remains the proxy-plane catch (`CheckOverlap` on full tools/call args). Its eBPF twin `cve_2025_53109_filesystem_escaperoute_pem_ebpf_capture_ceiling_gap` previously missed because a real-sized PEM exceeds `PAYLOAD_MAX` so the excerpt cannot contain the *complete* tainted value. Contiguous N-byte chunk matching (default N=32) on the PEM body now proves overlap when the truncated excerpt still holds a body chunk — that scenario reaches `EXFIL` with `match_form=chunk_32`. Secrets that land *entirely* past the capture window (zero secret bytes in the excerpt) remain a KnownGap (`malicious_gap_payload_truncated`).\n\n")
	fmt.Fprintf(&b, "**What this doesn't fix.** `secretPatterns` is still pattern-based extraction, not a general secret-shape detector: X.509 certificates, database connection strings (`postgres://user:pass@host/db`), and binary key containers (PKCS#12 `.p12`/`.pfx`) remain invisible to it for the same underlying reason PEM was — no textual marker `ExtractTaintedValues` looks for. PKCS#12 in particular can't be closed with a content regex at all (it's binary DER, no fixed textual anchor); closing it would need tainting driven by the *file path* observed at read time (a `.p12`/`.pfx` extension via the `openat` path or the `read_file` tool's own arguments) rather than by result content — a materially different mechanism this session didn't build. Those remaining shapes are still open product gaps. Both this general pattern-extraction ceiling and the still-open DNS-fragment reassembly gap from the section above are now tiered in `docs/architecture.md` §13, where they were previously named only here.\n\n")

	fmt.Fprintf(&b, "## Correction\n\n")
	fmt.Fprintf(&b, "This report previously published a gap note for `cve_2025_53967_figma_reverse_shell_connect_only_gap` naming only the first cause above, and reconstructed the scenario as a *proxy-tied* Variant B session so the fix would visibly flip its outcome to `SUSPICIOUS`. Both were mistakes, caught on review, not silently fixed:\n\n")
	fmt.Fprintf(&b, "1. **The scenario had been fitted to the patch.** CVE-2025-53967 has no natural proxy-visible untrusted-content step — the faithful reconstruction is sensor-only, matching how this CVE would actually surface on the DaemonSet. Rebuilding it as proxy-tied to make the fix demonstrable, rather than reporting the faithful reconstruction's real (still-negative) outcome, would have quietly inflated this report's credibility on the strength of a scenario built to succeed. It is reverted to sensor-only.\n")
	fmt.Fprintf(&b, "2. **The gap note named one cause and stopped**, when a second, independent, and more consequential one (the sensor-only `AllLit` finding above) was sitting one level deeper in the same code path. Both are now named in the gap note together.\n\n")
	fmt.Fprintf(&b, "The fix demonstration is kept, but as its own separate, explicitly-labeled scenario (`cve_2025_53967_figma_proxy_tied_connect_only_demo`) that states plainly it is *not* a CVE reconstruction — grows the denominator honestly instead of hiding inside the reconstruction it was borrowed from. Net effect on this report's own numbers: **the fix does not change either of `mcp-server-git`'s or Figma's own escape-shaped CVE reconstruction outcomes.** Both `cve_2025_68143_mcp_git_push_wire_protocol_gap` and `cve_2025_53967_figma_reverse_shell_connect_only_gap` remain full misses — one for a protocol-level reason the fix was never going to address, one for the newly-found sensor-mode structural reason. The fix is real and matters generally (proxy-tied Variant B sessions, demonstrated in the separate scenario, and it moved `docs/fp_corpus.md`'s own operational false-positive number — see below) — it just doesn't flip either real CVE reconstruction it was found on, and this report should not have implied otherwise.\n\n")

	fmt.Fprintf(&b, "## Operational consequences of the fix\n\n")
	fmt.Fprintf(&b, "**It creates double emission on the best-case detection path — partially addressed, not fully solved.** `cve_2025_65720_gpt_researcher_html_injection_reverse_shell_exfil` now produces verdicts `[SUSPICIOUS EXFIL]` where it previously produced `[EXFIL]` alone — the connect() now soft-trips before the corroborating write proves `EXFIL`. `internal/engine.Engine` has no session-level dedup: every syscall that reaches a verdict calls `e.sink.Emit` unconditionally (`internal/engine/engine.go`), regardless of whether the same session already tripped moments earlier. `alerting.webhook.min_verdict` and `siem.min_verdict` both default to `SUSPICIOUS` (`internal/config/config.go`'s `normalizeMinVerdict`), so nothing filters the earlier record out by default: **one incident still produces two evidence records and two OCSF findings.** For PagerDuty specifically, `dedup_key` is now `SessionID:Verdict`, not `SessionID` alone — the first cut of that fix keyed on session only, which had a sharp inverse edge: PagerDuty sets severity/urgency from the triggering event, and a still-open, already-acknowledged incident does not generally re-escalate on a later dedup'd trigger, so a session-only key let a later, higher-confidence `EXFIL` merge into an already-acked, lower-severity `SUSPICIOUS` incident instead of paging fresh at the severity it deserves. Keying on verdict too keeps same-tier repeats deduped (the noise case this exists to fix — see the volume finding below) while guaranteeing an escalation always opens its own correctly-`critical` incident. `TestWebhook_PagerDuty_EscalationGetsFreshIncident` (`internal/alerting`) pins it. Note what this means for *this* scenario specifically: `SUSPICIOUS` and `EXFIL` are different verdicts, so their dedup keys differ too — PagerDuty does **not** collapse this pair either, by design, so all three sinks (evidence, OCSF, PagerDuty) double here. The verdict-keyed dedup only collapses *same-tier* repeats within one session — see the volume finding below, where it does change the PagerDuty count specifically. Post-fix, \"one incident, two records\" is therefore format- and case-dependent, not a blanket property of every sink. The base evidence sink and generic/OCSF streams still get two records for one incident; a real session+PID-windowed dedup there is a deliberate design question (what counts as \"the same incident\" across an escalating verdict) that deserves its own scoped change, tracked in `docs/ROADMAP.md`, not bolted on here. Confirmed: no scenario in the self-authored corpus produced more than one verdict per session before the classifyTrip fix; this is new alert-noise surface on the happy path, not a pre-existing, already-tolerated behavior.\n\n")
	fmt.Fprintf(&b, "**It measurably widens `docs/fp_corpus.md`'s operational false-positive surface — measured, not assumed.** The self-authored corpus's existing benign Variant B scenarios never exercised `AllLit` + connect-only (one has no session attribution at all; the other explicitly never touches a `sensitive_source` tool) — the restored tripwire's false-positive surface was previously untested by construction, not proven clean. `benign_ebpf_b_connect_only_alllit_unlisted_endpoint` (`internal/corpus/scenarios_benign.go`) now exercises it directly: a legitimate proxy-tied session with a real sensitive read and untrusted content, then an ordinary but non-allowlisted egress (an unlisted CDN/telemetry endpoint) with no payload. Result: `docs/fp_corpus.md`'s any-trip operational false-positive rate moved from **13.3%% (4/30) to 18.8%% (6/32)** — the same content-blind shape that produced the original 46.7%% finding, now landing on soft `detected_only` instead of a hard block/kill, which is why it's a tolerable, `ExpectTripByDesign` addition rather than a regression.\n\n")
	fmt.Fprintf(&b, "**The PEM taint fix has its own FP consequence — also measured.** Anchoring `-----BEGIN PRIVATE KEY-----` as a secret marker means that same 27-byte universal constant now clears `content_bind_min_len` (16) whenever an untrusted excerpt and a sink both merely *reference* PEM format — no real key required, no quoting relationship, nothing secret. `benign_proxy_a_pem_header_universal_collision` pins that deterministic collision. Combined with the connect-only tripwire scenarios above, `docs/fp_corpus.md`'s any-trip rate is now **%s (%d/%d)** — that %d/%d is the number to watch as this corpus grows, not any single pin in it.\n\n", pct(fpRate), fpN, fpTotal, fpN, fpTotal)
	fmt.Fprintf(&b, "**That rate itself understates real per-incident alert volume — also measured, not just flagged, and format-dependent.** `fp_corpus.md` scores any-trip per *scenario*, not per *verdict*: there is no \"already tripped, stop re-evaluating\" gate anywhere in the engine, so a single chatty session making several different non-allowlisted connects (analytics, CDN, telemetry endpoints an operator forgot to allowlist) trips the soft tripwire independently on **each** one. `benign_ebpf_b_connect_only_alllit_high_volume` makes this concrete: one benign scenario, 5 different non-allowlisted connects, all landing on the same verdict (`SUSPICIOUS`/`detected_only`) — **5** independent evidence records and **5** independent OCSF findings, visible directly in `fp_corpus.md`'s false-positive table, which now reports a verdict count alongside every tripping scenario. PagerDuty is the one sink where this doesn't hold: because all 5 trips share one `SessionID:Verdict` dedup key (unlike the escalating case above, where the verdict itself changes), they collapse into **1** PagerDuty incident — the same-tier noise case the verdict-keyed dedup exists to fix. So the honest per-incident count for this one benign scenario is 5 evidence records, 5 OCSF findings, but only 1 PagerDuty page — three different numbers for one incident, depending which sink is asked. It still counts as exactly one row toward %s; the real alert volume a pattern like it produces in an operational fleet is larger than that headline rate implies, and which sink you're watching changes by how much.\n\n", pct(fpRate))

	fmt.Fprintf(&b, "## Discussion\n\n")
	fmt.Fprintf(&b, "%s\n\n", r.discussion(esc))

	fmt.Fprintf(&b, "## Reproduce\n\n```bash\ngo test ./internal/corpus/... -run TestCVECorpus\nmake cve-corpus   # regenerates this file\n```\n")

	return b.String()
}

// scenarioOutcomeLabel distinguishes three real outcomes, not two: a scenario
// that never trips at all (res.TrippedAny false) is a materially different
// finding from one that trips SUSPICIOUS but not EXFIL (res.TrippedAny true,
// res.TrippedExfil false) — the coarse Outcome enum (shared with the
// self-authored corpus, which has no benign-vs-soft-catch distinction to
// make) collapses both into "missed". This corpus needs the distinction.
func scenarioOutcomeLabel(res Result) string {
	switch res.Outcome {
	case OutcomeTruePositive:
		return "**Caught** — EXFIL"
	case OutcomeBonusCatch:
		return "**Caught** — bonus (gap closed)"
	case OutcomeFalseNegative:
		return "**Missed** — regression (undocumented)"
	case OutcomeKnownGapMiss:
		if res.TrippedAny {
			return "**Soft-caught** — SUSPICIOUS, not EXFIL (evidence/alert emitted, no containment)"
		}
		return "**Missed** — no verdict at all"
	default:
		return string(res.Outcome)
	}
}

func (r CVEReport) discussion(esc cveEscapeStats) string {
	var b strings.Builder
	// Six distinct ceiling reasons matching the six full-miss + soft-catch
	// escape reconstructions (capture-ceiling included). Count is derived
	// from escape outcomes so adding a seventh reason without updating this
	// taxonomy fails TestCVECorpus_ReportNarrativePremises.
	ceilingReasons := esc.FullMiss + esc.SoftCaught
	b.WriteString("**Every family's escape-shaped variant lands on one of a small number of real, code-traced reasons — never a fabricated one.** `cve_2025_68143_mcp_git_push_wire_protocol_gap` produces no verdict because the stolen credential travels as git object bytes inside git's own wire protocol — never inside anything `CheckOverlap` inspects (tool-call JSON args) or `CheckOverlapPayload` would see (a captured syscall payload excerpt). ROADMAP §20 closes packfile-adjacent flat zlib/gzip/ZIP when those bytes *do* appear in ToolArgs/PayloadExcerpt; ROADMAP §21 names protocol-aware egress parsers as a demand-gated Named boundary (no dissector unless a deploy shows that MCP family). `cve_2025_66335_doris_blind_sql_injection_exfil_gap` is a sharper class still: the secret's bytes are never observed anywhere Interlock inspects at all — blind SQL injection reconstructs the value externally from a sequence of booleans, so no taint is ever registered, and no downstream overlap logic gets a chance to run regardless of how faithfully the agent relays the value afterward. ROADMAP §22 rejects query-pattern / side-channel detection as EXFIL (wrong observation model; SUSPICIOUS-dark only if ever researched). `cve_2025_53967_figma_reverse_shell_connect_only_gap` misses because it is faithfully sensor-only, and a *pure* sensor-only deployment (no proxy sidecar anywhere) can never light `untrusted_content_present` — a structural fact about that specific deploy shape. That range — protocol-native transport outside inspected surfaces (Named §21), a value never observed at all (rejected §22), and a structural deployment-mode gap — is the actual shape of this detector's ceiling, not a single repeated excuse dressed up " + fmt.Sprintf("%d", ceilingReasons) + " different ways. Further reasons used to belong here and are fixed: a secret's bytes never becoming taint because they don't match a token-shaped pattern (`cve_2025_53109_filesystem_escaperoute_pem_never_tainted_gap` → PEM taint anchors); an eBPF capture-window ceiling on long secrets when the truncated excerpt still holds body bytes (`cve_2025_53109_filesystem_escaperoute_pem_ebpf_capture_ceiling_gap` → ROADMAP §8 chunk matching); Fetch's five-layer nest (`cve_2025_65513_fetch_ssrf_cloud_metadata_depth5_nest`, formerly `*_depth5_nest_gap`) which missed at default `max_decode_depth=3` and now catches after ROADMAP §15 raised the default to 5 — chosen because `TestCorpus_DecodeDepthFPCurve` measured EXFIL FP 0.0% at depths 3/4/5 with flat decode-miss latency (~380µs); Excel's ZIP-compressed `.xlsx` **whole-file** relay (`cve_2026_40576_excel_path_traversal_binary_container_exfil`, formerly `*_binary_container_gap`) via path-driven provenance seeding (ROADMAP §18); extracted-cell / sink ZIP / flat zlib on inspected bytes via bounded container descent (ROADMAP §20 — `malicious_proxy_a_extracted_from_xlsx_container`, `malicious_proxy_a_sink_zip_contains_secret`, `malicious_ebpf_b_zlib_wrapped_secret`); and same-dest DNS/write fragmentation via egress reassembly (ROADMAP §19 — `cve_2025_65720_gpt_researcher_dns_fragmented_exfil`). Secrets that land *entirely* past the capture window (zero secret bytes in the excerpt) remain a self-authored KnownGap (`malicious_gap_payload_truncated`), not a CVE reconstruction. Container inspect hard-cap aborts remain NamedGaps (`malicious_gap_container_inspect_bomb`). Nests needing more than five decode steps remain outside the clamp `[3,5]`.\n\n")
	b.WriteString("**The catches are real, but they catch the symptom, not the root cause.** In every reconstructed scenario that reached EXFIL, Interlock has zero visibility into the actual vulnerability (a path-traversal bug in `git_init`, an argument-injection flaw in `git_diff`, an unauthenticated command injection in a `curl` fallback, a raw SQL injection, an SSRF bypass, a sandbox-escape symlink/prefix-match bug). What it catches is the downstream data movement those bugs enable, once that movement takes a shape — literal or encoded bytes in a tool call's arguments or a captured syscall payload — that value-overlap matching can see. Every catch in this report landed because bytes appeared somewhere Interlock inspects; every miss is a channel it doesn't read, or a value it never observed. That is a coherent, defensible claim — Interlock proves exfiltration when the bytes are visible, and says so — and it is narrower than \"severs the connection the instant a sequence turns into exfiltration.\" The out-of-scope table above is where the rest of that gap lives.\n\n")
	b.WriteString("**The out-of-scope list is the honest ceiling on that claim.** Roughly half the CVE IDs surveyed for this report never became a scenario at all, because they exploit a layer — process spawn configuration, transport negotiation, registry trust, a local developer tool's own browser-reachable proxy — that sits entirely outside a post-session behavioral monitor's remit. That is not a roadmap item; it is a different product's job.")
	return b.String()
}
