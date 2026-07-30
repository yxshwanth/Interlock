package corpus

import (
	"fmt"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/engine"
)

// TestCVECorpus_DetectionRate runs the CVE-derived corpus (scenarios_cve.go)
// and pins today's confusion matrix. Unlike TestCorpus_DetectionAndFalsePositiveRate,
// there is no benign/false-positive dimension here — that story is owned by
// docs/fp_corpus.md. This test hard-fails on:
//   - any non-gap scenario missing EXFIL-tier detection (regression in
//     overlap/encoding logic, or in a previously-working reconstruction)
//   - a KnownGap scenario unexpectedly reaching EXFIL is logged, not
//     failed — closing a gap is good news; promote the scenario out of
//     KnownGap and update docs/cve_corpus.md when it happens, same
//     discipline as the self-authored corpus.
//
// No root, BTF, or kernel required: this drives internal/engine directly.
func TestCVECorpus_DetectionRate(t *testing.T) {
	scenarios := CVEScenarios()
	assertUniqueIDs(t, scenarios)

	results := RunWithConfig(scenarios, cveTestConfig)
	report := BuildCVEReport(results, CVEOutOfScope())

	for _, res := range results {
		checkMalicious(t, res)
	}

	// Pin the TrippedAny distinction too — checkMalicious only asserts
	// TrippedExfil for KnownGap scenarios, so a regression that silently
	// turned a soft SUSPICIOUS catch back into a full miss (the exact bug
	// cve_2025_53967_figma_reverse_shell_connect_only_gap surfaced) would
	// otherwise pass unnoticed here.
	wantTrippedAny := map[string]bool{
		"cve_2025_68143_mcp_git_push_wire_protocol_gap":                      false, // git wire protocol carries the bytes outside anything inspected
		"cve_2025_53967_figma_reverse_shell_connect_only_gap":                false, // sensor-only: AllLit unreachable, independent of the connect-payload fix
		"cve_2025_53967_figma_proxy_tied_connect_only_demo":                  true,  // proxy-tied: AllLit reachable, demonstrates the fix
		"cve_2025_65720_gpt_researcher_dns_fragmented_exfil":                 true,  // promoted: bounded egress reassembly proves EXFIL on fragmented DNS exfil
		"cve_2025_66335_doris_blind_sql_injection_exfil_gap":                 false, // secret never observed in any single message
		"cve_2025_53109_filesystem_escaperoute_pem_ebpf_capture_ceiling_gap": true, // promoted: chunk_32 overlap in truncated excerpt (ROADMAP §8)
		// cve_2025_65513_fetch_ssrf_cloud_metadata_depth5_nest promoted out of
		// KnownGap when default max_decode_depth rose to 5 (ROADMAP §15).
		// cve_2025_53109_filesystem_escaperoute_pem_exfil is intentionally
		// absent here: it was promoted out of KnownGap (see
		// cveFilesystemEscapeRoutePEMExfil) and is now a plain catching
		// reconstruction, asserted by checkMalicious like any other.
	}
	for _, res := range results {
		if want, ok := wantTrippedAny[res.Scenario.ID]; ok && res.TrippedAny != want {
			t.Errorf("%s: TrippedAny=%v, want %v (verdicts=%v) — %s",
				res.Scenario.ID, res.TrippedAny, want, res.Verdicts, res.Scenario.GapNote)
		}
	}

	t.Logf("CVE corpus: %d reconstructed scenarios, %d architecturally out of scope",
		len(scenarios), len(report.OutOfScope))
	caught, total := report.ExfilCaught()
	t.Logf("caught EXFIL, raw fraction (not a rate): %d/%d", caught, total)
	t.Logf("missed (documented gap): %d, missed (regression): %d, bonus catches: %d",
		report.Base.KnownGapMisses, report.Base.FalseNegatives, report.Base.BonusCatches)
}

// TestCVECorpus_PreExistingGapPremises guards against the exact kind of
// silent drift that let the deferred-kill code and the sensor-only
// SUSPICIOUS doc claim go stale undetected: Scenario.PreExistingGap is a
// hand-maintained claim that a miss was already catalogued in
// docs/architecture.md before this corpus reconstructed it, and nothing
// else re-checks that claim against the engine's actual current behavior.
// If either premise below stops holding, this test fails loudly instead of
// leaving a stale PreExistingGap: true sitting undetected — a maintainer
// then has to look at whether the scenario, its PreExistingGap marking,
// and/or docs/architecture.md §13's tier table need updating together.
func TestCVECorpus_PreExistingGapPremises(t *testing.T) {
	// Fetch's five-layer nest was promoted out of PreExistingGap when
	// DefaultMaxDecodeDepth rose to 5 (ROADMAP §15). Pin that the encode
	// layer count is still what the former gap needed, and that lowering
	// the live budget to 3 re-opens a miss (TestCorpus_DecodeDepthFPCurve).
	if fetchDepth5EncodeLayers != 5 {
		t.Errorf("fetchDepth5EncodeLayers=%d, want 5 — update depth5 nest scenario + §15 docs together", fetchDepth5EncodeLayers)
	}
	if engine.DefaultMaxDecodeDepth < 5 {
		t.Errorf("DefaultMaxDecodeDepth=%d, want ≥5 so Fetch depth-5 nest stays detection at default", engine.DefaultMaxDecodeDepth)
	}

	// cve_2026_40576_excel_path_traversal_binary_container_exfil promoted when
	// path-driven taint (ROADMAP §18) closed the ZIP/xlsx container gap.
	const wantCanonicalFormCount = 13 // + brotli_base64, zstd_base64, lz4_base64
	if got := len(engine.CanonicalEncodings("premise-probe-value")); got != wantCanonicalFormCount {
		t.Errorf("CanonicalEncodings form count drift: got %d, want %d — "+
			"re-check any PreExistingGap premises that assumed a new canonical form closed a container gap.",
			got, wantCanonicalFormCount)
	}
}

// TestCVECorpus_ReportNarrativePremises guards the same silent-drift class as
// TestCVECorpus_PreExistingGapPremises, but for numbers and claims that live
// in cve_report.go prose: escape counts, family max, PreExistingGap label
// coverage, live fp_corpus any-trip rate, and the Filesystem escape-slot
// claim. If Markdown hardcodes a number that Results no longer support, this
// fails before docs/cve_corpus.md can ship the contradiction.
func TestCVECorpus_ReportNarrativePremises(t *testing.T) {
	results := RunWithConfig(CVEScenarios(), cveTestConfig)
	report := BuildCVEReport(results, CVEOutOfScope())
	esc := report.escapeStats()
	fam := report.familyStats()
	caught, total := report.ExfilCaught()
	md := report.Markdown()

	// Escape headline counts must match Results (the table is interpolated;
	// this pins the surrounding prose can't claim a different arithmetic).
	wantEscapeLine := fmt.Sprintf("| Full miss (no verdict at all) | %d/%d |", esc.FullMiss, esc.Total)
	if !strings.Contains(md, wantEscapeLine) {
		t.Errorf("markdown missing interpolated escape full-miss line %q", wantEscapeLine)
	}
	wantSoftLine := fmt.Sprintf("| Soft-caught (`SUSPICIOUS`, not `EXFIL`) | %d/%d |", esc.SoftCaught, esc.Total)
	if !strings.Contains(md, wantSoftLine) {
		t.Errorf("markdown missing interpolated escape soft-catch line %q", wantSoftLine)
	}

	// Every PreExistingGap reconstruction must have a headline label, and
	// every label must still name a live PreExistingGap scenario.
	livePre := map[string]bool{}
	for _, id := range esc.PreExistingIDs {
		livePre[id] = true
		label, ok := preExistingGapLabels[id]
		if !ok {
			t.Errorf("PreExistingGap scenario %q has no preExistingGapLabels entry — headline prose will fall back to a bare id", id)
			continue
		}
		if !strings.Contains(md, label) {
			t.Errorf("markdown does not mention PreExistingGap label for %q: %q", id, label)
		}
	}
	for id := range preExistingGapLabels {
		if !livePre[id] {
			t.Errorf("preExistingGapLabels has stale entry %q — no live PreExistingGap scenario with that id", id)
		}
	}
	if esc.PreExisting != len(esc.PreExistingIDs) {
		t.Errorf("escape PreExisting count %d != len(PreExistingIDs) %d", esc.PreExisting, len(esc.PreExistingIDs))
	}

	// Open-probe full misses must be labeled (or at least named by id).
	for _, id := range esc.OpenProbeMiss {
		if _, ok := openProbeMissLabels[id]; !ok {
			t.Errorf("open-probe full-miss %q has no openProbeMissLabels entry", id)
		}
	}

	// Family coverage: max-per-family claim must match computed stats.
	wantMax := fmt.Sprintf("max reconstructions in one family is %d of the %d genuine reconstructions", fam.MaxPerFamily, total)
	if !strings.Contains(md, wantMax) {
		t.Errorf("markdown missing interpolated family-max claim %q", wantMax)
	}
	if fam.MaxPerFamily < 3 {
		t.Errorf("expected Filesystem family to contribute ≥3 reconstructions after PEM eBPF gap, got max=%d (%s)", fam.MaxPerFamily, fam.MaxFamilyKey)
	}
	wantCaught := fmt.Sprintf("| Genuine CVE reconstructions, raw fraction reaching `EXFIL` | %d/%d |", caught, total)
	if !strings.Contains(md, wantCaught) {
		t.Errorf("markdown missing interpolated EXFIL fraction %q", wantCaught)
	}

	// Filesystem PEM eBPF scenario was promoted to EXFIL via chunk matching —
	// must still be named; must NOT claim it is the current escape-shaped slot.
	if strings.Contains(md, "pending a replacement") {
		t.Error(`markdown still claims Filesystem's escape-shaped slot is "pending a replacement"`)
	}
	if !strings.Contains(md, "cve_2025_53109_filesystem_escaperoute_pem_ebpf_capture_ceiling_gap") {
		t.Error("markdown never names the PEM eBPF capture-ceiling scenario")
	}
	if strings.Contains(md, "That scenario is Filesystem's current escape-shaped variant") {
		t.Error("markdown still claims pem_ebpf_capture_ceiling_gap is Filesystem's escape-shaped variant after ROADMAP §8 promotion")
	}
	if !strings.Contains(md, "ROADMAP §8") && !strings.Contains(md, "chunk matching") {
		t.Error("markdown does not credit ROADMAP §8 / chunk matching for closing the PEM eBPF capture-ceiling case")
	}

	// PEM proxy vs eBPF RealWorld mechanism text must differ in the table.
	var pemExfilRW, pemEbpfRW string
	for _, res := range results {
		if res.Scenario.CVERef == nil {
			continue
		}
		switch res.Scenario.ID {
		case "cve_2025_53109_filesystem_escaperoute_pem_exfil":
			pemExfilRW = res.Scenario.CVERef.RealWorld
		case "cve_2025_53109_filesystem_escaperoute_pem_ebpf_capture_ceiling_gap":
			pemEbpfRW = res.Scenario.CVERef.RealWorld
		}
	}
	if pemExfilRW == "" || pemEbpfRW == "" {
		t.Fatal("missing PEM exfil or PEM eBPF scenario CVERef")
	}
	if pemExfilRW == pemEbpfRW {
		t.Errorf("pem_exfil and pem_ebpf_capture_ceiling_gap share identical RealWorld text %q — scenario table cannot distinguish them", pemExfilRW)
	}
	if !strings.Contains(pemEbpfRW, "eBPF") && !strings.Contains(pemEbpfRW, "PAYLOAD_MAX") {
		t.Errorf("pem_ebpf RealWorld %q does not mention the eBPF/capture-ceiling distinction", pemEbpfRW)
	}

	// Live fp_corpus any-trip rate must appear; stale 18.8%/6/32-as-current must not be "the number to watch".
	fpN, fpTotal, fpRate := fpCorpusAnyTrip()
	wantFP := fmt.Sprintf("%s (%d/%d)", pct(fpRate), fpN, fpTotal)
	if !strings.Contains(md, wantFP) {
		t.Errorf("markdown missing live fp_corpus any-trip rate %q", wantFP)
	}
	wantWatch := fmt.Sprintf("that %d/%d is the number to watch", fpN, fpTotal)
	if !strings.Contains(md, wantWatch) {
		t.Errorf("markdown missing FP watch-number claim %q", wantWatch)
	}
	if strings.Contains(md, "That 6/32 is the number to watch") {
		t.Error("markdown still tells readers to watch stale 6/32 after the PEM-header collision moved the rate")
	}
	if !strings.Contains(md, "benign_proxy_a_pem_header_universal_collision") {
		t.Error("markdown never mentions the PEM-header universal-collision FP scenario created by the PEM taint fix")
	}

	// Discussion taxonomy: capture-ceiling closed by §8; remaining self-authored gap named.
	if !strings.Contains(md, "malicious_gap_payload_truncated") {
		t.Error("discussion omits malicious_gap_payload_truncated as the remaining entirely-past-window KnownGap")
	}
	if !strings.Contains(md, "chunk matching") && !strings.Contains(md, "ROADMAP §8") {
		t.Error("discussion does not mention chunk matching / ROADMAP §8 closing the eBPF capture-window case")
	}
	wantDressed := fmt.Sprintf("dressed up %d different ways", esc.FullMiss+esc.SoftCaught)
	if !strings.Contains(md, wantDressed) {
		t.Errorf("discussion missing interpolated ceiling-reason count %q", wantDressed)
	}

	// Methodology must not claim every family has exactly two variants / fourteen scenarios.
	if strings.Contains(md, "each with both an exfil-shaped and an escape-shaped variant. That every family landed at exactly two") {
		t.Error("methodology still claims every family landed at exactly two variants")
	}
	if strings.Contains(md, "settled at seven, or at fourteen scenarios") {
		t.Error("methodology still claims corpus settled at seven/fourteen")
	}

	// Doc-count claim must name three docs, not "three docs (A, B)".
	if strings.Contains(md, "three docs (`README.md`, `docs/architecture.md` §5)") {
		t.Error(`markdown still says "three docs" while naming only two`)
	}
}
