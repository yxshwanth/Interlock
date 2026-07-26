package corpus

import (
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
		"cve_2025_68143_mcp_git_push_wire_protocol_gap":            false, // git wire protocol carries the bytes outside anything inspected
		"cve_2025_53967_figma_reverse_shell_connect_only_gap":      false, // sensor-only: AllLit unreachable, independent of the connect-payload fix
		"cve_2025_53967_figma_proxy_tied_connect_only_demo":        true,  // proxy-tied: AllLit reachable, demonstrates the fix
		"cve_2025_65720_gpt_researcher_dns_fragmented_exfil_gap":   true,  // connect() still soft-catches; DNS fragments never prove EXFIL
		"cve_2025_65513_fetch_ssrf_cloud_metadata_depth5_nest_gap": false, // exceeds maxDecodeDepth=3
		"cve_2025_66335_doris_blind_sql_injection_exfil_gap":       false, // secret never observed in any single message
		"cve_2026_40576_excel_path_traversal_binary_container_gap": false, // ZIP-compressed .xlsx bytes match no registered canonical form
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
	// cve_2025_65513_fetch_ssrf_cloud_metadata_depth5_nest_gap is only a
	// pre-existing (not newly discovered) gap because its 5 encode layers
	// need exactly one more decode than internal/engine/decode.go's
	// maxDecodeDepth budget allows. If that budget ever changes without
	// this scenario changing too, the miss stops being "entailed by the
	// already-catalogued depth-4+ gap" and becomes something else.
	wantEncodeLayers := engine.MaxDecodeDepth + 2
	if fetchDepth5EncodeLayers != wantEncodeLayers {
		t.Errorf("cve_2025_65513_fetch_ssrf_cloud_metadata_depth5_nest_gap's PreExistingGap premise is stale: "+
			"fetchDepth5EncodeLayers=%d, want engine.MaxDecodeDepth(%d)+2=%d — internal/engine's decode budget changed. "+
			"Re-examine this scenario's PreExistingGap marking, its GapNote, and docs/architecture.md §13's depth-4+ row together.",
			fetchDepth5EncodeLayers, engine.MaxDecodeDepth, wantEncodeLayers)
	}

	// cve_2026_40576_excel_path_traversal_binary_container_gap is only a
	// pre-existing gap because CanonicalEncodings has no registered form
	// for raw ZIP/compressed bytes — only literal/base64/hex/url/reversed/
	// depth-2 nests/gzip_base64. If a new canonical form is ever added,
	// this count changes and the Excel scenario's PreExistingGap premise
	// (and possibly its actual outcome) needs re-checking, not silent trust.
	const wantCanonicalFormCount = 10 // literal, base64, hex, url, reversed, base64_hex, hex_base64, base64_url, base64_reversed, gzip_base64
	if got := len(engine.CanonicalEncodings("premise-probe-value")); got != wantCanonicalFormCount {
		t.Errorf("cve_2026_40576_excel_path_traversal_binary_container_gap's PreExistingGap premise is stale: "+
			"CanonicalEncodings now returns %d forms, want %d — a new canonical form was added. "+
			"Re-examine this scenario's PreExistingGap marking, its GapNote, and docs/architecture.md §13's "+
			"non-gzip-compressor row together (it may now catch, or may no longer be the same class of gap).",
			got, wantCanonicalFormCount)
	}
}
