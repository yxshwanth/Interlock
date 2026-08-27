package corpus

import "testing"

// TestCorpus_DetectionAndFalsePositiveRate runs the full benign/malicious
// corpus and pins today's confusion matrix. It hard-fails on:
//   - any non-gap malicious scenario missing EXFIL-tier detection (regression
//     in overlap/encoding logic)
//   - any benign scenario reaching EXFIL (should never happen, ever)
//   - any benign scenario's any-trip outcome disagreeing with its pinned
//     ExpectTripByDesign (catches both new false positives AND silently
//     "fixed" ones that should be reflected in docs/fp_corpus.md)
//
// A KnownGap malicious scenario unexpectedly reaching EXFIL is logged, not
// failed — closing a gap is good news; promote the scenario out of
// maliciousKnownGap() and update docs/fp_corpus.md when it happens.
//
// No root, BTF, or kernel required: this drives internal/engine directly.
func TestCorpus_DetectionAndFalsePositiveRate(t *testing.T) {
	scenarios := All()
	assertUniqueIDs(t, scenarios)

	results := Run(scenarios)
	report := Build(results)

	for _, res := range results {
		sc := res.Scenario
		switch sc.Category {
		case Malicious:
			checkMalicious(t, res)
		case Benign:
			checkBenign(t, res)
		default:
			t.Errorf("scenario %s: unknown category %q", sc.ID, sc.Category)
		}
	}

	t.Logf("corpus: %d scenarios (%d malicious, %d benign)", len(scenarios), report.maliciousTotal(), report.BenignTotal())
	t.Logf("detection rate (EXFIL-tier, non-gap malicious): %s (%d/%d)",
		pct(report.DetectionRate()), report.TruePositives, report.MaliciousNonGapTotal())
	t.Logf("false-positive rate (any trip, benign): %s (%d/%d)",
		pct(report.FalsePositiveRate()), report.FalsePositiveTripwire+report.FalsePositiveExfil, report.BenignTotal())
	t.Logf("false-positive rate (EXFIL-tier, benign): %s (%d/%d)",
		pct(report.FalsePositiveRateExfil()), report.FalsePositiveExfil, report.BenignTotal())
	t.Logf("known-gap misses: %d, bonus catches: %d", report.KnownGapMisses, report.BonusCatches)
}

func checkMalicious(t *testing.T, res Result) {
	sc := res.Scenario
	if sc.KnownGap {
		if res.TrippedExfil {
			t.Logf("BONUS CATCH: %s appears to have closed its documented gap (EXFIL achieved: %v). "+
				"Promote it out of maliciousKnownGap() and update docs/fp_corpus.md. Gap note: %s",
				sc.ID, res.Verdicts, sc.GapNote)
		}
		return
	}
	if !res.TrippedAny {
		t.Errorf("REGRESSION: %s never tripped at all (expected at least SUSPICIOUS) — %s", sc.ID, sc.Description)
	}
	if !res.TrippedExfil {
		t.Errorf("REGRESSION: %s did not reach EXFIL-tier detection (verdicts=%v) — %s", sc.ID, res.Verdicts, sc.Description)
	}
}

func checkBenign(t *testing.T, res Result) {
	sc := res.Scenario
	if res.TrippedExfil {
		t.Errorf("FALSE POSITIVE (EXFIL): %s reached EXFIL on benign content — %s", sc.ID, sc.Description)
	}
	if res.TrippedAny != sc.ExpectTripByDesign {
		t.Errorf("%s: TrippedAny=%v but ExpectTripByDesign=%v (%s) — %s",
			sc.ID, res.TrippedAny, sc.ExpectTripByDesign, sc.DesignNote, sc.Description)
	}
}

func assertUniqueIDs(t *testing.T, scenarios []Scenario) {
	seen := make(map[string]bool, len(scenarios))
	for _, sc := range scenarios {
		if sc.ID == "" {
			t.Fatalf("scenario with empty ID: %+v", sc)
		}
		if seen[sc.ID] {
			t.Fatalf("duplicate scenario ID: %s", sc.ID)
		}
		seen[sc.ID] = true
	}
}
