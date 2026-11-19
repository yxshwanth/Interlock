// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"fmt"
	"strings"
	"testing"
)

// The per-plane breakdown is a partition of the results, so its columns must
// add up to the headline totals, and the headline in the markdown must print
// the same numbers the report holds.
func TestReport_BreakdownMatchesHeadline(t *testing.T) {
	report := Build(Run(All()))

	var tp, fn, gap, bonus, tn, fpt, fpx int
	for _, vb := range report.byVariant() {
		tp += vb.TP
		fn += vb.FN
		gap += vb.GapMiss
		bonus += vb.Bonus
		tn += vb.TN
		fpt += vb.FPTripwire
		fpx += vb.FPExfil
	}
	got := [...]int{tp, fn, gap, bonus, tn, fpt, fpx}
	want := [...]int{report.TruePositives, report.FalseNegatives, report.KnownGapMisses, report.BonusCatches, report.TrueNegatives, report.FalsePositiveTripwire, report.FalsePositiveExfil}
	if got != want {
		t.Fatalf("breakdown columns %v do not sum to report totals %v", got, want)
	}

	md := report.Markdown()
	wantLine := fmt.Sprintf("| **Detection rate** (EXFIL-tier, non-gap malicious) | **%s** (%d/%d) |", pct(report.DetectionRate()), report.TruePositives, report.MaliciousNonGapTotal())
	if !strings.Contains(md, wantLine) {
		t.Errorf("markdown headline missing %q", wantLine)
	}
}

func TestRunCVEScenarios_MatchesConfiguredRunner(t *testing.T) {
	scenarios := CVEScenarios()
	got := RunCVEScenarios(scenarios)
	want := RunWithConfig(scenarios, cveTestConfig)
	if len(got) != len(want) {
		t.Fatalf("RunCVEScenarios returned %d results, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i].TrippedExfil != want[i].TrippedExfil || got[i].TrippedAny != want[i].TrippedAny {
			t.Errorf("scenario %d outcome differs between RunCVEScenarios and RunWithConfig", i)
		}
	}
}
