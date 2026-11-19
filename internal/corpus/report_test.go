// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"fmt"
	"strings"
	"testing"
)

func resultOn(v Variant, o Outcome) Result {
	return Result{Scenario: Scenario{Variant: v}, Outcome: o}
}

// Each result must be counted under its own plane and outcome, not just in
// the totals. Planes come back sorted by name.
func TestReport_BreakdownAssignsPlanes(t *testing.T) {
	report := Build([]Result{
		resultOn(VariantProxyA, OutcomeTruePositive),
		resultOn(VariantProxyA, OutcomeTruePositive),
		resultOn(VariantProxyA, OutcomeTrueNegative),
		resultOn(VariantEbpfB, OutcomeKnownGapMiss),
		resultOn(VariantEbpfB, OutcomeFalsePositiveExfil),
	})

	want := []variantBreakdown{
		{Variant: VariantEbpfB, GapMiss: 1, FPExfil: 1},
		{Variant: VariantProxyA, TP: 2, TN: 1},
	}
	got := report.byVariant()
	if len(got) != len(want) {
		t.Fatalf("got %d planes, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("plane %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// The markdown headline must print the numbers the report holds.
func TestReport_MarkdownHeadline(t *testing.T) {
	report := Build(Run(All()))
	wantLine := fmt.Sprintf("| **Detection rate** (EXFIL-tier, non-gap malicious) | **%s** (%d/%d) |", pct(report.DetectionRate()), report.TruePositives, report.MaliciousNonGapTotal())
	if !strings.Contains(report.Markdown(), wantLine) {
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
