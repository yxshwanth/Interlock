package corpus

import (
	"strings"
	"testing"
)

// TestCorpus_ShannonEntropyDarkMeasurement pins the §12 research spike and
// ensures the published markdown section stays non-empty / regenerable.
func TestCorpus_ShannonEntropyDarkMeasurement(t *testing.T) {
	benignHits, gapHits, benignTotal, gapTotal := MeasureShannonEntropyDark(All(), testConfig)
	md := EntropyDarkMarkdown(benignHits, gapHits, benignTotal, gapTotal)
	t.Logf("\n%s", md)
	if benignTotal == 0 {
		t.Fatal("expected benign scenarios")
	}
	if !strings.Contains(md, "## ROADMAP §12 — Shannon entropy dark measurement") {
		t.Fatal("missing §12 section header")
	}
	if !strings.Contains(md, "Not wired") {
		t.Fatal("must state not wired to alerts")
	}
	// Never claim product FP rates changed — this test must not call Emit.
	_ = gapHits
	_ = gapTotal
}
