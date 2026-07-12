// Command fp-corpus runs the internal/corpus benign/malicious corpus and
// writes the published detection-rate / false-positive-rate report.
//
//	go run ./cmd/fp-corpus                  # writes docs/fp_corpus.md
//	go run ./cmd/fp-corpus -out /tmp/x.md    # writes elsewhere
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/yxshwanth/Interlock/internal/corpus"
)

func main() {
	out := flag.String("out", "docs/fp_corpus.md", "path to write the markdown report")
	flag.Parse()

	scenarios := corpus.All()
	results := corpus.Run(scenarios)
	report := corpus.Build(results)

	md := report.Markdown()
	if err := os.WriteFile(*out, []byte(md), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "fp-corpus: writing %s: %v\n", *out, err)
		os.Exit(1)
	}

	fmt.Printf("fp-corpus: %d scenarios (%d malicious, %d benign)\n", len(scenarios), report.TruePositives+report.FalseNegatives+report.KnownGapMisses+report.BonusCatches, report.BenignTotal())
	fmt.Printf("  detection rate (EXFIL-tier, non-gap malicious): %.1f%%  (%d/%d)\n",
		report.DetectionRate()*100, report.TruePositives, report.MaliciousNonGapTotal())
	fmt.Printf("  false-positive rate (any trip, benign):         %.1f%%  (%d/%d)\n",
		report.FalsePositiveRate()*100, report.FalsePositiveTripwire+report.FalsePositiveExfil, report.BenignTotal())
	fmt.Printf("  false-positive rate (EXFIL-tier, benign):       %.1f%%  (%d/%d)\n",
		report.FalsePositiveRateExfil()*100, report.FalsePositiveExfil, report.BenignTotal())
	fmt.Printf("  known-gap misses: %d, bonus catches: %d\n", report.KnownGapMisses, report.BonusCatches)
	fmt.Printf("wrote %s\n", *out)
}
