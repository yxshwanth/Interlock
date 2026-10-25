// SPDX-License-Identifier: Apache-2.0

// Command gate checks the corpus results and benchmark output against the
// budgets in docs/budgets.json and exits non-zero on any violation.
//
//	go run ./cmd/gate                      # corpus gates only
//	go run ./cmd/gate -bench bench.txt     # also check `go test -bench` output
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/yxshwanth/Interlock/internal/corpus"
)

type budgets struct {
	FP struct {
		Scenarios    int `json:"scenarios"`
		ExfilFP      int `json:"exfil_false_positives"`
		TP           int `json:"detection_true_positives"`
		FN           int `json:"detection_false_negatives"`
		KnownGap     int `json:"known_gap_misses"`
		BonusCatches int `json:"bonus_catches"`
	} `json:"fp_corpus"`
	CVE struct {
		Scenarios    int `json:"scenarios"`
		Caught       int `json:"exfil_caught"`
		Total        int `json:"exfil_total"`
		KnownGap     int `json:"known_gap_misses"`
		Regression   int `json:"regression_misses"`
		BonusCatches int `json:"bonus_catches"`
	} `json:"cve_corpus"`
	Bench map[string]float64 `json:"bench_max_ns_op"`
}

var failed bool

func check(name string, got, want int) {
	if got != want {
		failed = true
		fmt.Printf("FAIL %-40s got %d, budget %d\n", name, got, want)
		return
	}
	fmt.Printf("ok   %-40s %d\n", name, got)
}

func main() {
	path := flag.String("budgets", "docs/budgets.json", "budget file")
	bench := flag.String("bench", "", "file with `go test -bench` output to check against bench_max_ns_op")
	skip := flag.String("skip", "", "regexp of bench names that may be absent from the output")
	flag.Parse()

	raw, err := os.ReadFile(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gate:", err)
		os.Exit(2)
	}
	var b budgets
	if err := json.Unmarshal(raw, &b); err != nil {
		fmt.Fprintln(os.Stderr, "gate: parse budgets:", err)
		os.Exit(2)
	}

	scenarios := corpus.All()
	r := corpus.Build(corpus.Run(scenarios))
	check("fp: scenarios", len(scenarios), b.FP.Scenarios)
	check("fp: EXFIL-tier false positives", r.FalsePositiveExfil, b.FP.ExfilFP)
	check("fp: detection true positives", r.TruePositives, b.FP.TP)
	check("fp: detection false negatives", r.FalseNegatives, b.FP.FN)
	check("fp: known-gap misses (pins)", r.KnownGapMisses, b.FP.KnownGap)
	check("fp: bonus catches", r.BonusCatches, b.FP.BonusCatches)

	cs := corpus.CVEScenarios()
	cr := corpus.BuildCVEReport(corpus.RunCVEScenarios(cs), corpus.CVEOutOfScope())
	caught, total := cr.ExfilCaught()
	check("cve: scenarios", len(cs), b.CVE.Scenarios)
	check("cve: EXFIL caught", caught, b.CVE.Caught)
	check("cve: EXFIL total", total, b.CVE.Total)
	check("cve: known-gap misses (pins)", cr.Base.KnownGapMisses, b.CVE.KnownGap)
	check("cve: regression misses", cr.Base.FalseNegatives, b.CVE.Regression)
	check("cve: bonus catches", cr.Base.BonusCatches, b.CVE.BonusCatches)

	if *bench != "" {
		checkBench(*bench, b.Bench, regexp.MustCompile(*skip))
	}
	if failed {
		fmt.Println("gate: FAILED")
		os.Exit(1)
	}
	fmt.Println("gate: passed")
}

var benchLine = regexp.MustCompile(`^(Benchmark\S+?)(?:-\d+)?\s+\d+\s+([\d.]+) ns/op`)

func checkBench(file string, max map[string]float64, skip *regexp.Regexp) {
	f, err := os.Open(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gate:", err)
		os.Exit(2)
	}
	defer f.Close()
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := benchLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		limit, ok := max[m[1]]
		if !ok {
			continue
		}
		ns, _ := strconv.ParseFloat(m[2], 64)
		seen[m[1]] = true
		if ns > limit {
			failed = true
			fmt.Printf("FAIL bench %-45s %.0f ns/op > budget %.0f\n", m[1], ns, limit)
		} else {
			fmt.Printf("ok   bench %-45s %.0f ns/op (budget %.0f)\n", m[1], ns, limit)
		}
	}
	for name := range max {
		if !seen[name] && (skip.String() == "" || !skip.MatchString(name)) {
			failed = true
			fmt.Printf("FAIL bench %-45s missing from output\n", name)
		}
	}
}
