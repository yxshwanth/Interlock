// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"os"
	"strconv"
	"testing"
)

// genParams: PR runs a fixed seed; the nightly job sets INTERLOCK_GEN_SEED
// and INTERLOCK_GEN_N to explore. A failure prints the seed that reproduces it.
func genParams() (seed int64, n int) {
	seed, n = 1, 300
	if v, err := strconv.ParseInt(os.Getenv("INTERLOCK_GEN_SEED"), 10, 64); err == nil {
		seed = v
	}
	if v, err := strconv.Atoi(os.Getenv("INTERLOCK_GEN_N")); err == nil && v > 0 {
		n = v
	}
	return
}

func TestGenerated_EveryAttackReachesExfil(t *testing.T) {
	seed, n := genParams()
	misses := 0
	for _, res := range Run(GenerateMalicious(seed, n)) {
		if !res.TrippedExfil {
			misses++
			if misses <= 10 {
				t.Errorf("MISS (seed=%d): %s verdicts=%v", seed, res.Scenario.ID, res.Verdicts)
			}
		}
	}
	t.Logf("seed=%d: %d generated attacks, %d missed EXFIL", seed, n, misses)
}

func TestGenerated_NoBenignFlowReachesExfil(t *testing.T) {
	seed, n := genParams()
	fp := 0
	for _, res := range Run(GenerateBenign(seed, n)) {
		if res.TrippedExfil {
			fp++
			if fp <= 10 {
				t.Errorf("EXFIL FALSE POSITIVE (seed=%d): %s verdicts=%v", seed, res.Scenario.ID, res.Verdicts)
			}
		}
	}
	t.Logf("seed=%d: %d generated benign flows, %d false EXFIL", seed, n, fp)
}

func TestGenerated_SameSeedSameScenarios(t *testing.T) {
	a, b := GenerateMalicious(7, 20), GenerateMalicious(7, 20)
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Description != b[i].Description {
			t.Fatalf("seed 7 is not deterministic at %d: %s vs %s", i, a[i].ID, b[i].ID)
		}
	}
}
