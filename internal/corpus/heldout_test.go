// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// The held-out set (ROADMAP §83) is never used for tuning. Two things make
// that auditable:
//   - data/heldout_expected.json pins the file's sha256, so editing a scenario
//     is a visible act in review, not a quiet one;
//   - it pins every outcome the detector produced when the set was first run,
//     misses included. A miss here is information to publish
//     (docs/heldout_corpus.md), not a regression to be fixed by tuning.
// To add scenarios, create a new file (heldout_v2.json) rather than editing this one.

type heldoutPin struct {
	SHA256   string            `json:"sha256"`
	Outcomes map[string]string `json:"outcomes"`
}

func heldoutRun(t *testing.T) ([]Result, string) {
	raw, err := dataFS.ReadFile("data/heldout.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return Run(loadScenarios("heldout.json")), hex.EncodeToString(sum[:])
}

func TestHeldout_FrozenAndOutcomesPinned(t *testing.T) {
	results, sum := heldoutRun(t)
	if os.Getenv("INTERLOCK_HELDOUT_UPDATE") != "" {
		pin := heldoutPin{SHA256: sum, Outcomes: map[string]string{}}
		for _, r := range results {
			pin.Outcomes[r.Scenario.ID] = string(r.Outcome)
		}
		b, _ := json.MarshalIndent(pin, "", "  ")
		if err := os.WriteFile("data/heldout_expected.json", append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Skip("pin rewritten; review the diff before committing")
	}
	var pin heldoutPin
	readData("heldout_expected.json", &pin)
	if pin.SHA256 != sum {
		t.Errorf("data/heldout.json changed (sha256 %s, pinned %s). The held-out set is frozen: add a new file instead of editing this one", sum, pin.SHA256)
	}
	for _, r := range results {
		want, ok := pin.Outcomes[r.Scenario.ID]
		switch {
		case !ok:
			t.Errorf("%s has no pinned outcome", r.Scenario.ID)
		case want != string(r.Outcome):
			t.Errorf("%s: outcome %s, pinned %s. Do not tune the engine against this set; if the change is intended, record it in docs/heldout_corpus.md and re-pin", r.Scenario.ID, r.Outcome, want)
		}
	}
	if len(pin.Outcomes) != len(results) {
		t.Errorf("pinned %d outcomes, ran %d scenarios", len(pin.Outcomes), len(results))
	}
}

// The published numbers must come from the pins, not from memory.
func TestHeldout_DocMatchesPins(t *testing.T) {
	var pin heldoutPin
	readData("heldout_expected.json", &pin)
	var tp, mal int
	var misses []string
	for _, sc := range loadScenarios("heldout.json") {
		if sc.Category != Malicious {
			continue
		}
		mal++
		if pin.Outcomes[sc.ID] == string(OutcomeTruePositive) {
			tp++
		} else {
			misses = append(misses, sc.ID)
		}
	}
	doc, err := os.ReadFile("../../docs/heldout_corpus.md")
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("| %d/%d (", tp, mal); !strings.Contains(string(doc), want) {
		t.Errorf("docs/heldout_corpus.md does not state %q", want)
	}
	for _, id := range misses {
		if !strings.Contains(string(doc), "`"+id+"`") {
			t.Errorf("docs/heldout_corpus.md does not list the miss %s", id)
		}
	}
}
