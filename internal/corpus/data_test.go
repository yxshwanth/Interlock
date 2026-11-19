// SPDX-License-Identifier: Apache-2.0

package corpus

import "testing"

func allData() []Scenario {
	return append(All(), CVEScenarios()...)
}

func TestData_ShapeIsValid(t *testing.T) {
	scs := allData()
	assertUniqueIDs(t, scs)
	for _, sc := range scs {
		if sc.Category != Malicious && sc.Category != Benign {
			t.Errorf("%s: category %q", sc.ID, sc.Category)
		}
		switch sc.Variant {
		case VariantProxyA, VariantEbpfB, VariantSensorB:
		default:
			t.Errorf("%s: variant %q", sc.ID, sc.Variant)
		}
		if len(sc.Steps) == 0 {
			t.Errorf("%s: no steps", sc.ID)
		}
		for i, s := range sc.Steps {
			switch s.Kind {
			case StepResult, StepRequest:
				if s.Event.SessionID == "" || s.Event.ToolName == "" {
					t.Errorf("%s step %d: %s needs session_id and tool_name", sc.ID, i, s.Kind)
				}
			case StepSyscall, StepSyscallSensor:
				if s.Syscall.Syscall == "" { // session_id may be empty: unattributed events are a scenario
					t.Errorf("%s step %d: %s needs a syscall", sc.ID, i, s.Kind)
				}
			case StepAdvanceTime:
				if s.SessionID == "" || s.AdvanceBy <= 0 {
					t.Errorf("%s step %d: advance_time needs session_id and a positive advance_by", sc.ID, i)
				}
			default:
				t.Errorf("%s step %d: kind %q", sc.ID, i, s.Kind)
			}
		}
	}
}

// Every KnownGap carries a machine-readable reason from the closed set in
// data/gap_tags.json, and no tag is defined without a scenario using it.
func TestData_GapTagsAreClosedAndUsed(t *testing.T) {
	var defined map[string]string
	readData("gap_tags.json", &defined)
	used := map[string]bool{}
	for _, sc := range allData() {
		switch {
		case sc.KnownGap && sc.GapTag == "":
			t.Errorf("%s: known_gap without gap_tag", sc.ID)
		case !sc.KnownGap && sc.GapTag != "":
			t.Errorf("%s: gap_tag %q on a scenario that is not a known_gap", sc.ID, sc.GapTag)
		case sc.KnownGap:
			if _, ok := defined[sc.GapTag]; !ok {
				t.Errorf("%s: gap_tag %q is not in data/gap_tags.json", sc.ID, sc.GapTag)
			}
			used[sc.GapTag] = true
		}
	}
	for tag := range defined {
		if !used[tag] {
			t.Errorf("gap tag %q is defined but no scenario uses it", tag)
		}
	}
}
