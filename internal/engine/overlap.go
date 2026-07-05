package engine

import (
	"encoding/json"
	"strings"

	"github.com/yxshwanth/Interlock/internal/model"
)

// CheckOverlap checks whether any tainted value (literal or canonical encoding)
// appears in the sink call's arguments. Returns the first hit, or nil.
func CheckOverlap(tainted []model.TaintedValue, sinkArgs json.RawMessage) *model.OverlapHit {
	if len(tainted) == 0 || len(sinkArgs) == 0 {
		return nil
	}

	argsStr := string(sinkArgs)

	for _, tv := range tainted {
		if hit := matchTaintedValue(argsStr, tv); hit != nil {
			return hit
		}
	}

	return nil
}

func matchTaintedValue(argsStr string, tv model.TaintedValue) *model.OverlapHit {
	forms := tv.Variants
	if len(forms) == 0 && tv.Value != "" {
		forms = variantsForLegacy(tv.Value)
	}

	for _, form := range forms {
		if form.Value == "" {
			continue
		}
		if strings.Contains(argsStr, form.Value) {
			return &model.OverlapHit{
				TaintedHash: tv.Hash,
				Preview:     tv.Preview,
				WhereFound:  "sink args",
				MatchForm:   form.Form,
			}
		}
	}
	return nil
}

// variantsForLegacy supports tests that construct TaintedValue without Variants.
func variantsForLegacy(value string) []model.TaintedVariant {
	forms := CanonicalEncodings(value)
	out := make([]model.TaintedVariant, len(forms))
	for i, f := range forms {
		out[i] = model.TaintedVariant{Form: string(f.Form), Value: f.Value}
	}
	return out
}
