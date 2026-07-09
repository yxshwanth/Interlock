package engine

import (
	"encoding/json"
	"strings"

	"github.com/yxshwanth/Interlock/internal/model"
)

// CheckOverlap checks whether any tainted value (literal or canonical encoding)
// appears in the sink call's arguments. Returns the first hit, or nil.
func CheckOverlap(tainted []model.TaintedValue, sinkArgs json.RawMessage) *model.OverlapHit {
	hit := checkOverlapString(tainted, string(sinkArgs))
	if hit != nil {
		hit.WhereFound = "sink args"
	}
	return hit
}

// CheckOverlapPayload checks egress payload bytes for tainted values.
func CheckOverlapPayload(tainted []model.TaintedValue, payload string) *model.OverlapHit {
	hit := checkOverlapString(tainted, payload)
	if hit != nil {
		hit.WhereFound = "egress payload"
	}
	return hit
}

func checkOverlapString(tainted []model.TaintedValue, haystack string) *model.OverlapHit {
	if len(tainted) == 0 || haystack == "" {
		return nil
	}
	for _, tv := range tainted {
		if hit := matchTaintedValue(haystack, tv); hit != nil {
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
				WhereFound:  "", // filled by CheckOverlap / CheckOverlapPayload
				MatchForm:   form.Form,
			}
		}
	}
	return nil
}

// variantsForLegacy supports tests that construct TaintedValue without Variants.
func variantsForLegacy(value string) []model.TaintedVariant {
	return CanonicalEncodings(value)
}
