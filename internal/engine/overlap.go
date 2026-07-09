package engine

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/yxshwanth/Interlock/internal/model"
)

// CheckOverlap checks whether any tainted value (literal or canonical encoding)
// appears in the sink call's arguments. Returns the first hit, or nil.
// If no direct hit, concatenates all JSON string values in the args object
// (same-call field reassembly) and retries.
func CheckOverlap(tainted []model.TaintedValue, sinkArgs json.RawMessage) *model.OverlapHit {
	hit := checkOverlapString(tainted, string(sinkArgs))
	if hit == nil {
		if reassembled := joinJSONStringValues(sinkArgs); reassembled != "" && reassembled != string(sinkArgs) {
			hit = checkOverlapString(tainted, reassembled)
		}
	}
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

// joinJSONStringValues concatenates all string leaves in a JSON value
// (depth-first, object key order as decoded by encoding/json).
func joinJSONStringValues(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	var b strings.Builder
	collectJSONStrings(v, &b)
	return b.String()
}

func collectJSONStrings(v any, b *strings.Builder) {
	switch t := v.(type) {
	case string:
		b.WriteString(t)
	case []any:
		for _, el := range t {
			collectJSONStrings(el, b)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			collectJSONStrings(t[k], b)
		}
	}
}

// variantsForLegacy supports tests that construct TaintedValue without Variants.
func variantsForLegacy(value string) []model.TaintedVariant {
	return CanonicalEncodings(value)
}
