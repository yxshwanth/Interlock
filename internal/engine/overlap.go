package engine

import (
	"encoding/json"
	"strings"

	"github.com/yxshwanth/Interlock/internal/model"
)

// CheckOverlap checks whether any tainted value appears in the sink call's
// arguments. It performs a substring match of each tainted value's raw Value
// against the JSON-serialized sink args. Returns the first hit, or nil.
func CheckOverlap(tainted []model.TaintedValue, sinkArgs json.RawMessage) *model.OverlapHit {
	if len(tainted) == 0 || len(sinkArgs) == 0 {
		return nil
	}

	argsStr := string(sinkArgs)

	for _, tv := range tainted {
		if tv.Value == "" {
			continue
		}
		if strings.Contains(argsStr, tv.Value) {
			return &model.OverlapHit{
				TaintedHash: tv.Hash,
				Preview:     tv.Preview,
				WhereFound:  "sink args",
			}
		}
	}

	return nil
}
