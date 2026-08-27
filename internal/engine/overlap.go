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
// (same-call field reassembly) and retries. On still-miss, attempts a bounded
// recursive base64/hex decode on JSON string leaves, then bounded container
// descent (ROADMAP §20).
func CheckOverlap(tainted []model.TaintedValue, sinkArgs json.RawMessage) *model.OverlapHit {
	hit, _ := CheckOverlapLimited(tainted, sinkArgs, DefaultContainerLimits())
	return hit
}

// CheckOverlapLimited is CheckOverlap with explicit container limits.
// abort is non-empty when a recognized container was inspected but a hard
// cap fired — callers may soft-SUSPICIOUS; never treat abort as EXFIL.
func CheckOverlapLimited(tainted []model.TaintedValue, sinkArgs json.RawMessage, lim ContainerLimits) (*model.OverlapHit, ContainerAbortReason) {
	hit := checkOverlapString(tainted, string(sinkArgs))
	if hit == nil {
		if reassembled := joinJSONStringValues(sinkArgs); reassembled != "" && reassembled != string(sinkArgs) {
			hit = checkOverlapString(tainted, reassembled)
		}
	}
	if hit == nil {
		hit = checkOverlapDecoded(tainted, decodeCandidatesFromArgs(sinkArgs))
	}
	var abort ContainerAbortReason
	if hit == nil {
		hit, abort = checkOverlapContainerCandidates(tainted, containerCandidatesFromArgs(sinkArgs), lim)
	}
	if hit != nil {
		hit.WhereFound = "sink args"
	}
	return hit, abort
}

// CheckOverlapPayload checks egress payload bytes for tainted values.
// On miss, attempts bounded recursive base64/hex decode, then container descent.
func CheckOverlapPayload(tainted []model.TaintedValue, payload string) *model.OverlapHit {
	hit, _ := CheckOverlapPayloadLimited(tainted, payload, DefaultContainerLimits())
	return hit
}

// CheckOverlapPayloadLimited is CheckOverlapPayload with explicit container limits.
func CheckOverlapPayloadLimited(tainted []model.TaintedValue, payload string, lim ContainerLimits) (*model.OverlapHit, ContainerAbortReason) {
	hit := checkOverlapString(tainted, payload)
	if hit == nil {
		hit = checkOverlapDecoded(tainted, decodeCandidatesFromPayload(payload))
	}
	var abort ContainerAbortReason
	if hit == nil {
		hit, abort = checkOverlapContainerCandidates(tainted, containerCandidatesFromPayload(payload), lim)
	}
	if hit != nil {
		hit.WhereFound = "egress payload"
	}
	return hit, abort
}

func containerCandidatesFromArgs(sinkArgs json.RawMessage) [][]byte {
	var out [][]byte
	seen := map[string]struct{}{}
	add := func(raw []byte) {
		blob := unwrapContainerBlob(raw)
		if blob == nil {
			return
		}
		key := string(blob)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, blob)
	}
	for _, leaf := range decodeCandidatesFromArgs(sinkArgs) {
		add([]byte(leaf))
	}
	add([]byte(string(sinkArgs)))
	return out
}

func containerCandidatesFromPayload(payload string) [][]byte {
	var out [][]byte
	seen := map[string]struct{}{}
	add := func(raw []byte) {
		blob := unwrapContainerBlob(raw)
		if blob == nil {
			return
		}
		key := string(blob)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, blob)
	}
	add([]byte(payload))
	for _, c := range decodeCandidatesFromPayload(payload) {
		add([]byte(c))
	}
	return out
}

// unwrapContainerBlob returns raw container bytes if raw (or a single-layer
// std/raw base64 unwrap of raw) sniffs as a recognized container. Binary ZIP
// etc. cannot round-trip through JSON strings as UTF-8; MCP often carries them
// base64-wrapped in text fields — §20 must unwrap that packaging.
func unwrapContainerBlob(raw []byte) []byte {
	if LooksLikeContainer(raw) {
		return raw
	}
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil
	}
	if dec, ok := tryBase64(s); ok && LooksLikeContainer([]byte(dec)) {
		return []byte(dec)
	}
	return nil
}

func checkOverlapContainerCandidates(tainted []model.TaintedValue, candidates [][]byte, lim ContainerLimits) (*model.OverlapHit, ContainerAbortReason) {
	var lastAbort ContainerAbortReason
	for _, raw := range candidates {
		hit, abort := checkOverlapContainer(tainted, raw, lim)
		if hit != nil {
			return hit, ContainerAbortNone
		}
		if abort != ContainerAbortNone {
			lastAbort = abort
		}
	}
	return nil, lastAbort
}

func checkOverlapContainer(tainted []model.TaintedValue, raw []byte, lim ContainerLimits) (*model.OverlapHit, ContainerAbortReason) {
	if !lim.Enabled || !LooksLikeContainer(raw) {
		return nil, ContainerAbortNone
	}
	res := InspectContainer(raw, lim)
	if res.Abort != ContainerAbortNone {
		return nil, res.Abort
	}
	for _, part := range res.Parts {
		if hit := checkOverlapString(tainted, part); hit != nil {
			if hit.MatchForm == "" || hit.MatchForm == string(FormLiteral) {
				hit.MatchForm = "container_" + string(FormLiteral)
			} else {
				hit.MatchForm = "container_" + hit.MatchForm
			}
			return hit, ContainerAbortNone
		}
	}
	return nil, ContainerAbortNone
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
	// Long-secret chunk match (ROADMAP §8): after full-variant miss, search
	// precomputed contiguous N-byte chunks of the literal body.
	for _, ch := range tv.Chunks {
		if ch.Value == "" {
			continue
		}
		if strings.Contains(argsStr, ch.Value) {
			return &model.OverlapHit{
				TaintedHash: tv.Hash,
				Preview:     tv.Preview,
				WhereFound:  "",
				MatchForm:   ch.Form,
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
