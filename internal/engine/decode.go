package engine

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/yxshwanth/Interlock/internal/model"
)

const (
	maxDecodeDepth     = 3
	maxDecodeBytes     = 8 * 1024
	minDecodeCandidate = 4
)

// singleLayerForms are the forms matched against after each decode step.
// Depth-2 nests are intentionally excluded — the recursive decoder unwraps instead.
var singleLayerForms = []EncodingForm{
	FormLiteral,
	FormBase64,
	FormHex,
	FormURLEncoded,
	FormReversed,
}

// checkOverlapDecoded attempts bounded base64/hex unwrap on candidate strings
// after the fast-path Contains scan missed. Depth is capped at maxDecodeDepth.
func checkOverlapDecoded(tainted []model.TaintedValue, candidates []string) *model.OverlapHit {
	if len(tainted) == 0 || len(candidates) == 0 {
		return nil
	}
	for _, c := range candidates {
		if len(c) < minDecodeCandidate || len(c) > maxDecodeBytes {
			continue
		}
		if hit := decodeMatchCandidates(c, tainted, nil, 0); hit != nil {
			return hit
		}
	}
	return nil
}

func decodeMatchCandidates(s string, tainted []model.TaintedValue, path []string, depth int) *model.OverlapHit {
	if depth >= maxDecodeDepth || s == "" || len(s) > maxDecodeBytes {
		return nil
	}

	type attempt struct {
		layer string
		decoded string
	}
	var attempts []attempt

	if d, ok := tryBase64(s); ok {
		attempts = append(attempts, attempt{layer: "base64", decoded: d})
	}
	if d, ok := tryHex(s); ok {
		attempts = append(attempts, attempt{layer: "hex", decoded: d})
	}

	for _, a := range attempts {
		if a.decoded == "" || len(a.decoded) > maxDecodeBytes {
			continue
		}
		newPath := append(append([]string(nil), path...), a.layer)
		if hit := matchSingleLayer(a.decoded, tainted, newPath); hit != nil {
			return hit
		}
		if !plausibleDecoded(a.decoded) {
			continue
		}
		if hit := decodeMatchCandidates(a.decoded, tainted, newPath, depth+1); hit != nil {
			return hit
		}
	}
	return nil
}

func matchSingleLayer(haystack string, tainted []model.TaintedValue, path []string) *model.OverlapHit {
	formName := "decoded_" + strings.Join(path, "_")
	for _, tv := range tainted {
		forms := tv.Variants
		if len(forms) == 0 && tv.Value != "" {
			forms = variantsForLegacy(tv.Value)
		}
		for _, form := range forms {
			if form.Value == "" || !isSingleLayerForm(form.Form) {
				continue
			}
			if strings.Contains(haystack, form.Value) {
				return &model.OverlapHit{
					TaintedHash: tv.Hash,
					Preview:     tv.Preview,
					MatchForm:   formName,
				}
			}
		}
		// Legacy / empty-variants: still match raw Value.
		if tv.Value != "" && strings.Contains(haystack, tv.Value) {
			return &model.OverlapHit{
				TaintedHash: tv.Hash,
				Preview:     tv.Preview,
				MatchForm:   formName,
			}
		}
	}
	return nil
}

func isSingleLayerForm(form string) bool {
	for _, f := range singleLayerForms {
		if form == string(f) {
			return true
		}
	}
	return false
}

func tryBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < minDecodeCandidate {
		return "", false
	}
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(dec), true
	}
	if dec, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return string(dec), true
	}
	return "", false
}

func tryHex(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < minDecodeCandidate || len(s)%2 != 0 {
		return "", false
	}
	// Cheap reject: non-hex chars.
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "", false
		}
	}
	dec, err := hex.DecodeString(s)
	if err != nil {
		return "", false
	}
	return string(dec), true
}

// plausibleDecoded gates further recursion after a successful decode.
func plausibleDecoded(s string) bool {
	if s == "" || len(s) > maxDecodeBytes {
		return false
	}
	if looksLikeHex(s) || looksLikeBase64(s) {
		return true
	}
	return mostlyPrintable(s)
}

func mostlyPrintable(s string) bool {
	if !utf8.ValidString(s) {
		// Allow binary that may be another encoding layer only if high printable ratio.
		printable := 0
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c >= 0x20 && c < 0x7f || c == '\n' || c == '\r' || c == '\t' {
				printable++
			}
		}
		return printable*100/len(s) >= 80
	}
	printable := 0
	for _, r := range s {
		if r >= 0x20 && r != 0x7f || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	n := utf8.RuneCountInString(s)
	if n == 0 {
		return false
	}
	return printable*100/n >= 80
}

func looksLikeHex(s string) bool {
	if len(s) < minDecodeCandidate || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func looksLikeBase64(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < minDecodeCandidate {
		return false
	}
	pad := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			if pad > 0 {
				return false
			}
		case c == '=':
			pad++
			if pad > 2 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// jsonStringLeaves returns each JSON string leaf (not concatenated).
func jsonStringLeaves(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	var out []string
	collectJSONStringLeaves(v, &out)
	return out
}

func collectJSONStringLeaves(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case []any:
		for _, el := range t {
			collectJSONStringLeaves(el, out)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			collectJSONStringLeaves(t[k], out)
		}
	}
}

func decodeCandidatesFromArgs(sinkArgs json.RawMessage) []string {
	leaves := jsonStringLeaves(sinkArgs)
	if len(leaves) > 0 {
		return leaves
	}
	// Non-JSON body: treat whole payload as one candidate.
	s := string(sinkArgs)
	if s != "" {
		return []string{s}
	}
	return nil
}

func decodeCandidatesFromPayload(payload string) []string {
	if payload == "" {
		return nil
	}
	out := []string{payload}
	if leaves := jsonStringLeaves(json.RawMessage(payload)); len(leaves) > 0 {
		out = append(out, leaves...)
	}
	return out
}
