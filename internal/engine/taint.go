package engine

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

// Secret-matching patterns. Each pattern extracts candidate secrets from
// tool result text. The patterns are intentionally broad for v0.1 —
// false positives are preferable to missed exfil.
var secretPatterns = []*regexp.Regexp{
	// Stripe-style API keys: sk-live-..., sk-test-..., sk_live_..., sk_test_...
	regexp.MustCompile(`\b(sk[-_](?:live|test)[-_][A-Za-z0-9]{10,})\b`),
	// Generic API keys: api_key, apikey, api-key followed by a value
	regexp.MustCompile(`\b(api[-_]?key[-_]?[A-Za-z0-9]{16,})\b`),
	// Bearer tokens (standalone long hex/base64 strings after "token" context)
	regexp.MustCompile(`(?i)(?:auth[_ ]?token|bearer|token)[:\s]+["']?([A-Za-z0-9+/=_-]{20,})["']?`),
	// Account IDs: acct_..., account_...
	regexp.MustCompile(`\b(acct_[A-Za-z0-9_]{8,})\b`),
}

// ExtractTaintedValues scans resultText for candidate secrets and returns
// them as TaintedValues with hashed+masked representations. The raw value
// is kept in memory only (json:"-" on the struct) and is never serialized.
func ExtractTaintedValues(resultText, source string, seq uint64) []model.TaintedValue {
	seen := make(map[string]bool)
	var values []model.TaintedValue
	now := time.Now().UnixNano()

	for _, pat := range secretPatterns {
		matches := pat.FindAllStringSubmatch(resultText, -1)
		for _, m := range matches {
			val := m[1]
			if seen[val] {
				continue
			}
			seen[val] = true

			values = append(values, model.TaintedValue{
				Value:        val,
				Hash:         HashValue(val),
				Preview:      MaskValue(val),
				Source:       source,
				Seq:          seq,
				RegisteredAt: now,
			})
		}
	}

	return values
}

// HashValue returns the hex-encoded SHA-256 hash of the value.
func HashValue(value string) string {
	h := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", h)
}

// MaskValue returns a masked preview of the value, showing the first 3
// characters and last 4 characters with "..." in between.
// Short values (<=10 chars) show first 2 and last 2.
func MaskValue(value string) string {
	n := len(value)
	switch {
	case n <= 4:
		return "****"
	case n <= 10:
		return value[:2] + "..." + value[n-2:]
	default:
		return value[:3] + "..." + value[n-4:]
	}
}

// RedactJSON replaces all known tainted values in a JSON blob with their
// masked previews. Returns the scrubbed blob. If tainted is empty or raw
// is nil/empty, the input is returned unchanged.
func RedactJSON(raw json.RawMessage, tainted []model.TaintedValue) json.RawMessage {
	if len(raw) == 0 || len(tainted) == 0 {
		return raw
	}
	s := string(raw)
	for _, tv := range tainted {
		if tv.Value == "" {
			continue
		}
		s = strings.ReplaceAll(s, tv.Value, tv.Preview)
	}
	return json.RawMessage(s)
}
