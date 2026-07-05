package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

func TestHashValue(t *testing.T) {
	h := HashValue("test-secret")
	if len(h) != 64 {
		t.Fatalf("expected 64-char hex hash, got %d chars: %q", len(h), h)
	}
	// Same input should produce same hash (deterministic).
	if HashValue("test-secret") != h {
		t.Fatal("hash is not deterministic")
	}
	// Different input should produce different hash.
	if HashValue("other-secret") == h {
		t.Fatal("different inputs produced the same hash")
	}
}

func TestMaskValue_Long(t *testing.T) {
	got := MaskValue("sk-live-51TxJANEd0eR3aLt0k3n")
	// Should show first 3 and last 4.
	if !strings.HasPrefix(got, "sk-") {
		t.Fatalf("expected prefix 'sk-', got %q", got)
	}
	if !strings.HasSuffix(got, "0k3n") {
		t.Fatalf("expected suffix '0k3n', got %q", got)
	}
	if !strings.Contains(got, "...") {
		t.Fatalf("expected '...' in masked value, got %q", got)
	}
	// Must not contain the full value.
	if got == "sk-live-51TxJANEd0eR3aLt0k3n" {
		t.Fatal("masked value should not equal the original")
	}
}

func TestMaskValue_Short(t *testing.T) {
	got := MaskValue("abcde")
	if got != "ab...de" {
		t.Fatalf("expected 'ab...de' for short value, got %q", got)
	}
}

func TestMaskValue_VeryShort(t *testing.T) {
	got := MaskValue("abc")
	if got != "****" {
		t.Fatalf("expected '****' for very short value, got %q", got)
	}
}

func TestExtractTaintedValues_APIKey(t *testing.T) {
	text := `Customer Auth Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef
Account ID: acct_prod_jane_7291`

	values := ExtractTaintedValues(text, "tickets/read_ticket", 5)
	if len(values) < 2 {
		t.Fatalf("expected at least 2 tainted values, got %d", len(values))
	}

	found := map[string]bool{}
	for _, v := range values {
		found[v.Value] = true
		if v.Hash == "" {
			t.Errorf("value %q has empty hash", v.Preview)
		}
		if v.Preview == "" {
			t.Errorf("value %q has empty preview", v.Value)
		}
		if v.Source != "tickets/read_ticket" {
			t.Errorf("expected source 'tickets/read_ticket', got %q", v.Source)
		}
		if v.Seq != 5 {
			t.Errorf("expected seq 5, got %d", v.Seq)
		}
		if v.RegisteredAt == 0 {
			t.Error("expected RegisteredAt to be set")
		}
	}

	if !found["sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"] {
		t.Error("expected to extract the sk-live API key")
	}
	if !found["acct_prod_jane_7291"] {
		t.Error("expected to extract the account ID")
	}
}

func TestExtractTaintedValues_BearerToken(t *testing.T) {
	text := `Auth Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`

	values := ExtractTaintedValues(text, "auth/get_token", 1)
	if len(values) == 0 {
		t.Fatal("expected to extract bearer token")
	}

	found := false
	for _, v := range values {
		if strings.Contains(v.Value, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
			found = true
		}
	}
	if !found {
		t.Error("expected to find the JWT-like token")
	}
}

func TestExtractTaintedValues_Deduplication(t *testing.T) {
	text := `Token: sk-live-abcdefghij1234567890
Repeated: sk-live-abcdefghij1234567890`

	values := ExtractTaintedValues(text, "src", 1)
	count := 0
	for _, v := range values {
		if v.Value == "sk-live-abcdefghij1234567890" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected deduplicated to 1, got %d", count)
	}
}

func TestExtractTaintedValues_NoSecrets(t *testing.T) {
	text := "Hello, this is a regular message with no secrets."
	values := ExtractTaintedValues(text, "src", 1)
	if len(values) != 0 {
		t.Fatalf("expected no tainted values, got %d", len(values))
	}
}

func TestTaintedValue_JSONExcludesRawValue(t *testing.T) {
	tv := model.TaintedValue{
		Value:        "sk-live-SECRET",
		Hash:         HashValue("sk-live-SECRET"),
		Preview:      MaskValue("sk-live-SECRET"),
		Source:       "test",
		Seq:          1,
		RegisteredAt: 12345,
	}

	data, err := json.Marshal(tv)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	s := string(data)
	if strings.Contains(s, "sk-live-SECRET") {
		t.Fatalf("JSON serialization must NOT contain the raw value: %s", s)
	}
	if !strings.Contains(s, `"hash"`) {
		t.Fatal("JSON should contain the hash field")
	}
	if !strings.Contains(s, `"preview"`) {
		t.Fatal("JSON should contain the preview field")
	}
}

func TestExtractTaintedValues_MultiplePatterns(t *testing.T) {
	text := `API Key: sk-test-longEnoughToMatch12345
Token: bearer myLongAccessTokenValue1234567890
Account: acct_user_admin_99`

	values := ExtractTaintedValues(text, "multi", 3)
	if len(values) < 3 {
		t.Fatalf("expected at least 3 tainted values from different patterns, got %d", len(values))
	}
}

func TestRedactJSON_EncodedVariants(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	tainted := ExtractTaintedValues(secret, "src", 1)
	if len(tainted) == 0 {
		t.Fatal("expected tainted value")
	}

	var b64 string
	for _, v := range tainted[0].Variants {
		if v.Form == string(FormBase64) {
			b64 = v.Value
		}
	}
	if b64 == "" {
		t.Fatal("expected base64 variant")
	}

	raw := json.RawMessage(`{"body":"` + b64 + `"}`)
	redacted := RedactJSON(raw, tainted)
	if strings.Contains(string(redacted), b64) {
		t.Fatalf("base64 variant should be redacted, got %s", redacted)
	}
	if !strings.Contains(string(redacted), tainted[0].Preview) {
		t.Fatalf("expected masked preview in output, got %s", redacted)
	}
}
