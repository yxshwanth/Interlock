package engine

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"testing"
)

func TestCanonicalEncodings_Deterministic(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	forms := CanonicalEncodings(secret)

	if len(forms) != 5 {
		t.Fatalf("expected 5 forms, got %d", len(forms))
	}

	want := map[string]string{
		string(FormLiteral):    secret,
		string(FormBase64):     base64.StdEncoding.EncodeToString([]byte(secret)),
		string(FormHex):        hex.EncodeToString([]byte(secret)),
		string(FormURLEncoded): url.QueryEscape(secret),
		string(FormReversed):   reverseString(secret),
	}

	for _, f := range forms {
		got, ok := want[f.Form]
		if !ok {
			t.Fatalf("unexpected form %q", f.Form)
		}
		if f.Value != got {
			t.Fatalf("form %q: got %q, want %q", f.Form, f.Value, got)
		}
	}
}

func TestCanonicalEncodings_Empty(t *testing.T) {
	if forms := CanonicalEncodings(""); forms != nil {
		t.Fatalf("expected nil for empty value, got %v", forms)
	}
}

func TestCanonicalEncodings_ReversedDiffers(t *testing.T) {
	secret := "abcdef"
	forms := CanonicalEncodings(secret)
	var reversed string
	for _, f := range forms {
		if f.Form == string(FormReversed) {
			reversed = f.Value
		}
	}
	if reversed == secret {
		t.Fatal("reversed form should differ from literal")
	}
	if reversed != "fedcba" {
		t.Fatalf("reversed = %q", reversed)
	}
}
