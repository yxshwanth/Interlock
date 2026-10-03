package engine

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

func TestCanonicalEncodings_Deterministic(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	forms := CanonicalEncodings(secret)

	// 5 single + 4 depth-2 + gzip/brotli/zstd/lz4_base64
	if len(forms) != 13 {
		t.Fatalf("expected 13 forms, got %d", len(forms))
	}

	want := map[string]string{
		string(FormLiteral):    secret,
		string(FormBase64):     base64.StdEncoding.EncodeToString([]byte(secret)),
		string(FormHex):        hex.EncodeToString([]byte(secret)),
		string(FormURLEncoded): url.QueryEscape(secret),
		string(FormReversed):   model.ReverseString(secret),
		string(FormBase64Hex):  base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte(secret)))),
		string(FormHexBase64):  hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(secret)))),
		string(FormBase64URL):  base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(secret))),
		string(FormBase64Rev):  base64.StdEncoding.EncodeToString([]byte(model.ReverseString(secret))),
	}
	for _, pair := range []struct {
		form EncodingForm
		fn   func(string) (string, error)
	}{
		{FormGzipBase64, gzipBase64},
		{FormBrotliBase64, brotliBase64},
		{FormZstdBase64, zstdBase64},
		{FormLZ4Base64, lz4Base64},
	} {
		v, err := pair.fn(secret)
		if err != nil {
			t.Fatalf("%s: %v", pair.form, err)
		}
		want[string(pair.form)] = v
	}

	seen := map[string]bool{}
	for _, f := range forms {
		got, ok := want[f.Form]
		if !ok {
			t.Fatalf("unexpected form %q", f.Form)
		}
		if f.Value != got {
			t.Fatalf("form %q: got %q, want %q", f.Form, f.Value, got)
		}
		seen[f.Form] = true
	}
	for name := range want {
		if !seen[name] {
			t.Fatalf("missing form %q", name)
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
