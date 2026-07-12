package engine

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

func TestCheckOverlap_Match(t *testing.T) {
	tainted := []model.TaintedValue{
		{Value: "sk-live-SECRET123", Hash: "abc123", Preview: "sk-...123"},
	}
	args := json.RawMessage(`{"body": "exfil sk-live-SECRET123 here"}`)

	hit := CheckOverlap(tainted, args)
	if hit == nil {
		t.Fatal("expected overlap hit, got nil")
	}
	if hit.TaintedHash != "abc123" {
		t.Fatalf("expected hash 'abc123', got %q", hit.TaintedHash)
	}
	if hit.Preview != "sk-...123" {
		t.Fatalf("expected preview 'sk-...123', got %q", hit.Preview)
	}
	if hit.WhereFound != "sink args" {
		t.Fatalf("expected 'sink args', got %q", hit.WhereFound)
	}
	if hit.MatchForm != string(FormLiteral) {
		t.Fatalf("expected match_form literal, got %q", hit.MatchForm)
	}
}

func TestCheckOverlap_NoMatch(t *testing.T) {
	tainted := []model.TaintedValue{
		{Value: "sk-live-SECRET123", Hash: "abc123", Preview: "sk-...123"},
	}
	args := json.RawMessage(`{"body": "hello world, nothing secret"}`)

	hit := CheckOverlap(tainted, args)
	if hit != nil {
		t.Fatalf("expected no overlap, got %+v", hit)
	}
}

func TestCheckOverlap_EmptyTainted(t *testing.T) {
	hit := CheckOverlap(nil, json.RawMessage(`{"body": "anything"}`))
	if hit != nil {
		t.Fatalf("expected nil with empty tainted list, got %+v", hit)
	}
}

func TestCheckOverlap_EmptyArgs(t *testing.T) {
	tainted := []model.TaintedValue{
		{Value: "secret", Hash: "h", Preview: "p"},
	}
	hit := CheckOverlap(tainted, nil)
	if hit != nil {
		t.Fatalf("expected nil with nil args, got %+v", hit)
	}
}

func TestCheckOverlap_FirstHitReturned(t *testing.T) {
	tainted := []model.TaintedValue{
		{Value: "first-secret", Hash: "hash1", Preview: "p1"},
		{Value: "second-secret", Hash: "hash2", Preview: "p2"},
	}
	args := json.RawMessage(`{"body": "contains second-secret and first-secret"}`)

	hit := CheckOverlap(tainted, args)
	if hit == nil {
		t.Fatal("expected overlap hit")
	}
	if hit.TaintedHash != "hash1" {
		t.Fatalf("expected first hit (hash1), got %q", hit.TaintedHash)
	}
}

func TestCheckOverlap_PartialMatch(t *testing.T) {
	tainted := []model.TaintedValue{
		{Value: "sk-live-fulltoken", Hash: "h", Preview: "p"},
	}
	// Only a prefix is present, not the full value.
	args := json.RawMessage(`{"body": "sk-live-full"}`)

	hit := CheckOverlap(tainted, args)
	if hit != nil {
		t.Fatalf("partial match should not trigger overlap, got %+v", hit)
	}
}

func TestCheckOverlap_EmptyValueSkipped(t *testing.T) {
	tainted := []model.TaintedValue{
		{Value: "", Hash: "h", Preview: "p"},
		{Value: "real-secret", Hash: "h2", Preview: "p2"},
	}
	args := json.RawMessage(`{"body": "real-secret"}`)

	hit := CheckOverlap(tainted, args)
	if hit == nil {
		t.Fatal("expected hit on second value")
	}
	if hit.TaintedHash != "h2" {
		t.Fatalf("expected h2, got %q", hit.TaintedHash)
	}
}

func TestCheckOverlap_EncodedExfil_KnownGap(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))

	tainted := []model.TaintedValue{
		{
			Value:    secret,
			Variants: CanonicalEncodings(secret),
			Hash:     HashValue(secret),
			Preview:  MaskValue(secret),
		},
	}
	args := json.RawMessage(`{"body": "` + encoded + `"}`)

	hit := CheckOverlap(tainted, args)
	if hit == nil {
		t.Fatal("expected overlap hit on base64-encoded secret")
	}
	if hit.MatchForm != string(FormBase64) {
		t.Fatalf("expected match_form base64, got %q", hit.MatchForm)
	}
}

func TestCheckOverlap_HexEncoded(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	encoded := hex.EncodeToString([]byte(secret))

	tainted := []model.TaintedValue{
		{Value: secret, Variants: CanonicalEncodings(secret), Hash: HashValue(secret), Preview: MaskValue(secret)},
	}
	args := json.RawMessage(`{"body": "` + encoded + `"}`)

	hit := CheckOverlap(tainted, args)
	if hit == nil {
		t.Fatal("expected overlap hit on hex-encoded secret")
	}
	if hit.MatchForm != string(FormHex) {
		t.Fatalf("expected match_form hex, got %q", hit.MatchForm)
	}
}

func TestCheckOverlap_URLEncoded(t *testing.T) {
	secret := "sk-live+token/special=value"
	encoded := url.QueryEscape(secret)
	if encoded == secret {
		t.Fatal("test secret must require URL encoding")
	}

	tainted := []model.TaintedValue{
		{Value: secret, Variants: CanonicalEncodings(secret), Hash: HashValue(secret), Preview: MaskValue(secret)},
	}
	args := json.RawMessage(`{"body": "` + encoded + `"}`)

	hit := CheckOverlap(tainted, args)
	if hit == nil {
		t.Fatal("expected overlap hit on URL-encoded secret")
	}
	if hit.MatchForm != string(FormURLEncoded) {
		t.Fatalf("expected match_form url_encoded, got %q", hit.MatchForm)
	}
}

func TestCheckOverlap_Reversed(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	reversed := reverseString(secret)

	tainted := []model.TaintedValue{
		{Value: secret, Variants: CanonicalEncodings(secret), Hash: HashValue(secret), Preview: MaskValue(secret)},
	}
	args := json.RawMessage(`{"body": "` + reversed + `"}`)

	hit := CheckOverlap(tainted, args)
	if hit == nil {
		t.Fatal("expected overlap hit on reversed secret")
	}
	if hit.MatchForm != string(FormReversed) {
		t.Fatalf("expected match_form reversed, got %q", hit.MatchForm)
	}
}

func TestCheckOverlap_SameCallFieldReassembly(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	half := len(secret) / 2
	tainted := []model.TaintedValue{
		{Value: secret, Variants: CanonicalEncodings(secret), Hash: HashValue(secret), Preview: MaskValue(secret)},
	}
	args := json.RawMessage(`{"part_a": "` + secret[:half] + `", "part_b": "` + secret[half:] + `"}`)

	hit := CheckOverlap(tainted, args)
	if hit == nil {
		t.Fatal("expected overlap when split parts rejoin in same-call sink args")
	}
	if hit.MatchForm != string(FormLiteral) {
		t.Fatalf("MatchForm = %q", hit.MatchForm)
	}
}

func TestCheckOverlap_SplitAcrossCalls_Reassembled(t *testing.T) {
	// Cross-call splits are closed by the session fragment buffer in
	// IngestResult (see TestFragmentBuffer_CrossCallReassembly), not by
	// CheckOverlap itself — CheckOverlap still only sees registered taint.
	t.Log("covered by TestFragmentBuffer_CrossCallReassembly")
}

func TestCheckOverlap_Compressed(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(secret))
	gz.Close()
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	tainted := []model.TaintedValue{
		{Value: secret, Variants: CanonicalEncodings(secret), Hash: HashValue(secret), Preview: MaskValue(secret)},
	}
	args := json.RawMessage(`{"body": "` + encoded + `"}`)

	hit := CheckOverlap(tainted, args)
	if hit == nil {
		t.Fatal("expected overlap on gzip+base64 payload")
	}
	if hit.MatchForm != string(FormGzipBase64) {
		t.Fatalf("MatchForm = %q, want gzip_base64", hit.MatchForm)
	}
}

func TestCheckOverlap_CompressedOther_KnownGap(t *testing.T) {
	t.Skip("known gap: zstd/deflate-raw/multi-layer compression not in canonical set")
}

func TestCheckOverlap_DoubleEncoded(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	hexed := hex.EncodeToString([]byte(secret))
	double := base64.StdEncoding.EncodeToString([]byte(hexed))

	tainted := []model.TaintedValue{
		{Value: secret, Variants: CanonicalEncodings(secret), Hash: HashValue(secret), Preview: MaskValue(secret)},
	}
	args := json.RawMessage(`{"body": "` + double + `"}`)

	hit := CheckOverlap(tainted, args)
	if hit == nil {
		t.Fatal("expected overlap on base64(hex(secret))")
	}
	if hit.MatchForm != string(FormBase64Hex) {
		t.Fatalf("MatchForm = %q, want base64_hex", hit.MatchForm)
	}
}

func TestCheckOverlap_TripleEncoded(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	// base64(hex(base64(secret))) — depth-3 nest outside closed CanonicalEncodings set.
	inner := base64.StdEncoding.EncodeToString([]byte(secret))
	mid := hex.EncodeToString([]byte(inner))
	triple := base64.StdEncoding.EncodeToString([]byte(mid))

	tainted := []model.TaintedValue{
		{Value: secret, Variants: CanonicalEncodings(secret), Hash: HashValue(secret), Preview: MaskValue(secret)},
	}
	args := json.RawMessage(`{"body": "` + triple + `"}`)

	hit := CheckOverlap(tainted, args)
	if hit == nil {
		t.Fatal("expected overlap on base64(hex(base64(secret))) via recursive decoder")
	}
	if !strings.HasPrefix(hit.MatchForm, "decoded_") {
		t.Fatalf("MatchForm = %q, want decoded_* path", hit.MatchForm)
	}
}

func TestCheckOverlap_DecodeInvalidBase64_NoFalseHit(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	tainted := []model.TaintedValue{
		{Value: secret, Variants: CanonicalEncodings(secret), Hash: HashValue(secret), Preview: MaskValue(secret)},
	}
	// Plausible-looking base64 alphabet noise that does not unwrap to the secret.
	args := json.RawMessage(`{"body": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="}`)
	if hit := CheckOverlap(tainted, args); hit != nil {
		t.Fatalf("unexpected hit on unrelated base64: %+v", hit)
	}
}

func TestCheckOverlap_DecodeSingleLayer_StillFastPath(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	tainted := []model.TaintedValue{
		{Value: secret, Variants: CanonicalEncodings(secret), Hash: HashValue(secret), Preview: MaskValue(secret)},
	}
	args := json.RawMessage(`{"body": "` + b64 + `"}`)
	hit := CheckOverlap(tainted, args)
	if hit == nil {
		t.Fatal("expected overlap")
	}
	if hit.MatchForm != string(FormBase64) {
		t.Fatalf("MatchForm = %q, want base64 (fast path, not decoder)", hit.MatchForm)
	}
}

func TestCheckOverlapPayload_TripleEncoded(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	inner := base64.StdEncoding.EncodeToString([]byte(secret))
	mid := hex.EncodeToString([]byte(inner))
	triple := base64.StdEncoding.EncodeToString([]byte(mid))

	tainted := []model.TaintedValue{
		{Value: secret, Variants: CanonicalEncodings(secret), Hash: HashValue(secret), Preview: MaskValue(secret)},
	}
	hit := CheckOverlapPayload(tainted, triple)
	if hit == nil {
		t.Fatal("expected payload overlap via recursive decoder")
	}
	if hit.WhereFound != "egress payload" {
		t.Fatalf("WhereFound = %q", hit.WhereFound)
	}
}
