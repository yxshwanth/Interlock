package mcphttp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcphttp "github.com/yxshwanth/Interlock/internal/proxy/http"
)

func TestWriteResponse_BlockedUsesJSON(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"blocked"}}`)
	rec := httptest.NewRecorder()

	if err := mcphttp.WriteResponse(rec, body, true, true); err != nil {
		t.Fatal(err)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), "blocked") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestWriteResponse_SSEWhenPreferred(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	rec := httptest.NewRecorder()

	if err := mcphttp.WriteResponse(rec, body, true, false); err != nil {
		t.Fatal(err)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	if !strings.Contains(rec.Body.String(), "data: ") {
		t.Fatalf("expected SSE data lines, got: %s", rec.Body.String())
	}
}

func TestWriteResponse_JSONWhenNotSSE(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	rec := httptest.NewRecorder()

	if err := mcphttp.WriteResponse(rec, body, false, false); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}
