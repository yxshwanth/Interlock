package mcphttp_test

import (
	"net/http"
	"strings"
	"testing"

	mcphttp "github.com/yxshwanth/Interlock/internal/proxy/http"
)

func TestRedactCredential(t *testing.T) {
	got := mcphttp.RedactCredential("Bearer sk-live-secret-token")
	if strings.Contains(got, "secret") {
		t.Fatalf("expected redacted output, got %q", got)
	}
	if got == "" {
		t.Fatal("expected non-empty redacted marker")
	}
}

func TestValidateAccept(t *testing.T) {
	req := mustRequest(t, "POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	req.Header.Set("Accept", "application/json, text/event-stream")
	if err := mcphttp.ValidateAccept(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req.Header.Set("Accept", "application/json")
	if err := mcphttp.ValidateAccept(req); err == nil {
		t.Fatal("expected error for missing text/event-stream")
	}
}

func TestValidateHeaderBodyMatch(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_ticket","arguments":{}}}`)
	meta := mcphttp.RequestMeta{
		McpMethod: "tools/call",
		McpName:   "read_ticket",
	}
	if err := mcphttp.ValidateHeaderBodyMatch(meta, body); err != nil {
		t.Fatalf("unexpected mismatch: %v", err)
	}

	meta.McpName = "send_message"
	if err := mcphttp.ValidateHeaderBodyMatch(meta, body); err == nil {
		t.Fatal("expected Mcp-Name mismatch error")
	}
}

func TestParseSSEResponse(t *testing.T) {
	raw := "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	got, err := mcphttp.ParseSSEResponse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"result"`) {
		t.Fatalf("unexpected payload: %s", got)
	}
}

func mustRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return req
}
