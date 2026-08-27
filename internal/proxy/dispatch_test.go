package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReplaceToolCallArguments(t *testing.T) {
	frame := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_message","arguments":{"body":"ilk.vault.abc"}}}`)
	args := json.RawMessage(`{"body":"sk-live-REALSECRET0000000000000000"}`)
	out, err := replaceToolCallArguments(frame, args)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "ilk.vault.abc") {
		t.Fatalf("dummy still present: %s", out)
	}
	if !strings.Contains(string(out), "sk-live-REALSECRET") {
		t.Fatalf("real secret missing: %s", out)
	}
	var msg map[string]any
	if err := json.Unmarshal(out, &msg); err != nil {
		t.Fatal(err)
	}
	params := msg["params"].(map[string]any)
	if params["name"] != "send_message" {
		t.Fatalf("tool name lost: %v", params["name"])
	}
}
