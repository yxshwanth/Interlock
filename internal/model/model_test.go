package model

import (
	"encoding/json"
	"testing"
)

func TestParseToolCallParams(t *testing.T) {
	tc, err := ParseToolCallParams(json.RawMessage(`{"name":"tickets.get","arguments":{"id":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tc.Name != "tickets.get" {
		t.Fatalf("name=%q", tc.Name)
	}
	if string(tc.Arguments) != `{"id":1}` {
		t.Fatalf("args=%s", tc.Arguments)
	}
}

func TestParseToolCallParams_InvalidJSON(t *testing.T) {
	_, err := ParseToolCallParams(json.RawMessage(`{`))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseToolCallParams_Empty(t *testing.T) {
	tc, err := ParseToolCallParams(nil)
	if err != nil {
		t.Fatal(err)
	}
	if tc.Name != "" {
		t.Fatalf("name=%q", tc.Name)
	}
}

func TestJSONRPCMessage_Kinds(t *testing.T) {
	var req JSONRPCMessage
	if err := json.Unmarshal([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`), &req); err != nil {
		t.Fatal(err)
	}
	if !req.IsRequest() || req.IsNotification() || req.IsResponse() {
		t.Fatalf("request classification wrong: request=%v notification=%v response=%v", req.IsRequest(), req.IsNotification(), req.IsResponse())
	}

	var note JSONRPCMessage
	_ = json.Unmarshal([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), &note)
	if !note.IsNotification() {
		t.Fatal("expected notification")
	}

	var resp JSONRPCMessage
	_ = json.Unmarshal([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`), &resp)
	if !resp.IsResponse() || resp.IsRequest() {
		t.Fatal("expected response")
	}
}

func TestMeetsMinVerdict(t *testing.T) {
	if !MeetsMinVerdict(VerdictSuspicious, "SUSPICIOUS") {
		t.Fatal("SUSPICIOUS should meet default min")
	}
	if MeetsMinVerdict(VerdictSuspicious, "EXFIL") {
		t.Fatal("SUSPICIOUS should not meet EXFIL min")
	}
	if !MeetsMinVerdict(VerdictExfil, "EXFIL") {
		t.Fatal("EXFIL should meet EXFIL min")
	}
}

func TestReverseString(t *testing.T) {
	if got := ReverseString("abc"); got != "cba" {
		t.Fatalf("got %q", got)
	}
}
