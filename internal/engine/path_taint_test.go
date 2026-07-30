package engine

import (
	"encoding/json"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

func TestIsSensitiveResourcePath_Extensions(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/home/svc/reports/salary.xlsx", true},
		{"/var/secrets/wallet.p12", true},
		{"/tmp/readme.txt", false},
		{"/etc/shadow", true}, // via prefix below
	}
	prefixes := []string{"/etc/shadow"}
	for _, tc := range cases {
		if got := IsSensitiveResourcePath(tc.path, prefixes); got != tc.want {
			t.Errorf("IsSensitiveResourcePath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestExtractPathsFromToolArgs(t *testing.T) {
	args := json.RawMessage(`{"filepath":"/home/svc/reports/salary.xlsx","sheet":"Q1"}`)
	paths := ExtractPathsFromToolArgs(args)
	if len(paths) != 1 || paths[0] != "/home/svc/reports/salary.xlsx" {
		t.Fatalf("paths = %v", paths)
	}
}

func TestTaintPathDrivenContent_RegistersBlob(t *testing.T) {
	blob := "\x50\x4b\x03\x04opaque-xlsx-bytes"
	vals := TaintPathDrivenContent(blob, "/reports/salary.xlsx", "excel/read_excel_file", 1)
	if len(vals) != 1 {
		t.Fatalf("len = %d, want 1", len(vals))
	}
	if vals[0].Value != blob {
		t.Fatal("expected full blob tainted")
	}
	if len(vals[0].Variants) == 0 {
		t.Fatal("expected canonical variants")
	}
}

func TestEngine_PathDrivenProxyExfil(t *testing.T) {
	cfg := &config.Config{
		Enforcement: "block",
		Servers: []config.ServerConfig{
			{ID: "excel", ProvidesTags: []string{"sensitive_source"}},
			{ID: "messenger", ProvidesTags: []string{"external_sink"}},
		},
		ToolTags: map[string][]string{
			"read_excel_file": {"sensitive_source"},
			"send_message":    {"external_sink"},
		},
		UntrustedOrigins: struct {
			ToolResults bool `yaml:"tool_results"`
			WebFetches  bool `yaml:"web_fetches"`
		}{ToolResults: true},
	}
	store := NewSessionStore()
	tagger := NewTagger(cfg)
	eng := NewEngine(store, tagger, "block", nil)
	eng.Configure(cfg)

	sid := "sess-path-taint"
	blob := "PK\x03\x04compressed-workbook-bytes"

	eng.EvaluateRequest(model.InterceptedEvent{
		SessionID: sid,
		Seq:       1,
		ToolName:  "read_excel_file",
		ServerID:  "excel",
		ToolArgs:  json.RawMessage(`{"filepath":"/home/svc/reports/salary.xlsx"}`),
	})
	eng.IngestResult(model.InterceptedEvent{
		SessionID: sid,
		Seq:       2,
		ToolName:  "read_excel_file",
		ServerID:  "excel",
		Result:    json.RawMessage(`{"content":[{"type":"text","text":` + mustJSON(blob) + `}]}`),
	})
	eng.IngestResult(model.InterceptedEvent{
		SessionID: sid,
		Seq:       3,
		ToolName:  "fetch_page",
		ServerID:  "web",
		Result:    json.RawMessage(`{"content":[{"type":"text","text":"untrusted page"}]}`),
	})

	dec := eng.EvaluateRequest(model.InterceptedEvent{
		SessionID: sid,
		Seq:       4,
		ToolName:  "send_message",
		ServerID:  "messenger",
		ToolArgs:  mustArgsJSON(map[string]string{"body": "Attaching: " + blob}),
	})
	if dec.Verdict != model.VerdictExfil {
		t.Fatalf("verdict = %q, want EXFIL", dec.Verdict)
	}
}

func TestEngine_PathDrivenSensorExfil(t *testing.T) {
	cfg := &config.Config{Enforcement: "block"}
	store := NewSessionStore()
	eng := NewEngine(store, NewTagger(cfg), "block", nil)
	eng.Configure(cfg)

	sid := "sensor-path"
	blob := "\x30\x82binary-p12-body"

	eng.IngestSyscallSensor(model.SyscallEvent{
		SessionID:    sid,
		Syscall:      "openat",
		Path:         "/var/secrets/wallet.p12",
		FileContents: blob,
		PID:          100,
		Comm:         "agent",
	})
	dec := eng.IngestSyscallSensor(model.SyscallEvent{
		SessionID:      sid,
		Syscall:        "write",
		DestIP:         "203.0.113.1",
		DestPort:       4444,
		PayloadExcerpt: "POST /collect\r\n\r\n" + blob,
		PID:            100,
		Comm:           "agent",
	})
	if dec.Verdict != model.VerdictExfil {
		t.Fatalf("verdict = %q, want EXFIL", dec.Verdict)
	}
}

func TestEngine_PathDriven_NoExfilWithoutOverlap(t *testing.T) {
	cfg := &config.Config{
		Enforcement: "block",
		Servers: []config.ServerConfig{
			{ID: "excel", ProvidesTags: []string{"sensitive_source"}},
			{ID: "messenger", ProvidesTags: []string{"external_sink"}},
		},
		ToolTags: map[string][]string{
			"read_excel_file": {"sensitive_source"},
			"send_message":    {"external_sink"},
		},
		UntrustedOrigins: struct {
			ToolResults bool `yaml:"tool_results"`
			WebFetches  bool `yaml:"web_fetches"`
		}{ToolResults: true},
	}
	store := NewSessionStore()
	eng := NewEngine(store, NewTagger(cfg), "block", nil)
	eng.Configure(cfg)

	sid := "sess-no-overlap"
	blob := "PK\x03\x04workbook"

	eng.EvaluateRequest(model.InterceptedEvent{
		SessionID: sid, Seq: 1, ToolName: "read_excel_file", ServerID: "excel",
		ToolArgs: json.RawMessage(`{"filepath":"/reports/salary.xlsx"}`),
	})
	eng.IngestResult(model.InterceptedEvent{
		SessionID: sid, Seq: 2, ToolName: "read_excel_file", ServerID: "excel",
		Result: json.RawMessage(`{"content":[{"type":"text","text":` + mustJSON(blob) + `}]}`),
	})
	eng.IngestResult(model.InterceptedEvent{
		SessionID: sid, Seq: 3, ToolName: "fetch_page", ServerID: "web",
		Result: json.RawMessage(`{"content":[{"type":"text","text":"untrusted"}]}`),
	})

	dec := eng.EvaluateRequest(model.InterceptedEvent{
		SessionID: sid, Seq: 4, ToolName: "send_message", ServerID: "messenger",
		ToolArgs: json.RawMessage(`{"body":"unrelated message"}`),
	})
	if dec.Verdict == model.VerdictExfil {
		t.Fatal("unexpected EXFIL without byte overlap")
	}
}

func mustJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func mustArgsJSON(kv map[string]string) json.RawMessage {
	b, err := json.Marshal(kv)
	if err != nil {
		panic(err)
	}
	return b
}
