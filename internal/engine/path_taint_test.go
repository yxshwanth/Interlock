// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/hex"
	"encoding/json"
	"math/rand"
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
	if vals[0].Hash != HashValue(blob) {
		t.Fatal("expected hash of the blob")
	}
}

// Whole-file taint keeps the first 64 KiB: a slice exfiltrated only from
// past the cap is not registered.
func TestTaintPathDrivenContent_TailPastCap_KnownGap(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	b := make([]byte, 40*1024)
	r.Read(b)
	blob := hex.EncodeToString(b)
	eng, _ := newTestEngine("block")
	st := eng.store.GetOrCreate("tail-cap")
	eng.addTainted(st, TaintPathDrivenContent(blob, "/x/credentials", "src", 1))
	if hit := CheckOverlapPayload(st.Tainted, blob[len(blob)-200:]); hit != nil {
		t.Fatal("tail past the cap now matched: gap closed, flip this pin")
	}
	if hit := CheckOverlapPayload(st.Tainted, blob); hit == nil {
		t.Fatal("whole-file exfil must still match the kept head")
	}
}

// Review #9: a pod looping open() on a 64 KiB credentials file must not grow
// taint without bound. Re-reading identical content adds nothing; distinct
// content sheds the oldest values, and the newest stays detectable.
func TestEngine_SensorPodLoopTaintBounded(t *testing.T) {
	eng, _ := newTestEngine("block")
	sid := "k8s:pod-loop"
	blob := func(i int) string {
		r := rand.New(rand.NewSource(int64(i)))
		b := make([]byte, 32*1024)
		r.Read(b)
		return hex.EncodeToString(b)
	}
	open := func(contents string) {
		eng.IngestSyscallSensor(model.SyscallEvent{
			SessionID: sid, Syscall: "openat", Path: "/x/credentials",
			PID: 1, Comm: "agent", FileContents: contents,
		})
	}

	same := blob(0)
	for i := 0; i < 50; i++ {
		open(same)
	}
	if n := len(eng.store.Get(sid).Tainted); n != 1 {
		t.Fatalf("identical re-reads registered %d values, want 1", n)
	}

	const iterations = 64
	for i := 1; i <= iterations; i++ {
		open(blob(i))
	}
	st := eng.store.Get(sid)
	total := 0
	for _, tv := range st.Tainted {
		total += len(tv.Value)
	}
	if len(st.Tainted) > maxTaintedPerSession || total > maxTaintedBytesPerSession {
		t.Fatalf("taint unbounded: %d values, %d bytes", len(st.Tainted), total)
	}

	newest := blob(iterations)
	dec := eng.IngestSyscallSensor(model.SyscallEvent{
		SessionID: sid, Syscall: "write", DestIP: "203.0.113.9", DestPort: 443,
		PID: 1, Comm: "agent", PayloadExcerpt: newest[1000:1200],
	})
	if dec.Verdict != model.VerdictExfil {
		t.Fatalf("newest value must stay detectable after shedding, got %q", dec.Verdict)
	}
}

// Shedding drops the oldest values: a slice of the first file read before
// the session filled its taint budget is no longer matched.
func TestEngine_SensorTaintShedOldest_KnownGap(t *testing.T) {
	eng, _ := newTestEngine("block")
	sid := "k8s:pod-shed"
	blob := func(i int) string {
		r := rand.New(rand.NewSource(int64(i)))
		b := make([]byte, 32*1024)
		r.Read(b)
		return hex.EncodeToString(b)
	}
	for i := 0; i <= maxTaintedBytesPerSession/len(blob(0)); i++ {
		eng.IngestSyscallSensor(model.SyscallEvent{
			SessionID: sid, Syscall: "openat", Path: "/x/credentials",
			PID: 1, Comm: "agent", FileContents: blob(i),
		})
	}
	dec := eng.IngestSyscallSensor(model.SyscallEvent{
		SessionID: sid, Syscall: "write", DestIP: "203.0.113.9", DestPort: 443,
		PID: 1, Comm: "agent", PayloadExcerpt: blob(0)[1000:1200],
	})
	if dec.Verdict == model.VerdictExfil {
		t.Fatal("shed value still matched: gap closed, flip this pin")
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
