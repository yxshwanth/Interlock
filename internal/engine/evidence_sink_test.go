package engine

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

func testEvidenceRecord() model.EvidenceRecord {
	return model.EvidenceRecord{
		SessionID:  "test-sess-1",
		TripTS:     1234567890,
		Verdict:    model.VerdictExfil,
		Action:     model.ActionPrevented,
		Variant:    model.VariantA,
		Confidence: 0.95,
		Legs: model.TrifectaLegs{
			SensitiveSourceTouched:  model.Leg{Lit: true, TriggerSeq: 1, Detail: "read_ticket returned sensitive data"},
			UntrustedContentPresent: model.Leg{Lit: true, TriggerSeq: 1, Detail: "untrusted tool result"},
			ExternalSinkInvoked:     model.Leg{Lit: true, TriggerSeq: 2, Detail: "send_message invoked"},
		},
		SinkCall: map[string]any{
			"tool_name": "send_message",
			"server_id": "messenger",
		},
		ValueOverlap: &model.OverlapHit{
			TaintedHash: "abc123def456",
			Preview:     "sk-...cdef",
			WhereFound:  "sink args",
		},
		Timeline: []model.TimelineItem{
			{TSMono: 100, Kind: "intercepted", Label: "sensitive_source_touched", Ref: 1},
			{TSMono: 200, Kind: "intercepted", Label: "external_sink_invoked", Ref: 2},
		},
	}
}

func TestJSONLEvidenceSink_Emit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")

	sink, err := NewJSONLEvidenceSink(path)
	if err != nil {
		t.Fatalf("NewJSONLEvidenceSink: %v", err)
	}

	rec := testEvidenceRecord()
	if err := sink.Emit(rec); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	sink.Close()

	// Read back JSONL and verify.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open JSONL: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
		var got model.EvidenceRecord
		if err := json.Unmarshal(scanner.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal JSONL line: %v", err)
		}
		if got.SessionID != "test-sess-1" {
			t.Errorf("session ID: expected test-sess-1, got %q", got.SessionID)
		}
		if got.Verdict != model.VerdictExfil {
			t.Errorf("verdict: expected EXFIL, got %q", got.Verdict)
		}
		if got.Confidence != 0.95 {
			t.Errorf("confidence: expected 0.95, got %f", got.Confidence)
		}
	}
	if count != 1 {
		t.Errorf("expected 1 JSONL line, got %d", count)
	}
}

func TestJSONLEvidenceSink_StandaloneJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")

	sink, err := NewJSONLEvidenceSink(path)
	if err != nil {
		t.Fatalf("NewJSONLEvidenceSink: %v", err)
	}

	rec := testEvidenceRecord()
	if err := sink.Emit(rec); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	sink.Close()

	// Check standalone evidence.json.
	standalone := filepath.Join(dir, "evidence.json")
	data, err := os.ReadFile(standalone)
	if err != nil {
		t.Fatalf("read evidence.json: %v", err)
	}

	var got model.EvidenceRecord
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal evidence.json: %v", err)
	}
	if got.SessionID != "test-sess-1" {
		t.Errorf("session ID: expected test-sess-1, got %q", got.SessionID)
	}
	if got.Verdict != model.VerdictExfil {
		t.Errorf("verdict: expected EXFIL, got %q", got.Verdict)
	}
	if got.ValueOverlap == nil {
		t.Error("expected ValueOverlap to be present")
	}
	if len(got.Timeline) != 2 {
		t.Errorf("expected 2 timeline items, got %d", len(got.Timeline))
	}
}

func TestJSONLEvidenceSink_MultipleEmits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")

	sink, err := NewJSONLEvidenceSink(path)
	if err != nil {
		t.Fatalf("NewJSONLEvidenceSink: %v", err)
	}

	rec1 := testEvidenceRecord()
	rec1.SessionID = "sess-1"
	rec2 := testEvidenceRecord()
	rec2.SessionID = "sess-2"
	rec2.Verdict = model.VerdictSuspicious

	sink.Emit(rec1)
	sink.Emit(rec2)
	sink.Close()

	// JSONL should have 2 lines.
	f, _ := os.Open(path)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 JSONL lines, got %d", count)
	}

	// Standalone should be the LAST record.
	standalone := filepath.Join(dir, "evidence.json")
	data, _ := os.ReadFile(standalone)
	var got model.EvidenceRecord
	json.Unmarshal(data, &got)
	if got.SessionID != "sess-2" {
		t.Errorf("standalone should be last record (sess-2), got %q", got.SessionID)
	}
	if got.Verdict != model.VerdictSuspicious {
		t.Errorf("standalone verdict should be SUSPICIOUS, got %q", got.Verdict)
	}
}
