// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

const regenerateEvidenceVectors = "go test ./internal/engine -run EvidenceChainVectors -update"

type evidenceHashVector struct {
	Name   string          `json:"name"`
	Record json.RawMessage `json:"record"`
	Hash   string          `json:"hash"`
}

type evidenceSealVector struct {
	ChainSeq *uint64         `json:"chain_seq"`
	PrevHash *string         `json:"prev_hash"`
	Hash     string          `json:"hash"`
	Record   json.RawMessage `json:"record"`
}

type evidenceChainVectors struct {
	Hashes []evidenceHashVector `json:"hashes"`
	Chain  []evidenceSealVector `json:"chain"`
}

func TestEvidenceChainVectors(t *testing.T) {
	const path = "testdata/evidence_chain_vectors.json"

	got := buildEvidenceChainVectors(t)
	if *updateEncodingVectors {
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatalf("encode vectors: %v; regenerate with %s", err, regenerateEvidenceVectors)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatalf("write vectors: %v; regenerate with %s", err, regenerateEvidenceVectors)
		}
		return
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("read vectors: %v; regenerate with %s", err, regenerateEvidenceVectors)
	}
	defer file.Close()

	var want evidenceChainVectors
	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&want); err != nil {
		t.Fatalf("decode vectors: %v; regenerate with %s", err, regenerateEvidenceVectors)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		t.Fatalf("unexpected content after vectors; regenerate with %s", regenerateEvidenceVectors)
	}

	if len(got.Hashes) != len(want.Hashes) {
		t.Fatalf("hashes: got %d cases, want %d; regenerate with %s", len(got.Hashes), len(want.Hashes), regenerateEvidenceVectors)
	}
	for i, g := range got.Hashes {
		t.Run("hashes/"+g.Name, func(t *testing.T) {
			w := want.Hashes[i]
			checkField(t, g.Name, "name", g.Name, w.Name, regenerateEvidenceVectors)
			diffEvidenceVectorRecord(t, g.Name, g.Record, w.Record)
			checkField(t, g.Name, "hash", g.Hash, w.Hash, regenerateEvidenceVectors)
		})
	}

	if len(got.Chain) != len(want.Chain) {
		t.Fatalf("chain: got %d cases, want %d; regenerate with %s", len(got.Chain), len(want.Chain), regenerateEvidenceVectors)
	}
	for i, g := range got.Chain {
		name := got.Hashes[i].Name
		t.Run("chain/"+name, func(t *testing.T) {
			w := want.Chain[i]
			if w.ChainSeq == nil || *g.ChainSeq != *w.ChainSeq {
				t.Fatalf("case %s: chain_seq: fixture missing or differs from %d; regenerate with %s", name, *g.ChainSeq, regenerateEvidenceVectors)
			}
			if w.PrevHash == nil {
				t.Fatalf("case %s: prev_hash: fixture missing; regenerate with %s", name, regenerateEvidenceVectors)
			}
			checkField(t, name, "prev_hash", *g.PrevHash, *w.PrevHash, regenerateEvidenceVectors)
			checkField(t, name, "hash", g.Hash, w.Hash, regenerateEvidenceVectors)
			diffEvidenceVectorRecord(t, name, g.Record, w.Record)
		})
	}
}

func buildEvidenceChainVectors(t *testing.T) evidenceChainVectors {
	t.Helper()
	full := model.EvidenceRecord{
		SessionID:  "café 漢字 🙂",
		TripTS:     1700000000000000001,
		Verdict:    model.VerdictExfil,
		Action:     model.ActionPrevented,
		Variant:    model.VariantA,
		Confidence: 0.95,
		Legs: model.TrifectaLegs{
			SensitiveSourceTouched:  model.Leg{Lit: true, TriggerSeq: 1, Detail: "source", LitAt: 1700000000000000000},
			UntrustedContentPresent: model.Leg{Lit: true, TriggerSeq: 2, Detail: "untrusted"},
			ExternalSinkInvoked:     model.Leg{Lit: true, TriggerSeq: 3, Detail: "sink"},
		},
		SinkCall: map[string]any{
			"tool_name": "send_message",
			"server_id": "messenger",
			"seq":       uint64(3),
			"args":      json.RawMessage(`{ "z": {"message":"<>& café","items":[null,false,42,1.25,{},[]]}, "a": true }`),
		},
		ValueOverlap: &model.OverlapHit{TaintedHash: strings.Repeat("ab", 32), Preview: "example", WhereFound: "sink args", MatchForm: "literal"},
		Timeline: []model.TimelineItem{
			{TimelineSeq: 1, TSMono: 100, Kind: "intercepted", Label: "source", Ref: 1},
			{TimelineSeq: 2, TSMono: 200, Kind: "syscall", Label: "connect"},
		},
		Pod: &model.PodContext{Namespace: "default", PodName: "worker", PodUID: "00000000-0000-0000-0000-000000000001", NodeName: "node-1"},
	}
	cases := []struct {
		name string
		rec  model.EvidenceRecord
	}{
		{"empty", model.EvidenceRecord{}},
		{"unicode_nested_args", full},
		{"escaped_string", model.EvidenceRecord{
			SessionID: "quote\" slash\\ newline\n tab\t nul\x00 <>& \u2028\u2029",
			SinkCall:  "line one\r\nline two\b\f",
			Hash:      strings.Repeat("cd", 32),
		}},
		{"integer_limits", model.EvidenceRecord{
			SessionID: strings.Repeat("x", 1024),
			TripTS:    math.MaxInt64,
			ChainSeq:  math.MaxUint64,
			PrevHash:  strings.Repeat("ef", 32),
			SinkCall:  uint64(math.MaxUint64),
			Timeline:  []model.TimelineItem{{TimelineSeq: math.MaxInt32, TSMono: math.MinInt64, Ref: math.MaxUint64}},
		}},
		{"boolean", model.EvidenceRecord{SinkCall: true, Timeline: []model.TimelineItem{}}},
		{"array", model.EvidenceRecord{
			SinkCall:     []any{"item", int64(math.MinInt64), nil, map[string]any{}},
			ValueOverlap: &model.OverlapHit{},
			Pod:          &model.PodContext{},
		}},
		{"syscall_sink", model.EvidenceRecord{
			SinkCall: map[string]any{
				"syscall": "connect", "dest_ip": "192.0.2.1", "dest_port": uint16(443),
				"pid": uint32(123), "comm": "worker", "path": "/tmp/worker",
				"payload_excerpt": `{"message":"<>&"}`,
			},
		}},
		{"kernel_denial_sink", model.EvidenceRecord{
			SinkCall: map[string]any{"syscall": "lsm_deny", "pid": uint32(123), "comm": "worker"},
		}},
		{"float_format", model.EvidenceRecord{
			Confidence: math.Copysign(0, -1),
			SinkCall:   []any{1.0, 1e-7, 1e-6, 1e20, 1e21, -1e-9, 1.2345678901234567},
		}},
		{"invalid_utf8", model.EvidenceRecord{SessionID: "a\xff\xfe�", SinkCall: "b\xe2\x82"}},
		{"float_limit", model.EvidenceRecord{SinkCall: math.MaxFloat64, Confidence: math.SmallestNonzeroFloat64}},
		{"escaped_raw_args", model.EvidenceRecord{SinkCall: map[string]any{
			"args": json.RawMessage("{ \"message\": \"quote\\\" slash\\\\ \u2028 <>&\" }"),
		}}},
		{"nil_raw_args", model.EvidenceRecord{SinkCall: map[string]any{"args": json.RawMessage(nil)}}},
		{"escaped_map_value", model.EvidenceRecord{SinkCall: map[string]any{
			"payload_excerpt": "quote\" slash\\ newline\n tab\t nul\x00 bad\xff\xe2\x82",
		}}},
		{"unicode_map_key", model.EvidenceRecord{SinkCall: map[string]any{
			"漢字": true, "café": false, "z": nil,
		}}},
	}

	var vectors evidenceChainVectors
	var prevHash string
	for i, c := range cases {
		rec := c.rec
		hash, err := HashEvidenceRecord(rec)
		if err != nil {
			t.Fatalf("case %s: hash: %v; regenerate with %s", c.name, err, regenerateEvidenceVectors)
		}
		vectors.Hashes = append(vectors.Hashes, evidenceHashVector{
			Name: c.name, Record: marshalEvidenceVectorRecord(t, c.name, rec), Hash: hash,
		})
		if err := SealEvidenceRecord(&rec, uint64(i), prevHash); err != nil {
			t.Fatalf("case %s: seal: %v; regenerate with %s", c.name, err, regenerateEvidenceVectors)
		}
		vectors.Chain = append(vectors.Chain, evidenceSealVector{
			ChainSeq: &rec.ChainSeq, PrevHash: &rec.PrevHash, Hash: rec.Hash,
			Record: marshalEvidenceVectorRecord(t, c.name, rec),
		})
		prevHash = rec.Hash
	}
	return vectors
}

func marshalEvidenceVectorRecord(t *testing.T, name string, rec model.EvidenceRecord) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("case %s: record: %v; regenerate with %s", name, err, regenerateEvidenceVectors)
	}
	return raw
}

func diffEvidenceVectorRecord(t *testing.T, name string, got, want json.RawMessage) {
	t.Helper()
	// Compare the JSON fields directly to preserve large integers, raw JSON
	// ordering, and the difference between an omitted field and a zero value.
	var gotFields, wantFields map[string]json.RawMessage
	if err := json.Unmarshal(got, &gotFields); err != nil {
		t.Fatalf("case %s: computed record: %v; regenerate with %s", name, err, regenerateEvidenceVectors)
	}
	if err := json.Unmarshal(want, &wantFields); err != nil {
		t.Fatalf("case %s: fixture record: %v; regenerate with %s", name, err, regenerateEvidenceVectors)
	}
	fields := make([]string, 0, len(gotFields)+len(wantFields))
	for field := range gotFields {
		fields = append(fields, field)
	}
	for field := range wantFields {
		if _, exists := gotFields[field]; !exists {
			fields = append(fields, field)
		}
	}
	slices.Sort(fields)
	for _, field := range fields {
		var compact bytes.Buffer
		if raw, exists := wantFields[field]; exists {
			if err := json.Compact(&compact, raw); err != nil {
				t.Fatalf("case %s: record.%s: %v; regenerate with %s", name, field, err, regenerateEvidenceVectors)
			}
		}
		checkField(t, name, "record."+field, string(gotFields[field]), compact.String(), regenerateEvidenceVectors)
	}
}
