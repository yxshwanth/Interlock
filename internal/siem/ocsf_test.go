package siem_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
	"github.com/yxshwanth/Interlock/internal/siem"
)

type recCounter struct {
	mu sync.Mutex
	m  map[string]int
}

func (r *recCounter) RecordAlertDelivery(kind, result string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m == nil {
		r.m = map[string]int{}
	}
	r.m[kind+":"+result]++
}

func sampleRec() model.EvidenceRecord {
	return model.EvidenceRecord{
		SessionID:  "sess-1",
		TripTS:     1_700_000_000_000_000_000,
		Verdict:    model.VerdictExfil,
		Action:     model.ActionContained,
		Variant:    model.VariantB,
		Confidence: 0.95,
		SinkCall: map[string]any{
			"syscall":         "write",
			"payload_excerpt": "sk-...cdef",
		},
		ValueOverlap: &model.OverlapHit{Preview: "sk-...cdef", WhereFound: "egress payload"},
	}
}

func TestToOCSF_RequiredKeys(t *testing.T) {
	ev := siem.ToOCSF(sampleRec())
	required := []string{
		"activity_id", "category_uid", "class_uid", "type_uid",
		"severity_id", "time", "metadata", "finding_info",
	}
	for _, k := range required {
		if _, ok := ev[k]; !ok {
			t.Fatalf("missing %s", k)
		}
	}
	if ev["class_uid"] != 2004 {
		t.Fatalf("class_uid=%v", ev["class_uid"])
	}
	if ev["category_uid"] != 2 {
		t.Fatalf("category_uid=%v", ev["category_uid"])
	}
	if ev["type_uid"].(int64) != 200401 {
		t.Fatalf("type_uid=%v", ev["type_uid"])
	}
	meta, _ := ev["metadata"].(map[string]any)
	if meta["version"] != "1.3.0" {
		t.Fatalf("metadata=%v", meta)
	}
	raw, _ := json.Marshal(ev)
	if strings.Contains(string(raw), "sk-live-") {
		t.Fatal("raw secret in OCSF")
	}
}

func TestExporter_FileAndHTTP(t *testing.T) {
	var posted []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "ocsf.jsonl")
	rc := &recCounter{}
	exp, err := siem.NewExporter(config.SIEMConfig{
		Format:     "ocsf",
		Path:       path,
		URL:        srv.URL,
		MinVerdict: "SUSPICIOUS",
		Timeout:    "2s",
	}, rc)
	if err != nil || exp == nil {
		t.Fatalf("exp=%v err=%v", exp, err)
	}
	exp.OnEvidenceEmitted(sampleRec())
	exp.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"class_uid":2004`) {
		t.Fatalf("file=%s", data)
	}
	if !strings.Contains(string(posted), `"class_uid":2004`) {
		t.Fatalf("posted=%s", posted)
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.m["siem:ok"] != 1 {
		t.Fatalf("recorder=%v", rc.m)
	}
}

func TestExporter_Disabled(t *testing.T) {
	exp, err := siem.NewExporter(config.SIEMConfig{}, nil)
	if err != nil || exp != nil {
		t.Fatalf("exp=%v err=%v", exp, err)
	}
}
