package alerting_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/alerting"
	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
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

func sampleRec(verdict model.Verdict) model.EvidenceRecord {
	return model.EvidenceRecord{
		SessionID:  "k8s:demo",
		TripTS:     1_700_000_000_000_000_000,
		Verdict:    verdict,
		Action:     model.ActionContained,
		Variant:    model.VariantB,
		Confidence: 0.95,
		Pod: &model.PodContext{
			Namespace: "default",
			PodName:   "exfil",
			PodUID:    "uid",
			NodeName:  "node",
		},
		ValueOverlap: &model.OverlapHit{
			Preview:    "sk-...cdef",
			WhereFound: "egress payload",
			MatchForm:  "literal",
		},
		SinkCall: map[string]any{
			"syscall":         "write",
			"payload_excerpt": "sk-...cdef",
		},
	}
}

func TestWebhook_Generic(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(204)
	}))
	defer srv.Close()

	rc := &recCounter{}
	n := alerting.NewWebhookNotifier(config.WebhookConfig{
		URL:        srv.URL,
		Format:     "generic",
		MinVerdict: "SUSPICIOUS",
		Timeout:    "2s",
	}, rc)
	n.OnEvidenceEmitted(sampleRec(model.VerdictExfil))
	n.Close()

	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	if m["verdict"] != "EXFIL" {
		t.Fatalf("body=%s", got)
	}
	raw, _ := json.Marshal(m)
	if strings.Contains(string(raw), "sk-live-") {
		t.Fatal("raw secret leaked")
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.m["webhook:ok"] != 1 {
		t.Fatalf("recorder=%v", rc.m)
	}
}

func TestWebhook_Slack(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	n := alerting.NewWebhookNotifier(config.WebhookConfig{
		URL: srv.URL, Format: "slack", MinVerdict: "SUSPICIOUS",
	}, nil)
	n.OnEvidenceEmitted(sampleRec(model.VerdictSuspicious))
	n.Close()
	text, _ := got["text"].(string)
	if !strings.Contains(text, "SUSPICIOUS") || !strings.Contains(text, "k8s:demo") {
		t.Fatalf("text=%q", text)
	}
}

func TestWebhook_PagerDuty(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(202)
	}))
	defer srv.Close()

	n := alerting.NewWebhookNotifier(config.WebhookConfig{
		URL:                 srv.URL,
		Format:              "pagerduty",
		MinVerdict:          "SUSPICIOUS",
		PagerDutyRoutingKey: "rkey",
	}, nil)
	n.OnEvidenceEmitted(sampleRec(model.VerdictExfil))
	n.Close()
	if got["routing_key"] != "rkey" || got["event_action"] != "trigger" {
		t.Fatalf("got=%v", got)
	}
	payload, _ := got["payload"].(map[string]any)
	if payload["severity"] != "critical" {
		t.Fatalf("payload=%v", payload)
	}
}

func TestWebhook_MinVerdictEXFIL(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()
	rc := &recCounter{}
	n := alerting.NewWebhookNotifier(config.WebhookConfig{
		URL: srv.URL, Format: "generic", MinVerdict: "EXFIL",
	}, rc)
	n.OnEvidenceEmitted(sampleRec(model.VerdictSuspicious))
	n.Close()
	if called {
		t.Fatal("expected skip for SUSPICIOUS when min=EXFIL")
	}
	time.Sleep(10 * time.Millisecond)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.m["webhook:skipped"] != 1 {
		t.Fatalf("recorder=%v", rc.m)
	}
}

func TestWebhook_Disabled(t *testing.T) {
	if alerting.NewWebhookNotifier(config.WebhookConfig{}, nil) != nil {
		t.Fatal("expected nil")
	}
}
