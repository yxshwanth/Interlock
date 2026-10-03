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

// TestWebhook_PagerDuty_EscalationGetsFreshIncident pins the fix for a
// finding surfaced reviewing docs/cve_corpus.md's own dedup_key fix: a
// SessionID-only dedup_key let a later, higher-confidence EXFIL merge into
// an already-acknowledged, lower-severity SUSPICIOUS incident instead of
// paging fresh at the severity it deserves. Keying on SessionID *and*
// Verdict means same-tier repeats (the noise case dedup exists to solve)
// still share a key, but an escalation to a different verdict always gets
// its own dedup_key — PagerDuty cannot silently absorb it into a stale one.
func TestWebhook_PagerDuty_EscalationGetsFreshIncident(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		got = append(got, body)
		mu.Unlock()
		w.WriteHeader(202)
	}))
	defer srv.Close()

	n := alerting.NewWebhookNotifier(config.WebhookConfig{
		URL:                 srv.URL,
		Format:              "pagerduty",
		MinVerdict:          "SUSPICIOUS",
		PagerDutyRoutingKey: "rkey",
	}, nil)
	n.OnEvidenceEmitted(sampleRec(model.VerdictSuspicious))
	n.OnEvidenceEmitted(sampleRec(model.VerdictSuspicious)) // same-tier repeat
	n.OnEvidenceEmitted(sampleRec(model.VerdictExfil))      // escalation
	n.Close()

	if len(got) != 3 {
		t.Fatalf("expected 3 deliveries, got %d", len(got))
	}
	// Deliveries are async (OnEvidenceEmitted spawns a goroutine per call),
	// so group by the payload's own verdict rather than assuming send order
	// survived to arrival order.
	var suspiciousKeys, exfilKeys []string
	for _, body := range got {
		payload, _ := body["payload"].(map[string]any)
		key, _ := body["dedup_key"].(string)
		switch payload["severity"] {
		case "warning":
			suspiciousKeys = append(suspiciousKeys, key)
		case "critical":
			exfilKeys = append(exfilKeys, key)
		}
	}
	if len(suspiciousKeys) != 2 || len(exfilKeys) != 1 {
		t.Fatalf("expected 2 SUSPICIOUS + 1 EXFIL delivery, got suspicious=%v exfil=%v", suspiciousKeys, exfilKeys)
	}
	if suspiciousKeys[0] != suspiciousKeys[1] {
		t.Fatalf("same-tier repeats must share a dedup_key: %q vs %q", suspiciousKeys[0], suspiciousKeys[1])
	}
	if exfilKeys[0] == suspiciousKeys[0] {
		t.Fatalf("escalation to EXFIL must NOT share the SUSPICIOUS dedup_key (would let it merge into an already-acked, lower-severity incident): both were %q", exfilKeys[0])
	}
	// The len(exfilKeys)==1 grouped-by-severity=="critical" check above
	// already confirms the EXFIL delivery carries critical severity.
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

func TestWebhook_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	rc := &recCounter{}
	n := alerting.NewWebhookNotifier(config.WebhookConfig{
		URL: srv.URL, Format: "generic", MinVerdict: "SUSPICIOUS", Timeout: "1s",
	}, rc)
	n.OnEvidenceEmitted(sampleRec(model.VerdictExfil))
	n.Close()
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.m["webhook:error"] != 1 {
		t.Fatalf("recorder=%v", rc.m)
	}
}

func TestWebhook_BacklogDrop(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)

	n := alerting.NewWebhookNotifier(config.WebhookConfig{
		URL: srv.URL, Format: "generic", MinVerdict: "SUSPICIOUS", Timeout: "5s",
	}, &recCounter{})
	for i := 0; i < 20; i++ {
		n.OnEvidenceEmitted(sampleRec(model.VerdictExfil))
	}
	time.Sleep(50 * time.Millisecond)
	n.Close()
}

func TestWebhook_Disabled(t *testing.T) {
	if alerting.NewWebhookNotifier(config.WebhookConfig{}, nil) != nil {
		t.Fatal("expected nil")
	}
}
