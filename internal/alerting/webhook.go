package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

// DeliveryRecorder records webhook delivery outcomes (ok|error|skipped).
type DeliveryRecorder interface {
	RecordAlertDelivery(kind, result string)
}

// WebhookNotifier posts trip alerts to a configured HTTP endpoint.
type WebhookNotifier struct {
	cfg      config.WebhookConfig
	client   *http.Client
	log      *log.Logger
	recorder DeliveryRecorder
	sem      chan struct{}
	wg       sync.WaitGroup
}

// NewWebhookNotifier returns nil if webhook is disabled.
func NewWebhookNotifier(cfg config.WebhookConfig, recorder DeliveryRecorder) *WebhookNotifier {
	if !cfg.Enabled() {
		return nil
	}
	return &WebhookNotifier{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.TimeoutDuration(),
		},
		log:      log.New(os.Stderr, "[alerting] ", log.LstdFlags),
		recorder: recorder,
		sem:      make(chan struct{}, 8),
	}
}

// OnEvidenceEmitted implements engine.EvidenceEmitObserver.
func (n *WebhookNotifier) OnEvidenceEmitted(rec model.EvidenceRecord) {
	if n == nil {
		return
	}
	if !meetsMinVerdict(rec.Verdict, n.cfg.MinVerdict) {
		n.record("skipped")
		return
	}
	select {
	case n.sem <- struct{}{}:
	default:
		n.log.Printf("[SECURITY] webhook backlog full — dropping alert for session=%s", rec.SessionID)
		n.record("error")
		return
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer func() { <-n.sem }()
		if err := n.deliver(rec); err != nil {
			n.log.Printf("[SECURITY] webhook delivery failed session=%s: %v", rec.SessionID, err)
			n.record("error")
			return
		}
		n.record("ok")
	}()
}

// Close waits for in-flight deliveries.
func (n *WebhookNotifier) Close() {
	if n == nil {
		return
	}
	n.wg.Wait()
}

func (n *WebhookNotifier) record(result string) {
	if n.recorder != nil {
		n.recorder.RecordAlertDelivery("webhook", result)
	}
}

func (n *WebhookNotifier) deliver(rec model.EvidenceRecord) error {
	body, contentType, err := n.buildBody(rec)
	if err != nil {
		return err
	}
	url := n.cfg.URL
	if n.cfg.Format == "pagerduty" && !strings.Contains(url, "events.pagerduty.com") {
		// Allow custom URL; default Events API v2 if path looks like a placeholder host-only.
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func (n *WebhookNotifier) buildBody(rec model.EvidenceRecord) ([]byte, string, error) {
	switch n.cfg.Format {
	case "slack":
		text := formatSlackText(rec)
		b, err := json.Marshal(map[string]string{"text": text})
		return b, "application/json", err
	case "pagerduty":
		payload := map[string]any{
			"routing_key":  n.cfg.PagerDutyRoutingKey,
			"event_action": "trigger",
			"dedup_key":    fmt.Sprintf("%s-%d", rec.SessionID, rec.TripTS),
			"payload": map[string]any{
				"summary":   formatSummary(rec),
				"severity": pdSeverity(rec.Verdict),
				"source":    "interlock",
				"timestamp": time.Unix(0, rec.TripTS).UTC().Format(time.RFC3339),
				"custom_details": compactDetails(rec),
			},
		}
		b, err := json.Marshal(payload)
		return b, "application/json", err
	default: // generic
		b, err := json.Marshal(compactDetails(rec))
		return b, "application/json", err
	}
}

func meetsMinVerdict(v model.Verdict, min string) bool {
	switch strings.ToUpper(min) {
	case "EXFIL":
		return v == model.VerdictExfil
	default:
		return v == model.VerdictExfil || v == model.VerdictSuspicious
	}
}

func pdSeverity(v model.Verdict) string {
	if v == model.VerdictExfil {
		return "critical"
	}
	return "warning"
}

func formatSummary(rec model.EvidenceRecord) string {
	pod := ""
	if rec.Pod != nil {
		pod = fmt.Sprintf(" pod=%s/%s", rec.Pod.Namespace, rec.Pod.PodName)
	}
	return fmt.Sprintf("Interlock %s (%s) session=%s%s", rec.Verdict, rec.Variant, rec.SessionID, pod)
}

func formatSlackText(rec model.EvidenceRecord) string {
	return formatSummary(rec) + fmt.Sprintf(" action=%s confidence=%.2f", rec.Action, rec.Confidence)
}

func compactDetails(rec model.EvidenceRecord) map[string]any {
	out := map[string]any{
		"session_id": rec.SessionID,
		"verdict":    string(rec.Verdict),
		"action":     string(rec.Action),
		"variant":    string(rec.Variant),
		"confidence": rec.Confidence,
		"trip_ts_ns": rec.TripTS,
	}
	if rec.Pod != nil {
		out["pod_context"] = map[string]string{
			"namespace": rec.Pod.Namespace,
			"pod_name":  rec.Pod.PodName,
			"pod_uid":   rec.Pod.PodUID,
			"node_name": rec.Pod.NodeName,
		}
	}
	if rec.ValueOverlap != nil {
		out["value_overlap"] = map[string]string{
			"preview":     rec.ValueOverlap.Preview,
			"where_found": rec.ValueOverlap.WhereFound,
			"match_form":  rec.ValueOverlap.MatchForm,
		}
	}
	if sc := sinkSummary(rec.SinkCall); sc != nil {
		out["sink_call"] = sc
	}
	out["legs"] = map[string]any{
		"sensitive_source_touched":  legDetail(rec.Legs.SensitiveSourceTouched),
		"untrusted_content_present": legDetail(rec.Legs.UntrustedContentPresent),
		"external_sink_invoked":     legDetail(rec.Legs.ExternalSinkInvoked),
	}
	return out
}

func legDetail(l model.Leg) map[string]any {
	return map[string]any{"lit": l.Lit, "detail": l.Detail}
}

func sinkSummary(sink any) map[string]any {
	m, ok := sink.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k == "payload_excerpt" {
			if s, ok := v.(string); ok {
				out[k] = s // already redacted by engine
			}
			continue
		}
		out[k] = v
	}
	return out
}
