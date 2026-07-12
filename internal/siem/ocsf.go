package siem

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

// OCSF Detection Finding classification (schema 1.3).
const (
	ocsfCategoryUID = 2
	ocsfClassUID    = 2004
	ocsfActivityID  = 1 // Create
	ocsfVersion     = "1.3.0"
)

// DeliveryRecorder records SIEM delivery outcomes.
type DeliveryRecorder interface {
	RecordAlertDelivery(kind, result string)
}

// Exporter writes OCSF Detection Finding events to file and/or HTTP.
type Exporter struct {
	cfg      config.SIEMConfig
	client   *http.Client
	log      *log.Logger
	recorder DeliveryRecorder
	sem      chan struct{}
	wg       sync.WaitGroup
	fileMu   sync.Mutex
}

// NewExporter returns nil if SIEM is disabled.
func NewExporter(cfg config.SIEMConfig, recorder DeliveryRecorder) (*Exporter, error) {
	if !cfg.Enabled() {
		return nil, nil
	}
	return &Exporter{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.TimeoutDuration(),
		},
		log:      log.New(os.Stderr, "[siem] ", log.LstdFlags),
		recorder: recorder,
		sem:      make(chan struct{}, 8),
	}, nil
}

// OnEvidenceEmitted implements engine.EvidenceEmitObserver.
func (e *Exporter) OnEvidenceEmitted(rec model.EvidenceRecord) {
	if e == nil {
		return
	}
	if !meetsMinVerdict(rec.Verdict, e.cfg.MinVerdict) {
		e.record("skipped")
		return
	}
	select {
	case e.sem <- struct{}{}:
	default:
		e.log.Printf("[SECURITY] SIEM backlog full — dropping event for session=%s", rec.SessionID)
		e.record("error")
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() { <-e.sem }()
		if err := e.deliver(rec); err != nil {
			e.log.Printf("[SECURITY] SIEM export failed session=%s: %v", rec.SessionID, err)
			e.record("error")
			return
		}
		e.record("ok")
	}()
}

// Close waits for in-flight exports.
func (e *Exporter) Close() {
	if e == nil {
		return
	}
	e.wg.Wait()
}

func (e *Exporter) record(result string) {
	if e.recorder != nil {
		e.recorder.RecordAlertDelivery("siem", result)
	}
}

func (e *Exporter) deliver(rec model.EvidenceRecord) error {
	ev := ToOCSF(rec)
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if e.cfg.Path != "" {
		if err := e.appendFile(data); err != nil {
			return err
		}
	}
	if e.cfg.URL != "" {
		if err := e.postHTTP(data); err != nil {
			return err
		}
	}
	return nil
}

func (e *Exporter) appendFile(data []byte) error {
	e.fileMu.Lock()
	defer e.fileMu.Unlock()
	f, err := os.OpenFile(e.cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func (e *Exporter) postHTTP(data []byte) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, e.cfg.URL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
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

// ToOCSF maps an EvidenceRecord to an OCSF 1.3 Detection Finding object.
func ToOCSF(rec model.EvidenceRecord) map[string]any {
	severityID, severity := ocsfSeverity(rec.Verdict)
	typeUID := int64(ocsfClassUID)*100 + int64(ocsfActivityID)
	ms := rec.TripTS / int64(time.Millisecond)
	if ms == 0 && rec.TripTS > 0 {
		ms = rec.TripTS / 1e6
	}
	title := fmt.Sprintf("Interlock %s detection", rec.Verdict)
	desc := fmt.Sprintf("variant=%s action=%s confidence=%.2f session=%s",
		rec.Variant, rec.Action, rec.Confidence, rec.SessionID)

	findingUID := fmt.Sprintf("%s-%d", rec.SessionID, rec.TripTS)
	out := map[string]any{
		"activity_id":   ocsfActivityID,
		"activity_name": "Create",
		"category_uid":  ocsfCategoryUID,
		"category_name": "Findings",
		"class_uid":     ocsfClassUID,
		"class_name":    "Detection Finding",
		"type_uid":      typeUID,
		"type_name":     "Detection Finding: Create",
		"severity_id":   severityID,
		"severity":      severity,
		"time":          ms,
		"metadata": map[string]any{
			"version": ocsfVersion,
			"uid":     findingUID,
			"product": map[string]any{
				"name":        "Interlock",
				"vendor_name": "Interlock",
			},
		},
		"finding_info": map[string]any{
			"uid":         findingUID,
			"title":       title,
			"desc":        desc,
			"product_uid": "interlock",
		},
		"unmapped": map[string]any{
			"session_id": rec.SessionID,
			"verdict":    string(rec.Verdict),
			"action":     string(rec.Action),
			"variant":    string(rec.Variant),
			"confidence": rec.Confidence,
		},
	}
	if rec.Pod != nil {
		out["unmapped"].(map[string]any)["pod_context"] = map[string]string{
			"namespace": rec.Pod.Namespace,
			"pod_name":  rec.Pod.PodName,
			"pod_uid":   rec.Pod.PodUID,
			"node_name": rec.Pod.NodeName,
		}
	}
	if rec.ValueOverlap != nil {
		out["unmapped"].(map[string]any)["value_overlap"] = map[string]string{
			"preview":     rec.ValueOverlap.Preview,
			"where_found": rec.ValueOverlap.WhereFound,
			"match_form":  rec.ValueOverlap.MatchForm,
		}
	}
	if m, ok := rec.SinkCall.(map[string]any); ok {
		sink := make(map[string]any, len(m))
		for k, v := range m {
			sink[k] = v
		}
		out["unmapped"].(map[string]any)["sink_call"] = sink
	}
	out["unmapped"].(map[string]any)["legs"] = map[string]any{
		"sensitive_source_touched":  map[string]any{"lit": rec.Legs.SensitiveSourceTouched.Lit, "detail": rec.Legs.SensitiveSourceTouched.Detail},
		"untrusted_content_present": map[string]any{"lit": rec.Legs.UntrustedContentPresent.Lit, "detail": rec.Legs.UntrustedContentPresent.Detail},
		"external_sink_invoked":     map[string]any{"lit": rec.Legs.ExternalSinkInvoked.Lit, "detail": rec.Legs.ExternalSinkInvoked.Detail},
	}
	return out
}

func ocsfSeverity(v model.Verdict) (int, string) {
	if v == model.VerdictExfil {
		return 5, "Critical"
	}
	return 3, "Medium"
}

func meetsMinVerdict(v model.Verdict, min string) bool {
	switch strings.ToUpper(min) {
	case "EXFIL":
		return v == model.VerdictExfil
	default:
		return v == model.VerdictExfil || v == model.VerdictSuspicious
	}
}
