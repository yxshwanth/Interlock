// Package engine implements the correlation and policy engine: the trifecta
// state machine, value-overlap taint checking, and verdict/evidence emission.
package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

// EvidenceSink receives evidence records when a trifecta trips.
type EvidenceSink interface {
	Emit(rec model.EvidenceRecord) error
}

// Engine is the core trifecta policy engine. It evaluates tool calls against
// the three-leg state machine and emits verdicts + evidence.
type Engine struct {
	store  *SessionStore
	tagger *Tagger
	sink   EvidenceSink
	mode   string // "block" or "monitor"
	log    *log.Logger
	mu     sync.Mutex
}

// NewEngine creates an engine wired to the given store, tagger, and mode.
// sink may be nil (evidence is logged to stderr only).
func NewEngine(store *SessionStore, tagger *Tagger, mode string, sink EvidenceSink) *Engine {
	if mode == "" {
		mode = "block"
	}
	l := log.New(os.Stderr, "[engine] ", log.LstdFlags)

	if tagger != nil {
		if !tagger.HasSensitiveSource() {
			l.Printf("[SECURITY] no sensitive_source tools configured — trifecta leg 1 can never fire")
		}
		if !tagger.HasExternalSink() {
			l.Printf("[SECURITY] no external_sink tools configured — trifecta leg 3 can never fire")
		}
	}

	return &Engine{
		store:  store,
		tagger: tagger,
		sink:   sink,
		mode:   mode,
		log:    l,
	}
}

// IngestResult is called when a server→agent result arrives. It updates
// the trifecta legs (sensitive_source_touched, untrusted_content_present),
// extracts tainted values from sensitive sources, and appends to the timeline.
func (e *Engine) IngestResult(ev model.InterceptedEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.store.GetOrCreate(ev.SessionID)
	state.LastActivity = time.Now().UnixNano()
	state.Timeline = append(state.Timeline, ev.Seq)

	if e.tagger.IsSensitiveSource(ev.ToolName, ev.ServerID) {
		e.setSensitiveSourceTouched(state, ev)

		resultText := extractResultText(ev.Result)
		if resultText != "" {
			source := fmt.Sprintf("%s/%s", ev.ServerID, ev.ToolName)
			tainted := ExtractTaintedValues(resultText, source, ev.Seq)
			state.Tainted = append(state.Tainted, tainted...)
			if len(tainted) > 0 {
				e.log.Printf("extracted %d tainted value(s) from %s (session=%s)",
					len(tainted), source, ev.SessionID)
			}
		}
	}

	e.setUntrustedContentPresent(state, ev)
}

// EvaluateRequest is called before forwarding a tools/call. It checks whether
// this call should be blocked based on the trifecta state.
func (e *Engine) EvaluateRequest(ev model.InterceptedEvent) model.Decision {
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.store.GetOrCreate(ev.SessionID)
	state.LastActivity = time.Now().UnixNano()
	state.Timeline = append(state.Timeline, ev.Seq)

	if !e.tagger.IsExternalSink(ev.ToolName, ev.ServerID) {
		return model.Decision{Allow: true}
	}

	e.setExternalSinkInvoked(state, ev)

	if !state.Legs.AllLit() {
		return model.Decision{Allow: true}
	}

	overlap := CheckOverlap(state.Tainted, ev.ToolArgs)

	var verdict model.Verdict
	var confidence float64
	if overlap != nil {
		verdict = model.VerdictExfil
		confidence = 0.95
	} else {
		verdict = model.VerdictSuspicious
		confidence = 0.6
	}

	allow := e.mode == "monitor"
	var action model.Action
	if allow {
		action = model.ActionAllowed
	} else {
		action = model.ActionPrevented
	}

	state.Status = model.Tripped
	state.Confidence = confidence

	evidence := e.buildEvidence(state, ev, verdict, action, confidence, overlap)

	if e.sink != nil {
		if err := e.sink.Emit(evidence); err != nil {
			e.log.Printf("[SECURITY] evidence sink write failed — enforcement continues but forensic record is incomplete: %v", err)
		}
	}

	e.log.Printf("TRIFECTA DETECTED: session=%s tool=%s verdict=%s action=%s",
		ev.SessionID, ev.ToolName, verdict, action)

	return model.Decision{
		Allow:    allow,
		Verdict:  verdict,
		Action:   action,
		Reason:   fmt.Sprintf("trifecta %s: %s", verdict, ev.ToolName),
		Evidence: &evidence,
	}
}

// RedactEvent scrubs known tainted values from the ToolArgs and Result
// fields of an InterceptedEvent, replacing raw secrets with masked previews.
func (e *Engine) RedactEvent(ev *model.InterceptedEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.store.Get(ev.SessionID)
	if state == nil || len(state.Tainted) == 0 {
		return
	}
	ev.ToolArgs = RedactJSON(ev.ToolArgs, state.Tainted)
	ev.Result = RedactJSON(ev.Result, state.Tainted)
}

func (e *Engine) setSensitiveSourceTouched(state *model.SessionState, ev model.InterceptedEvent) {
	if state.Legs.SensitiveSourceTouched.Lit {
		return
	}
	state.Legs.SensitiveSourceTouched = model.Leg{
		Lit:        true,
		TriggerSeq: ev.Seq,
		Detail:     fmt.Sprintf("tool %s returned sensitive data", ev.ToolName),
	}
	e.log.Printf("leg lit: sensitive_source_touched (session=%s, tool=%s, seq=%d)",
		ev.SessionID, ev.ToolName, ev.Seq)
}

func (e *Engine) setUntrustedContentPresent(state *model.SessionState, ev model.InterceptedEvent) {
	if state.Legs.UntrustedContentPresent.Lit {
		return
	}
	state.Legs.UntrustedContentPresent = model.Leg{
		Lit:        true,
		TriggerSeq: ev.Seq,
		Detail:     fmt.Sprintf("untrusted content from tool result (tool=%s)", ev.ToolName),
	}
	e.log.Printf("leg lit: untrusted_content_present (session=%s, seq=%d)",
		ev.SessionID, ev.Seq)
}

func (e *Engine) setExternalSinkInvoked(state *model.SessionState, ev model.InterceptedEvent) {
	if state.Legs.ExternalSinkInvoked.Lit {
		return
	}
	state.Legs.ExternalSinkInvoked = model.Leg{
		Lit:        true,
		TriggerSeq: ev.Seq,
		Detail:     fmt.Sprintf("external sink tool %s invoked", ev.ToolName),
	}
	e.log.Printf("leg lit: external_sink_invoked (session=%s, tool=%s, seq=%d)",
		ev.SessionID, ev.ToolName, ev.Seq)
}

func (e *Engine) buildEvidence(
	state *model.SessionState,
	ev model.InterceptedEvent,
	verdict model.Verdict,
	action model.Action,
	confidence float64,
	overlap *model.OverlapHit,
) model.EvidenceRecord {
	sinkCall := map[string]any{
		"tool_name": ev.ToolName,
		"server_id": ev.ServerID,
		"args":      RedactJSON(ev.ToolArgs, state.Tainted),
		"seq":       ev.Seq,
	}

	timeline := make([]model.TimelineItem, 0, len(state.Timeline))
	for i, seq := range state.Timeline {
		item := model.TimelineItem{
			TimelineSeq: i + 1,
			TSMono:      time.Now().UnixNano(),
			Kind:        "intercepted",
			Ref:         seq,
		}

		switch {
		case seq == state.Legs.SensitiveSourceTouched.TriggerSeq:
			item.Label = fmt.Sprintf("sensitive_source_touched: %s", state.Legs.SensitiveSourceTouched.Detail)
		case seq == state.Legs.UntrustedContentPresent.TriggerSeq:
			item.Label = fmt.Sprintf("untrusted_content_present: %s", state.Legs.UntrustedContentPresent.Detail)
		case seq == state.Legs.ExternalSinkInvoked.TriggerSeq:
			item.Label = fmt.Sprintf("external_sink_invoked: %s", state.Legs.ExternalSinkInvoked.Detail)
		default:
			item.Label = fmt.Sprintf("event #%d", seq)
		}

		timeline = append(timeline, item)
	}

	return model.EvidenceRecord{
		SessionID:    state.SessionID,
		TripTS:       time.Now().UnixNano(),
		Verdict:      verdict,
		Action:       action,
		Variant:      model.VariantA,
		Confidence:   confidence,
		Legs:         state.Legs,
		SinkCall:     sinkCall,
		ValueOverlap: overlap,
		Timeline:     timeline,
	}
}

// IngestSyscall is called when the eBPF sensor detects a non-allowlisted
// connect() syscall from a monitored PID. It lights the external_sink_invoked
// leg via the kernel plane (Variant B) and evaluates the trifecta.
//
// For v0.1, syscall events never have value overlap (we don't inspect payload),
// so the verdict for a trip is always SUSPICIOUS. The action is
// contained_by_kill for EXFIL or detected_only for SUSPICIOUS.
func (e *Engine) IngestSyscall(ev model.SyscallEvent) model.Decision {
	e.mu.Lock()
	defer e.mu.Unlock()

	sessionID := ev.SessionID
	if sessionID == "" {
		sessionID = e.store.FirstSessionID()
	}
	if sessionID == "" {
		return model.Decision{Allow: true}
	}

	state := e.store.GetOrCreate(sessionID)

	if !state.Legs.ExternalSinkInvoked.Lit {
		state.Legs.ExternalSinkInvoked = model.Leg{
			Lit:    true,
			Detail: fmt.Sprintf("connect() to %s:%d by pid %d (%s)", ev.DestIP, ev.DestPort, ev.PID, ev.Comm),
		}
		e.log.Printf("leg lit: external_sink_invoked via eBPF (session=%s, dest=%s:%d, pid=%d)",
			sessionID, ev.DestIP, ev.DestPort, ev.PID)
	}

	if !state.Legs.AllLit() {
		return model.Decision{Allow: true}
	}

	verdict := model.VerdictSuspicious
	confidence := 0.6

	action := model.ActionContained
	if verdict == model.VerdictSuspicious {
		action = model.ActionContained
	}

	state.Status = model.Tripped
	state.Confidence = confidence

	evidence := e.buildEvidenceVariantB(state, ev, verdict, action, confidence)

	if e.sink != nil {
		if err := e.sink.Emit(evidence); err != nil {
			e.log.Printf("[SECURITY] evidence sink write failed — enforcement continues but forensic record is incomplete: %v", err)
		}
	}

	e.log.Printf("TRIFECTA DETECTED (eBPF): session=%s dest=%s:%d verdict=%s action=%s",
		sessionID, ev.DestIP, ev.DestPort, verdict, action)

	return model.Decision{
		Allow:    false,
		Verdict:  verdict,
		Action:   action,
		Reason:   fmt.Sprintf("trifecta %s: connect() to %s:%d by pid %d", verdict, ev.DestIP, ev.DestPort, ev.PID),
		Evidence: &evidence,
	}
}

func (e *Engine) buildEvidenceVariantB(
	state *model.SessionState,
	ev model.SyscallEvent,
	verdict model.Verdict,
	action model.Action,
	confidence float64,
) model.EvidenceRecord {
	sinkCall := map[string]any{
		"syscall":   ev.Syscall,
		"dest_ip":   ev.DestIP,
		"dest_port": ev.DestPort,
		"pid":       ev.PID,
		"comm":      ev.Comm,
	}

	timeline := make([]model.TimelineItem, 0, len(state.Timeline)+1)
	for i, seq := range state.Timeline {
		item := model.TimelineItem{
			TimelineSeq: i + 1,
			TSMono:      time.Now().UnixNano(),
			Kind:        "intercepted",
			Ref:         seq,
		}

		switch {
		case seq == state.Legs.SensitiveSourceTouched.TriggerSeq:
			item.Label = fmt.Sprintf("sensitive_source_touched: %s", state.Legs.SensitiveSourceTouched.Detail)
		case seq == state.Legs.UntrustedContentPresent.TriggerSeq:
			item.Label = fmt.Sprintf("untrusted_content_present: %s", state.Legs.UntrustedContentPresent.Detail)
		default:
			item.Label = fmt.Sprintf("event #%d", seq)
		}

		timeline = append(timeline, item)
	}

	// Append the syscall event itself — last in causal order.
	timeline = append(timeline, model.TimelineItem{
		TimelineSeq: len(state.Timeline) + 1,
		TSMono:      ev.TSMono,
		Kind:        "syscall",
		Label:       fmt.Sprintf("external_sink_invoked: connect() to %s:%d by %s (pid %d)", ev.DestIP, ev.DestPort, ev.Comm, ev.PID),
	})

	return model.EvidenceRecord{
		SessionID:  state.SessionID,
		TripTS:     time.Now().UnixNano(),
		Verdict:    verdict,
		Action:     action,
		Variant:    model.VariantB,
		Confidence: confidence,
		Legs:       state.Legs,
		SinkCall:   sinkCall,
		Timeline:   timeline,
	}
}

// extractResultText pulls the text content from a tools/call MCP result.
// MCP results are structured as {content: [{type: "text", text: "..."}]}.
func extractResultText(result json.RawMessage) string {
	if len(result) == 0 {
		return ""
	}

	var structured struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(result, &structured) == nil && len(structured.Content) > 0 {
		var text string
		for _, c := range structured.Content {
			if c.Type == "text" {
				text += c.Text + "\n"
			}
		}
		if text != "" {
			return text
		}
	}

	return string(result)
}
