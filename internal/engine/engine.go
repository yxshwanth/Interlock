// Package engine implements the correlation and policy engine: the trifecta
// state machine, value-overlap taint checking, and verdict/evidence emission.
package engine

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

const (
	maxUntrustedExcerpts = 8
	maxUntrustedExcerpt  = 4096
	defaultFragmentChunks = 16
	defaultFragmentBytes  = 64 * 1024
)

// EvidenceSink receives evidence records when a trifecta trips.
type EvidenceSink interface {
	Emit(rec model.EvidenceRecord) error
}

// SecurityAuditSink receives security audit records (e.g. unattributed syscalls).
type SecurityAuditSink interface {
	EmitSecurityAudit(rec model.SecurityAuditEvent) error
}

// TaintForwarder is invoked (outside Engine.mu) after new tainted values are
// registered from a sensitive_source result. Used by the proxy→sensor bridge.
type TaintForwarder func(tvs []model.TaintedValue)

// Engine is the core trifecta policy engine. It evaluates tool calls against
// the three-leg state machine and emits verdicts + evidence.
type Engine struct {
	store  *SessionStore
	tagger *Tagger
	sink   EvidenceSink
	audit  SecurityAuditSink
	mode   string // "block" or "monitor"
	log    *log.Logger
	mu     sync.Mutex

	untrustedToolResults bool
	legTTL               time.Duration
	decayAfterCalls      int
	contentBindMinLen    int
	fragmentMaxChunks    int
	fragmentMaxBytes     int

	taintForwarder TaintForwarder
}

// NewEngine creates an engine wired to the given store, tagger, and mode.
// sink may be nil (evidence is logged to stderr only).
// Call Configure to apply trifecta / untrusted_origins settings from config.
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
		store:                store,
		tagger:               tagger,
		sink:                 sink,
		mode:                 mode,
		log:                  l,
		untrustedToolResults: true,
		legTTL:               30 * time.Minute,
		decayAfterCalls:      32,
		contentBindMinLen:    defaultContentBindMinLen,
		fragmentMaxChunks:    defaultFragmentChunks,
		fragmentMaxBytes:     defaultFragmentBytes,
	}
}

// Configure applies trifecta decay / content-bind knobs and untrusted_origins
// from cfg. Safe to call after NewEngine; nil cfg is a no-op.
func (e *Engine) Configure(cfg *config.Config) {
	if cfg == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.untrustedToolResults = cfg.UntrustedOrigins.ToolResults
	e.legTTL = cfg.Trifecta.LegTTLDuration()
	e.decayAfterCalls = cfg.Trifecta.DecayAfterCallsOrDefault()
	e.contentBindMinLen = cfg.Trifecta.ContentBindMinLenOrDefault()
	e.fragmentMaxChunks = cfg.Trifecta.FragmentMaxChunksOrDefault()
	e.fragmentMaxBytes = cfg.Trifecta.FragmentMaxBytesOrDefault()
}

// SetSecurityAuditSink wires optional JSONL audit logging for security events.
func (e *Engine) SetSecurityAuditSink(s SecurityAuditSink) {
	e.audit = s
}

// SetTaintForwarder wires an optional callback for newly registered taints
// (proxy→sensor Unix-socket bridge). Invoked outside Engine.mu.
func (e *Engine) SetTaintForwarder(fn TaintForwarder) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.taintForwarder = fn
}

// RegisterRemoteTaint seeds taint into a sensor session (typically k8s:<podUID>)
// from the node-local taint bridge. Lights sensitive_source_touched like openat seed.
func (e *Engine) RegisterRemoteTaint(sessionID string, tv model.TaintedValue) {
	if sessionID == "" || tv.Value == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.store.GetOrCreate(sessionID)
	e.touchSession(state, tv.Seq, "remote taint registered")

	if !state.Legs.SensitiveSourceTouched.Lit {
		now := time.Now().UnixNano()
		detail := "proxy taint bridge"
		if tv.Source != "" {
			detail = "proxy taint bridge: " + tv.Source
		}
		state.Legs.SensitiveSourceTouched = model.Leg{
			Lit:         true,
			Detail:      detail,
			LitAt:       now,
			EventsAtLit: state.EventCount,
		}
	}

	if len(tv.Variants) == 0 {
		tv.Variants = CanonicalEncodings(tv.Value)
	}
	if tv.Hash == "" {
		tv.Hash = HashValue(tv.Value)
	}
	if tv.Preview == "" {
		tv.Preview = MaskValue(tv.Value)
	}
	if tv.RegisteredAt == 0 {
		tv.RegisteredAt = time.Now().UnixNano()
	}

	added := appendUniqueTainted(state.Tainted, tv)
	if len(added) == 0 {
		return
	}
	state.Tainted = append(state.Tainted, added...)
	e.log.Printf("remote taint: session=%s source=%s registered %d value(s)",
		sessionID, tv.Source, len(added))
}

// IngestResult is called when a server→agent result arrives. It updates
// the trifecta legs (sensitive_source_touched, untrusted_content_present),
// extracts tainted values from sensitive sources, and appends to the timeline.
func (e *Engine) IngestResult(ev model.InterceptedEvent) {
	var toForward []model.TaintedValue
	var forwarder TaintForwarder

	e.mu.Lock()
	state := e.store.GetOrCreate(ev.SessionID)
	e.touchSession(state, ev.Seq, fmt.Sprintf("%s result returned", ev.ToolName))

	sensitive := e.tagger != nil && e.tagger.IsSensitiveSource(ev.ToolName, ev.ServerID)
	if sensitive {
		e.setSensitiveSourceTouched(state, ev)

		resultText := extractResultText(ev.Result)
		if resultText != "" {
			source := fmt.Sprintf("%s/%s", ev.ServerID, ev.ToolName)
			e.appendFragment(state, resultText)
			tainted := ExtractTaintedValues(resultText, source, ev.Seq)
			// Reassembly-first: secrets split across calls may only match
			// secretPatterns on the concatenated fragment buffer.
			reassembled := ExtractTaintedValues(strings.Join(state.FragmentChunks, ""), source, ev.Seq)
			added := appendUniqueTainted(state.Tainted, append(tainted, reassembled...)...)
			state.Tainted = append(state.Tainted, added...)
			if len(added) > 0 {
				e.log.Printf("extracted %d tainted value(s) from %s (session=%s)",
					len(added), source, ev.SessionID)
				toForward = added
				forwarder = e.taintForwarder
			}
		}
	} else if e.untrustedToolResults {
		e.setUntrustedContentPresent(state, ev, extractResultText(ev.Result))
	}
	e.mu.Unlock()

	if len(toForward) > 0 && forwarder != nil {
		forwarder(toForward)
	}
}

// EvaluateRequest is called before forwarding a tools/call. It checks whether
// this call should be blocked based on the trifecta state.
func (e *Engine) EvaluateRequest(ev model.InterceptedEvent) model.Decision {
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.store.GetOrCreate(ev.SessionID)
	e.touchSession(state, ev.Seq, fmt.Sprintf("%s called", ev.ToolName))

	if e.tagger == nil || !e.tagger.IsExternalSink(ev.ToolName, ev.ServerID) {
		return model.Decision{Allow: true}
	}

	e.setExternalSinkInvoked(state, ev)

	overlap := CheckOverlap(state.Tainted, ev.ToolArgs)
	verdict, confidence, ok := e.classifyTrip(state, overlap, string(ev.ToolArgs))
	if !ok {
		return model.Decision{Allow: true}
	}

	allow, action := e.proxyAction(verdict)

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

func (e *Engine) touchSession(state *model.SessionState, seq uint64, label string) {
	now := time.Now().UnixNano()
	if state.TimelineLabels == nil {
		state.TimelineLabels = make(map[uint64]string)
	}
	state.LastActivity = now
	state.EventCount++
	e.pruneLegs(state, now)
	if seq != 0 {
		state.Timeline = append(state.Timeline, seq)
		if label != "" && !strings.HasPrefix(label, " ") {
			state.TimelineLabels[seq] = label
		}
	}
}

func (e *Engine) pruneLegs(state *model.SessionState, now int64) {
	e.maybeDecayLeg(&state.Legs.SensitiveSourceTouched, state, now, "sensitive_source_touched")
	if e.maybeDecayLeg(&state.Legs.UntrustedContentPresent, state, now, "untrusted_content_present") {
		state.UntrustedExcerpts = nil
	}
	e.maybeDecayLeg(&state.Legs.ExternalSinkInvoked, state, now, "external_sink_invoked")
}

func (e *Engine) maybeDecayLeg(leg *model.Leg, state *model.SessionState, now int64, name string) bool {
	if !leg.Lit {
		return false
	}
	ttlExpired := e.legTTL > 0 && leg.LitAt > 0 && now-leg.LitAt >= e.legTTL.Nanoseconds()
	callsExpired := e.decayAfterCalls > 0 && leg.EventsAtLit > 0 &&
		state.EventCount > leg.EventsAtLit &&
		int(state.EventCount-leg.EventsAtLit) >= e.decayAfterCalls
	if !ttlExpired && !callsExpired {
		return false
	}
	*leg = model.Leg{}
	e.log.Printf("leg decayed: %s (session=%s, ttl=%v, calls=%v)", name, state.SessionID, ttlExpired, callsExpired)
	return true
}

// RewindLegClocks moves LitAt on all lit legs backward by d so the next
// touchSession/pruneLegs observes TTL expiry. Used by the FP corpus to
// exercise trifecta.leg_ttl without sleeping wall-clock time.
func (e *Engine) RewindLegClocks(sessionID string, d time.Duration) {
	if d <= 0 || sessionID == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.store.Get(sessionID)
	if state == nil {
		return
	}
	delta := d.Nanoseconds()
	rewind := func(leg *model.Leg) {
		if leg.Lit && leg.LitAt > delta {
			leg.LitAt -= delta
		} else if leg.Lit {
			leg.LitAt = 1
		}
	}
	rewind(&state.Legs.SensitiveSourceTouched)
	rewind(&state.Legs.UntrustedContentPresent)
	rewind(&state.Legs.ExternalSinkInvoked)
}

// classifyTrip decides EXFIL / SUSPICIOUS / no-trip.
// EXFIL: value overlap against registered taint (sensitive leg may have decayed).
// SUSPICIOUS: AllLit + content bind between untrusted excerpts and sink.
func (e *Engine) classifyTrip(state *model.SessionState, overlap *model.OverlapHit, sinkPayload string) (model.Verdict, float64, bool) {
	if overlap != nil {
		return model.VerdictExfil, 0.95, true
	}
	if state.Legs.AllLit() && CheckContentBind(state.UntrustedExcerpts, sinkPayload, e.contentBindMinLen) {
		return model.VerdictSuspicious, 0.6, true
	}
	return "", 0, false
}

func (e *Engine) proxyAction(verdict model.Verdict) (allow bool, action model.Action) {
	if verdict == model.VerdictExfil {
		if e.mode == "monitor" {
			return true, model.ActionAllowed
		}
		return false, model.ActionPrevented
	}
	// SUSPICIOUS: evidence/alert only — never hard-block.
	return true, model.ActionAllowed
}

func (e *Engine) variantBAction(verdict model.Verdict) (allow bool, action model.Action) {
	if verdict == model.VerdictExfil {
		return false, model.ActionContained
	}
	return true, model.ActionDetectedOnly
}

func (e *Engine) setSensitiveSourceTouched(state *model.SessionState, ev model.InterceptedEvent) {
	if state.Legs.SensitiveSourceTouched.Lit {
		return
	}
	now := time.Now().UnixNano()
	state.Legs.SensitiveSourceTouched = model.Leg{
		Lit:         true,
		TriggerSeq:  ev.Seq,
		Detail:      fmt.Sprintf("tool %s returned sensitive data", ev.ToolName),
		LitAt:       now,
		EventsAtLit: state.EventCount,
	}
	e.log.Printf("leg lit: sensitive_source_touched (session=%s, tool=%s, seq=%d)",
		ev.SessionID, ev.ToolName, ev.Seq)
}

func (e *Engine) setUntrustedContentPresent(state *model.SessionState, ev model.InterceptedEvent, excerpt string) {
	e.storeUntrustedExcerpt(state, excerpt)
	if state.Legs.UntrustedContentPresent.Lit {
		return
	}
	now := time.Now().UnixNano()
	state.Legs.UntrustedContentPresent = model.Leg{
		Lit:         true,
		TriggerSeq:  ev.Seq,
		Detail:      fmt.Sprintf("untrusted content from tool result (tool=%s)", ev.ToolName),
		LitAt:       now,
		EventsAtLit: state.EventCount,
	}
	e.log.Printf("leg lit: untrusted_content_present (session=%s, seq=%d)",
		ev.SessionID, ev.Seq)
}

func (e *Engine) storeUntrustedExcerpt(state *model.SessionState, excerpt string) {
	excerpt = strings.TrimSpace(excerpt)
	if excerpt == "" {
		return
	}
	if len(excerpt) > maxUntrustedExcerpt {
		excerpt = excerpt[:maxUntrustedExcerpt]
	}
	if len(state.UntrustedExcerpts) >= maxUntrustedExcerpts {
		state.UntrustedExcerpts = state.UntrustedExcerpts[1:]
	}
	state.UntrustedExcerpts = append(state.UntrustedExcerpts, excerpt)
}

func (e *Engine) setExternalSinkInvoked(state *model.SessionState, ev model.InterceptedEvent) {
	if state.Legs.ExternalSinkInvoked.Lit {
		return
	}
	now := time.Now().UnixNano()
	state.Legs.ExternalSinkInvoked = model.Leg{
		Lit:         true,
		TriggerSeq:  ev.Seq,
		Detail:      fmt.Sprintf("external sink tool %s invoked", ev.ToolName),
		LitAt:       now,
		EventsAtLit: state.EventCount,
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
			if label, ok := state.TimelineLabels[seq]; ok {
				item.Label = label
			} else {
				item.Label = fmt.Sprintf("event #%d", seq)
			}
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
// connect/sendto/dns, a write correlated to a recent suspicious connect,
// or an openat of a configured sensitive path.
// Payload overlap (write/sendto) → EXFIL (0.95). SUSPICIOUS requires AllLit
// plus content-bind and never hard-kills. openat never upgrades to EXFIL.
func (e *Engine) IngestSyscall(ev model.SyscallEvent) model.Decision {
	e.mu.Lock()
	defer e.mu.Unlock()

	sessionID := ev.SessionID
	if sessionID == "" {
		e.recordUnattributedSyscall(ev, "no session attribution for monitored PID")
		return model.Decision{Allow: true}
	}

	state := e.store.GetOrCreate(sessionID)
	e.touchSession(state, 0, "")

	if !state.Legs.ExternalSinkInvoked.Lit {
		detail := fmt.Sprintf("%s to %s:%d by pid %d (%s)", ev.Syscall, ev.DestIP, ev.DestPort, ev.PID, ev.Comm)
		switch ev.Syscall {
		case "write":
			detail = fmt.Sprintf("write() egress correlated to %s:%d by pid %d (%s)", ev.DestIP, ev.DestPort, ev.PID, ev.Comm)
		case "openat":
			detail = fmt.Sprintf("openat sensitive path %s by pid %d (%s)", ev.Path, ev.PID, ev.Comm)
		case "dns":
			detail = fmt.Sprintf("dns sendto %s:%d by pid %d (%s)", ev.DestIP, ev.DestPort, ev.PID, ev.Comm)
		}
		now := time.Now().UnixNano()
		state.Legs.ExternalSinkInvoked = model.Leg{
			Lit:         true,
			Detail:      detail,
			LitAt:       now,
			EventsAtLit: state.EventCount,
		}
		e.log.Printf("leg lit: external_sink_invoked via eBPF (session=%s, syscall=%s, dest=%s:%d, path=%s, pid=%d)",
			sessionID, ev.Syscall, ev.DestIP, ev.DestPort, ev.Path, ev.PID)
	}

	var overlap *model.OverlapHit
	if ev.Syscall != "openat" && ev.PayloadExcerpt != "" {
		overlap = CheckOverlapPayload(state.Tainted, ev.PayloadExcerpt)
	}

	verdict, confidence, ok := e.classifyTrip(state, overlap, ev.PayloadExcerpt)
	if !ok {
		return model.Decision{Allow: true}
	}

	allow, action := e.variantBAction(verdict)

	state.Status = model.Tripped
	state.Confidence = confidence

	evidence := e.buildEvidenceVariantB(state, ev, verdict, action, confidence, overlap)

	if e.sink != nil {
		if err := e.sink.Emit(evidence); err != nil {
			e.log.Printf("[SECURITY] evidence sink write failed — enforcement continues but forensic record is incomplete: %v", err)
		}
	}

	e.log.Printf("TRIFECTA DETECTED (eBPF): session=%s syscall=%s dest=%s:%d path=%s verdict=%s action=%s",
		sessionID, ev.Syscall, ev.DestIP, ev.DestPort, ev.Path, verdict, action)

	reason := fmt.Sprintf("trifecta %s: %s to %s:%d by pid %d", verdict, ev.Syscall, ev.DestIP, ev.DestPort, ev.PID)
	if ev.Syscall == "openat" {
		reason = fmt.Sprintf("trifecta %s: openat %s by pid %d", verdict, ev.Path, ev.PID)
	}

	return model.Decision{
		Allow:    allow,
		Verdict:  verdict,
		Action:   action,
		Reason:   reason,
		Evidence: &evidence,
	}
}

// IngestSyscallSensor handles Variant B events in sensor-only mode (no MCP proxy).
//
// openat on a sensitive path: seed taint + light sensitive_source_touched, do not
// contain (opening a file is not exfiltration).
// connect/write/sendto/dns: EXFIL on payload overlap; SUSPICIOUS only with AllLit
// + content-bind (soft detected_only).
func (e *Engine) IngestSyscallSensor(ev model.SyscallEvent) model.Decision {
	e.mu.Lock()
	defer e.mu.Unlock()

	sessionID := ev.SessionID
	if sessionID == "" {
		e.recordUnattributedSyscall(ev, "no pod attribution for monitored PID")
		return model.Decision{Allow: true}
	}

	state := e.store.GetOrCreate(sessionID)
	e.touchSession(state, 0, "")

	if ev.Syscall == "openat" {
		e.seedSensorSensitiveOpen(state, ev)
		return model.Decision{Allow: true}
	}

	detail := fmt.Sprintf("%s to %s:%d by pid %d (%s)", ev.Syscall, ev.DestIP, ev.DestPort, ev.PID, ev.Comm)
	switch ev.Syscall {
	case "write":
		detail = fmt.Sprintf("write() egress correlated to %s:%d by pid %d (%s)", ev.DestIP, ev.DestPort, ev.PID, ev.Comm)
	case "dns":
		detail = fmt.Sprintf("dns sendto %s:%d by pid %d (%s)", ev.DestIP, ev.DestPort, ev.PID, ev.Comm)
	}
	now := time.Now().UnixNano()
	state.Legs.ExternalSinkInvoked = model.Leg{
		Lit:         true,
		Detail:      detail,
		LitAt:       now,
		EventsAtLit: state.EventCount,
	}

	var overlap *model.OverlapHit
	if ev.PayloadExcerpt != "" {
		overlap = CheckOverlapPayload(state.Tainted, ev.PayloadExcerpt)
	}

	verdict, confidence, ok := e.classifyTrip(state, overlap, ev.PayloadExcerpt)
	if !ok {
		return model.Decision{Allow: true}
	}

	allow, action := e.variantBAction(verdict)
	state.Status = model.Tripped
	state.Confidence = confidence

	evidence := e.buildEvidenceVariantB(state, ev, verdict, action, confidence, overlap)

	if e.sink != nil {
		if err := e.sink.Emit(evidence); err != nil {
			e.log.Printf("[SECURITY] evidence sink write failed — enforcement continues but forensic record is incomplete: %v", err)
		}
	}

	e.log.Printf("SENSOR TRIP: session=%s syscall=%s dest=%s:%d path=%s verdict=%s action=%s",
		sessionID, ev.Syscall, ev.DestIP, ev.DestPort, ev.Path, verdict, action)

	reason := fmt.Sprintf("sensor %s: %s to %s:%d by pid %d", verdict, ev.Syscall, ev.DestIP, ev.DestPort, ev.PID)
	return model.Decision{
		Allow:    allow,
		Verdict:  verdict,
		Action:   action,
		Reason:   reason,
		Evidence: &evidence,
	}
}

// seedSensorSensitiveOpen lights sensitive_source_touched and registers taint from
// FileContents (read by the DaemonSet via /proc/<pid>/root). Does not trip or kill.
// Does not light untrusted_content_present — sensor-only has no MCP untrusted plane.
func (e *Engine) seedSensorSensitiveOpen(state *model.SessionState, ev model.SyscallEvent) {
	path := ev.Path
	if path == "" {
		path = "(unknown)"
	}
	if !state.Legs.SensitiveSourceTouched.Lit {
		now := time.Now().UnixNano()
		state.Legs.SensitiveSourceTouched = model.Leg{
			Lit:         true,
			Detail:      fmt.Sprintf("openat sensitive path %s by pid %d (%s)", path, ev.PID, ev.Comm),
			LitAt:       now,
			EventsAtLit: state.EventCount,
		}
	}

	if ev.FileContents == "" {
		e.log.Printf("sensor seed: openat %s session=%s — no file contents (taint not registered)", path, state.SessionID)
		return
	}

	source := "sensor:" + path
	tainted := ExtractTaintedValues(ev.FileContents, source, 0)
	if len(tainted) == 0 {
		e.log.Printf("sensor seed: openat %s session=%s — no secret patterns in file (%d bytes)",
			path, state.SessionID, len(ev.FileContents))
		return
	}
	state.Tainted = append(state.Tainted, tainted...)
	e.log.Printf("sensor seed: openat %s session=%s — registered %d tainted value(s)",
		path, state.SessionID, len(tainted))
}

func (e *Engine) recordUnattributedSyscall(ev model.SyscallEvent, reason string) {
	e.log.Printf("[SECURITY] unattributed %s: pid=%d comm=%q dest=%s:%d — %s (fail-safe: not guessing session)",
		ev.Syscall, ev.PID, ev.Comm, ev.DestIP, ev.DestPort, reason)

	if e.audit == nil {
		return
	}
	rec := model.SecurityAuditEvent{
		Kind:    "unattributed_syscall",
		Reason:  reason,
		TSWall:  time.Now(),
		Syscall: ev,
	}
	if err := e.audit.EmitSecurityAudit(rec); err != nil {
		e.log.Printf("[SECURITY] security audit write failed: %v", err)
	}
}

// RecordToolShadowing logs and audit-emits a cross-server tool-name collision.
// Registration keeps the first owner; this is not a trifecta trip.
func (e *Engine) RecordToolShadowing(ev model.ShadowEvent) {
	reason := fmt.Sprintf("tool %q: owner=%s, shadow=%s (session %s) — route unchanged, shadow refused",
		ev.ToolName, ev.OwnerServerID, ev.ShadowServerID, ev.SessionID)
	e.log.Printf("[SECURITY] tool shadowing: %s", reason)

	if e.audit == nil {
		return
	}
	rec := model.SecurityAuditEvent{
		Kind:   "tool_shadowing",
		Reason: reason,
		TSWall: time.Now(),
	}
	if err := e.audit.EmitSecurityAudit(rec); err != nil {
		e.log.Printf("[SECURITY] security audit write failed: %v", err)
	}
}

func (e *Engine) buildEvidenceVariantB(
	state *model.SessionState,
	ev model.SyscallEvent,
	verdict model.Verdict,
	action model.Action,
	confidence float64,
	overlap *model.OverlapHit,
) model.EvidenceRecord {
	sinkCall := map[string]any{
		"syscall":   ev.Syscall,
		"dest_ip":   ev.DestIP,
		"dest_port": ev.DestPort,
		"pid":       ev.PID,
		"comm":      ev.Comm,
	}
	if ev.Path != "" {
		sinkCall["path"] = ev.Path
	}
	if ev.PayloadExcerpt != "" {
		// Redact known secrets from the excerpt before persistence.
		redacted := RedactJSON(json.RawMessage(ev.PayloadExcerpt), state.Tainted)
		sinkCall["payload_excerpt"] = string(redacted)
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
			if label, ok := state.TimelineLabels[seq]; ok {
				item.Label = label
			} else {
				item.Label = fmt.Sprintf("event #%d", seq)
			}
		}

		timeline = append(timeline, item)
	}

	label := fmt.Sprintf("external_sink_invoked: %s to %s:%d by %s (pid %d)", ev.Syscall, ev.DestIP, ev.DestPort, ev.Comm, ev.PID)
	timeline = append(timeline, model.TimelineItem{
		TimelineSeq: len(state.Timeline) + 1,
		TSMono:      ev.TSMono,
		Kind:        "syscall",
		Label:       label,
	})

	return model.EvidenceRecord{
		SessionID:    state.SessionID,
		TripTS:       time.Now().UnixNano(),
		Verdict:      verdict,
		Action:       action,
		Variant:      model.VariantB,
		Confidence:   confidence,
		Legs:         state.Legs,
		SinkCall:     sinkCall,
		ValueOverlap: overlap,
		Timeline:     timeline,
		Pod:          ev.Pod,
	}
}

// appendFragment pushes a sensitive-source text chunk into the session's
// rolling FIFO, enforcing chunk-count and total-byte caps.
func (e *Engine) appendFragment(state *model.SessionState, chunk string) {
	if chunk == "" {
		return
	}
	// extractResultText appends a trailing newline per text leaf; strip so
	// abutting paginated halves reassemble into a contiguous secret.
	chunk = strings.TrimRight(chunk, "\n")
	if chunk == "" {
		return
	}
	maxChunks := e.fragmentMaxChunks
	if maxChunks <= 0 {
		maxChunks = defaultFragmentChunks
	}
	maxBytes := e.fragmentMaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultFragmentBytes
	}
	// Oversized single chunk: keep a trailing window so reassembly can still
	// catch a secret that straddles the end of a large page.
	if len(chunk) > maxBytes {
		chunk = chunk[len(chunk)-maxBytes:]
	}
	state.FragmentChunks = append(state.FragmentChunks, chunk)
	for len(state.FragmentChunks) > maxChunks || fragmentBytes(state.FragmentChunks) > maxBytes {
		if len(state.FragmentChunks) == 0 {
			break
		}
		state.FragmentChunks = state.FragmentChunks[1:]
	}
}

func fragmentBytes(chunks []string) int {
	n := 0
	for _, c := range chunks {
		n += len(c)
	}
	return n
}

// appendUniqueTainted returns values in candidates whose Hash is not already
// present in existing (or earlier in candidates).
func appendUniqueTainted(existing []model.TaintedValue, candidates ...model.TaintedValue) []model.TaintedValue {
	seen := make(map[string]struct{}, len(existing)+len(candidates))
	for _, tv := range existing {
		seen[tv.Hash] = struct{}{}
	}
	var out []model.TaintedValue
	for _, tv := range candidates {
		if _, ok := seen[tv.Hash]; ok {
			continue
		}
		seen[tv.Hash] = struct{}{}
		out = append(out, tv)
	}
	return out
}

// extractResultText pulls text from a tools/call MCP result for taint scanning.
// It prefers content[].type=="text", then walks other JSON string leaves
// (bounded depth/bytes) so secrets outside the MCP text envelope are still found.
func extractResultText(result json.RawMessage) string {
	if len(result) == 0 {
		return ""
	}

	var b strings.Builder
	var structured struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(result, &structured) == nil {
		for _, c := range structured.Content {
			if c.Type == "text" {
				b.WriteString(c.Text)
				b.WriteByte('\n')
			}
		}
	}

	var root any
	if err := json.Unmarshal(result, &root); err != nil {
		if b.Len() > 0 {
			return b.String()
		}
		return string(result)
	}
	// Skip the MCP "content" array — already handled above — so paginated
	// content[].text halves stay abutting in the fragment buffer.
	walkJSONStrings(root, 0, &b, true)
	if b.Len() == 0 {
		return string(result)
	}
	return b.String()
}

const (
	maxExtractDepth = 8
	maxExtractBytes = 64 * 1024
)

func walkJSONStrings(v any, depth int, b *strings.Builder, skipContentKey bool) {
	if depth > maxExtractDepth || b.Len() >= maxExtractBytes {
		return
	}
	switch x := v.(type) {
	case string:
		if b.Len()+len(x)+1 > maxExtractBytes {
			remain := maxExtractBytes - b.Len()
			if remain > 0 {
				b.WriteString(x[:remain])
			}
			return
		}
		b.WriteString(x)
		b.WriteByte('\n')
	case []any:
		for _, el := range x {
			walkJSONStrings(el, depth+1, b, false)
			if b.Len() >= maxExtractBytes {
				return
			}
		}
	case map[string]any:
		for k, el := range x {
			if skipContentKey && k == "content" {
				continue
			}
			walkJSONStrings(el, depth+1, b, false)
			if b.Len() >= maxExtractBytes {
				return
			}
		}
	}
}
