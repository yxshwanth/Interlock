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
	maxUntrustedExcerpts  = 8
	maxUntrustedExcerpt   = 4096
	defaultFragmentChunks = 16
	defaultFragmentBytes  = 64 * 1024
	defaultEgressFragmentChunks = 16
	defaultEgressFragmentBytes  = 4 * 1024
	defaultEgressFragmentAge    = 10 * time.Second
	defaultEgressMaxFlows       = 32
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

// UntrustedForwarder is invoked (outside Engine.mu) the first time a proxy
// session lights untrusted_content_present, so a sensor-only session sharing
// the same taint_bridge can light its own copy of the leg. Without this,
// IngestSyscallSensor can never light untrusted_content_present at all —
// AllLit() is permanently false in sensor-only mode, so the entire soft
// SUSPICIOUS tier is inert there regardless of the connect-only classifyTrip
// fix. See docs/cve_corpus.md and docs/architecture.md §13.
type UntrustedForwarder func(source string, seq uint64)

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
	chunkMatchBytes      int
	chunkMatchMinLen     int
	egressReassemblyEnabled bool
	egressFragmentMaxChunks int
	egressFragmentMaxBytes  int
	egressFragmentMaxAge    time.Duration
	egressMaxFlows          int
	vaultEnabled         bool
	vaultAuthorize       []config.VaultAuthorizeEntry
	sensitivePaths       []string
	containerLimits      ContainerLimits

	taintForwarder     TaintForwarder
	untrustedForwarder UntrustedForwarder
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
		chunkMatchBytes:      defaultChunkMatchBytes,
		chunkMatchMinLen:     defaultChunkMatchMinLen,
		egressReassemblyEnabled: true,
		egressFragmentMaxChunks: defaultEgressFragmentChunks,
		egressFragmentMaxBytes:  defaultEgressFragmentBytes,
		egressFragmentMaxAge:    defaultEgressFragmentAge,
		egressMaxFlows:          defaultEgressMaxFlows,
		containerLimits:         DefaultContainerLimits(),
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
	e.chunkMatchBytes = cfg.Trifecta.ChunkMatchBytesOrDefault()
	e.chunkMatchMinLen = cfg.Trifecta.ChunkMatchMinLenOrDefault()
	e.egressReassemblyEnabled = cfg.Trifecta.EgressReassemblyEnabledOrDefault()
	e.egressFragmentMaxChunks = cfg.Trifecta.EgressFragmentMaxChunksOrDefault()
	e.egressFragmentMaxBytes = cfg.Trifecta.EgressFragmentMaxBytesOrDefault()
	e.egressFragmentMaxAge = cfg.Trifecta.EgressFragmentMaxAgeOrDefault()
	e.egressMaxFlows = cfg.Trifecta.EgressMaxDestinationsOrDefault()
	SetMaxDecodeDepth(cfg.Trifecta.MaxDecodeDepthOrDefault())
	e.vaultEnabled = cfg.Vault.Enabled
	e.vaultAuthorize = applyVaultAuthorize(cfg.Vault.Authorize)
	e.sensitivePaths = append([]string(nil), cfg.SensitivePaths...)
	e.containerLimits = ContainerLimits{
		Enabled:              cfg.Trifecta.ContainerInspectEnabledOrDefault(),
		MaxDecompressedBytes: cfg.Trifecta.ContainerMaxDecompressedBytesOrDefault(),
		MaxDescentDepth:      cfg.Trifecta.ContainerMaxDescentDepthOrDefault(),
		MaxParts:             cfg.Trifecta.ContainerMaxPartsOrDefault(),
		MaxInspect:           time.Duration(cfg.Trifecta.ContainerMaxInspectMsOrDefault()) * time.Millisecond,
	}
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

// SetUntrustedForwarder wires an optional callback fired the first time a
// proxy session lights untrusted_content_present (proxy→sensor Unix-socket
// bridge). Invoked outside Engine.mu. See RegisterRemoteUntrusted.
func (e *Engine) SetUntrustedForwarder(fn UntrustedForwarder) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.untrustedForwarder = fn
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
	if len(tv.Chunks) == 0 {
		AttachChunks(&tv, e.chunkMatchBytes, e.chunkMatchMinLen)
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

// RegisterRemoteUntrusted lights untrusted_content_present in a sensor
// session (typically k8s:<podUID>) from the node-local taint bridge, mirroring
// RegisterRemoteTaint. Without this, IngestSyscallSensor can never light this
// leg on its own — AllLit() would be permanently false in sensor-only mode,
// making the entire soft SUSPICIOUS tier inert there (see docs/architecture.md
// §13, docs/cve_corpus.md). Does not carry the excerpt text itself (bridge
// stays a boolean "untrusted content was observed" signal, not a channel for
// raw tool-result content) — content-bound SUSPICIOUS for payload-bearing
// sensor-observed egress still requires a real excerpt, which is not
// currently forwarded; the payload-less connect-only tripwire this restores
// does not need one (classifyTrip fires on AllLit alone for those).
func (e *Engine) RegisterRemoteUntrusted(sessionID string, source string, seq uint64) {
	if sessionID == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.store.GetOrCreate(sessionID)
	e.touchSession(state, seq, "remote untrusted content registered")

	if state.Legs.UntrustedContentPresent.Lit {
		return
	}
	now := time.Now().UnixNano()
	detail := "proxy taint bridge: untrusted content observed"
	if source != "" {
		detail = "proxy taint bridge: untrusted content observed (" + source + ")"
	}
	state.Legs.UntrustedContentPresent = model.Leg{
		Lit:         true,
		Detail:      detail,
		LitAt:       now,
		EventsAtLit: state.EventCount,
	}
	e.log.Printf("remote untrusted: session=%s source=%s leg lit", sessionID, source)
}

// IngestResult is called when a server→agent result arrives. It updates
// the trifecta legs (sensitive_source_touched, untrusted_content_present),
// extracts tainted values from sensitive sources, and appends to the timeline.
func (e *Engine) IngestResult(ev model.InterceptedEvent) {
	var toForward []model.TaintedValue
	var forwarder TaintForwarder
	var newlyUntrusted bool
	var untrustedForwarder UntrustedForwarder

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
			combined := append(tainted, reassembled...)
			if readPath := consumePendingSensitiveReadPath(state, ev.ServerID, ev.ToolName); readPath != "" &&
				IsSensitiveResourcePath(readPath, e.sensitivePaths) {
				combined = append(combined, TaintPathDrivenContent(resultText, readPath, source, ev.Seq)...)
			}
			combined = append(combined, e.taintFromContainer(resultText, source, ev.Seq)...)
			e.attachChunksAll(combined)
			added := appendUniqueTainted(state.Tainted, combined...)
			state.Tainted = append(state.Tainted, added...)
			e.vaultMint(state, added)
			if len(added) > 0 {
				e.log.Printf("extracted %d tainted value(s) from %s (session=%s)",
					len(added), source, ev.SessionID)
				toForward = added
				forwarder = e.taintForwarder
			}
		} else {
			consumePendingSensitiveReadPath(state, ev.ServerID, ev.ToolName)
		}
	} else if e.untrustedToolResults {
		if !state.Legs.UntrustedContentPresent.Lit {
			newlyUntrusted = true
			untrustedForwarder = e.untrustedForwarder
		}
		e.setUntrustedContentPresent(state, ev, extractResultText(ev.Result))
	}
	e.mu.Unlock()

	if len(toForward) > 0 && forwarder != nil {
		forwarder(toForward)
	}
	if newlyUntrusted && untrustedForwarder != nil {
		untrustedForwarder(ev.ToolName, ev.Seq)
	}
}

// EvaluateRequest is called before forwarding a tools/call. It checks whether
// this call should be blocked based on the trifecta state.
func (e *Engine) EvaluateRequest(ev model.InterceptedEvent) model.Decision {
	e.mu.Lock()
	defer e.mu.Unlock()

	state := e.store.GetOrCreate(ev.SessionID)
	e.touchSession(state, ev.Seq, fmt.Sprintf("%s called", ev.ToolName))
	e.stashSensitiveReadPath(state, ev)

	if e.tagger == nil || !e.tagger.IsExternalSink(ev.ToolName, ev.ServerID) {
		return model.Decision{Allow: true}
	}

	e.setExternalSinkInvoked(state, ev)

	args := ev.ToolArgs
	var forwardArgs json.RawMessage
	if e.vaultEnabled {
		if ok, allowClass := e.vaultToolAuthorized(ev.ToolName); ok {
			detok := vaultDetokenize(args, state.Vault, allowClass)
			if string(detok) != string(args) {
				args = detok
				forwardArgs = detok
			}
		}
	}

	overlap, containerAbort := CheckOverlapLimited(state.Tainted, args, e.containerLimits)
	// A tools/call always has an args channel (even if this call's args are
	// short/empty) — content-bind gates SUSPICIOUS here unconditionally.
	verdict, confidence, ok := e.classifyTrip(state, overlap, string(args), true, containerAbort)
	if !ok {
		dec := model.Decision{Allow: true}
		if forwardArgs != nil {
			dec.ForwardArgs = forwardArgs
		}
		return dec
	}

	allow, action := e.proxyAction(verdict)

	state.Status = model.Tripped
	state.Confidence = confidence

	// buildEvidence uses ev.ToolArgs for redaction; scan used detokenized args
	// when vault authorized. Overlap hit already carries the match form.
	evidence := e.buildEvidence(state, ev, verdict, action, confidence, overlap)

	if e.sink != nil {
		if err := e.sink.Emit(evidence); err != nil {
			e.log.Printf("[SECURITY] evidence sink write failed — enforcement continues but forensic record is incomplete: %v", err)
		}
	}

	e.log.Printf("TRIFECTA DETECTED: session=%s tool=%s verdict=%s action=%s",
		ev.SessionID, ev.ToolName, verdict, action)

	reason := fmt.Sprintf("trifecta %s: %s", verdict, ev.ToolName)
	if verdict == model.VerdictSuspicious && containerAbort != ContainerAbortNone {
		reason = fmt.Sprintf("trifecta %s: container_inspect_limit (%s): %s", verdict, containerAbort, ev.ToolName)
	}
	dec := model.Decision{
		Allow:    allow,
		Verdict:  verdict,
		Action:   action,
		Reason:   reason,
		Evidence: &evidence,
	}
	// Only hand detokenized args to the proxy when the call is allowed —
	// never rehydrate the real secret on a blocked path.
	if allow && forwardArgs != nil {
		dec.ForwardArgs = forwardArgs
	}
	return dec
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
// SUSPICIOUS: AllLit, plus one of —
//   - the sink event carries a payload/args channel at all, and that channel
//     shares byte-level content with an untrusted excerpt (CheckContentBind);
//   - the sink event has NO payload channel by construction (a bare
//     connect() — TCP/UDP handshakes carry no application data, that's what
//     the follow-up write()/sendto() is for). Content-bind cannot apply to
//     "nothing"; requiring it here made the connect()-only tripwire
//     structurally unreachable (an empty sink string always fails
//     CheckContentBind's length check), silently deleting the signal a
//     malicious subprocess opening its own raw socket is supposed to trip —
//     see cve_2025_53967_figma_reverse_shell_connect_only_gap in
//     internal/corpus/scenarios_cve.go and docs/cve_corpus.md.
//
// hasPayloadChannel is false only for events that structurally never carry
// data (eBPF "connect"); true for anything that does (write/writev/sendto/
// sendmsg/dns PayloadExcerpt, and Variant A tool-call args), even if this
// particular instance's payload happens to be empty or unrelated — for
// those, content-bind still gates SUSPICIOUS exactly as ROADMAP §1 intends.
func (e *Engine) classifyTrip(state *model.SessionState, overlap *model.OverlapHit, sinkPayload string, hasPayloadChannel bool, containerAbort ContainerAbortReason) (model.Verdict, float64, bool) {
	if overlap != nil {
		return model.VerdictExfil, 0.95, true
	}
	if !state.Legs.AllLit() {
		return "", 0, false
	}
	if !hasPayloadChannel {
		return model.VerdictSuspicious, 0.6, true
	}
	if CheckContentBind(state.UntrustedExcerpts, sinkPayload, e.contentBindMinLen) {
		return model.VerdictSuspicious, 0.6, true
	}
	// Opaque container left but inspection hit a hard limit — soft signal only
	// (ROADMAP §20). Never EXFIL from an aborted walk.
	if containerAbort != ContainerAbortNone {
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

	if ev.Syscall == "lsm_deny" {
		return e.ingestLSMDeny(ev)
	}

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
	var containerAbort ContainerAbortReason
	payloadForOverlap := ev.PayloadExcerpt
	if ev.Syscall != "openat" && ev.PayloadExcerpt != "" {
		payloadForOverlap = e.egressCandidatePayload(state, ev)
		overlap, containerAbort = CheckOverlapPayloadLimited(state.Tainted, payloadForOverlap, e.containerLimits)
	}

	// connect() is a bare TCP/UDP handshake — it never carries application
	// data at the eBPF level (no Payload field on the raw event at all), so
	// content-bind cannot apply to it; every other syscall type here
	// (write/writev/sendto/sendmsg/dns) does carry a payload channel.
	verdict, confidence, ok := e.classifyTrip(state, overlap, ev.PayloadExcerpt, ev.Syscall != "connect", containerAbort)
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
	if verdict == model.VerdictSuspicious && containerAbort != ContainerAbortNone {
		reason = fmt.Sprintf("trifecta %s: container_inspect_limit (%s): %s to %s:%d by pid %d",
			verdict, containerAbort, ev.Syscall, ev.DestIP, ev.DestPort, ev.PID)
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

	if ev.Syscall == "lsm_deny" {
		return e.ingestLSMDeny(ev)
	}

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
	var containerAbort ContainerAbortReason
	payloadForOverlap := ev.PayloadExcerpt
	if ev.PayloadExcerpt != "" {
		payloadForOverlap = e.egressCandidatePayload(state, ev)
		overlap, containerAbort = CheckOverlapPayloadLimited(state.Tainted, payloadForOverlap, e.containerLimits)
	}

	// See IngestSyscall's identical comment: connect() has no payload
	// channel at all; every other syscall reaching this point does.
	verdict, confidence, ok := e.classifyTrip(state, overlap, ev.PayloadExcerpt, ev.Syscall != "connect", containerAbort)
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
	if verdict == model.VerdictSuspicious && containerAbort != ContainerAbortNone {
		reason = fmt.Sprintf("sensor %s: container_inspect_limit (%s): %s to %s:%d by pid %d",
			verdict, containerAbort, ev.Syscall, ev.DestIP, ev.DestPort, ev.PID)
	}
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
	if len(tainted) == 0 && IsSensitiveResourcePath(path, e.sensitivePaths) {
		tainted = TaintPathDrivenContent(ev.FileContents, path, source, 0)
	}
	tainted = append(tainted, e.taintFromContainer(ev.FileContents, source, 0)...)
	if len(tainted) == 0 {
		e.log.Printf("sensor seed: openat %s session=%s — no taint registered (%d bytes)",
			path, state.SessionID, len(ev.FileContents))
		return
	}
	e.attachChunksAll(tainted)
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

// RecordFailClosedTransition audit-logs fail-closed engage/clear transitions.
func (e *Engine) RecordFailClosedTransition(engaged bool, reason string) {
	kind := "fail_closed_cleared"
	if engaged {
		kind = "fail_closed_engaged"
	}
	if e.audit == nil {
		return
	}
	rec := model.SecurityAuditEvent{
		Kind:   kind,
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

// ingestLSMDeny handles a kernel-side connect() denial reported by the
// opt-in LSM quarantine hook (v0.3 Phase 2, Slice 1 — ebpf.lsm_enforce).
// The engine already confirmed EXFIL to arm the quarantine (see
// internal/ebpf/sensor.go's Quarantine call alongside containPIDs); this is
// purely a follow-up record that a *repeat* connection attempt from the same
// PID/cgroup was denied in-kernel before the socket formed — no
// leg/overlap re-classification, no new containment decision. Known gap:
// the very first EXFIL-carrying packet is never caught here — it is always
// contained_by_kill, since detection is payload-driven and necessarily lands
// after connect() has already succeeded.
func (e *Engine) ingestLSMDeny(ev model.SyscallEvent) model.Decision {
	reason := fmt.Sprintf("lsm quarantine denied repeat connect() by pid %d (%s)", ev.PID, ev.Comm)

	sessionID := ev.SessionID
	if sessionID == "" {
		e.recordUnattributedSyscall(ev, "no session attribution for LSM-denied connect")
		return model.Decision{Allow: true, Verdict: model.VerdictExfil, Action: model.ActionPrevented, Reason: reason}
	}

	state := e.store.Get(sessionID)
	if state == nil || state.Status != model.Tripped {
		e.log.Printf("[SECURITY] lsm_deny for session=%s pid=%d comm=%s but session not tripped locally — "+
			"quarantine entry may be stale (kernel denied the connect regardless)", sessionID, ev.PID, ev.Comm)
		return model.Decision{Allow: false, Verdict: model.VerdictExfil, Action: model.ActionPrevented, Reason: reason}
	}

	evidence := e.buildLSMDenyEvidence(state, ev)

	if e.sink != nil {
		if err := e.sink.Emit(evidence); err != nil {
			e.log.Printf("[SECURITY] evidence sink write failed — enforcement continues but forensic record is incomplete: %v", err)
		}
	}

	e.log.Printf("LSM QUARANTINE HELD: session=%s pid=%d comm=%s — repeat connect() denied in-kernel",
		sessionID, ev.PID, ev.Comm)

	return model.Decision{
		Allow:    false,
		Verdict:  model.VerdictExfil,
		Action:   model.ActionPrevented,
		Reason:   reason,
		Evidence: &evidence,
	}
}

// buildLSMDenyEvidence builds a lightweight follow-up EvidenceRecord for an
// already-tripped session, recording that the kernel denied a repeat
// connect() attempt. Mirrors buildEvidenceVariantB's shape without
// re-deriving legs/overlap (the session already tripped for those).
func (e *Engine) buildLSMDenyEvidence(state *model.SessionState, ev model.SyscallEvent) model.EvidenceRecord {
	sinkCall := map[string]any{
		"syscall": "lsm_deny",
		"pid":     ev.PID,
		"comm":    ev.Comm,
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
	timeline = append(timeline, model.TimelineItem{
		TimelineSeq: len(state.Timeline) + 1,
		TSMono:      ev.TSMono,
		Kind:        "syscall",
		Label:       fmt.Sprintf("lsm_deny: kernel denied repeat connect() by %s (pid %d)", ev.Comm, ev.PID),
	})

	return model.EvidenceRecord{
		SessionID:  state.SessionID,
		TripTS:     time.Now().UnixNano(),
		Verdict:    model.VerdictExfil,
		Action:     model.ActionPrevented,
		Variant:    model.VariantB,
		Confidence: state.Confidence,
		Legs:       state.Legs,
		SinkCall:   sinkCall,
		Timeline:   timeline,
		Pod:        ev.Pod,
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

// egressCandidatePayload returns the payload to scan for overlap on this egress
// event. When reassembly is enabled, it appends the normalized fragment to a
// bounded per-(pid,destination) flow buffer and returns the concatenated window.
func (e *Engine) egressCandidatePayload(state *model.SessionState, ev model.SyscallEvent) string {
	if ev.Syscall == "openat" || ev.PayloadExcerpt == "" {
		return ev.PayloadExcerpt
	}
	fragment := normalizedEgressFragment(ev)
	if fragment == "" {
		return ev.PayloadExcerpt
	}
	if !e.egressReassemblyEnabled {
		return fragment
	}
	return e.appendEgressFlowFragment(state, ev, fragment)
}

func normalizedEgressFragment(ev model.SyscallEvent) string {
	if ev.Syscall != "dns" {
		return ev.PayloadExcerpt
	}
	// DNS exfil commonly puts payload bytes in the left-most label(s):
	// "<frag>.exfil.evil.example". Reassemble on that fragment, not the whole
	// query string, so repeated suffixes do not drown the signal.
	q := strings.TrimSpace(strings.TrimSuffix(ev.PayloadExcerpt, "."))
	if q == "" {
		return ""
	}
	if i := strings.IndexByte(q, '.'); i > 0 {
		return q[:i]
	}
	return q
}

func (e *Engine) appendEgressFlowFragment(state *model.SessionState, ev model.SyscallEvent, fragment string) string {
	if state.EgressFlows == nil {
		state.EgressFlows = make(map[string]*model.EgressFlowBuffer)
	}
	now := e.egressEventTime(ev)
	e.pruneEgressFlows(state, now)

	key, dest := e.egressFlowKey(ev)
	flow, ok := state.EgressFlows[key]
	if !ok {
		e.enforceEgressFlowCap(state)
		flow = &model.EgressFlowBuffer{
			PID:         ev.PID,
			Destination: dest,
		}
		state.EgressFlows[key] = flow
	}

	// Slow-trickle boundary: if the flow sat idle longer than the window,
	// restart accumulation for this destination.
	maxAge := e.egressFragmentMaxAge
	if maxAge <= 0 {
		maxAge = defaultEgressFragmentAge
	}
	if flow.LastAppendNS > 0 && now-flow.LastAppendNS > maxAge.Nanoseconds() {
		flow.Chunks = nil
	}
	flow.LastAppendNS = now

	maxBytes := e.egressFragmentMaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultEgressFragmentBytes
	}
	maxChunks := e.egressFragmentMaxChunks
	if maxChunks <= 0 {
		maxChunks = defaultEgressFragmentChunks
	}

	if len(fragment) > maxBytes {
		fragment = fragment[len(fragment)-maxBytes:]
	}
	flow.Chunks = append(flow.Chunks, fragment)
	for len(flow.Chunks) > maxChunks || fragmentBytes(flow.Chunks) > maxBytes {
		if len(flow.Chunks) == 0 {
			break
		}
		flow.Chunks = flow.Chunks[1:]
	}

	return strings.Join(flow.Chunks, "")
}

func (e *Engine) pruneEgressFlows(state *model.SessionState, now int64) {
	if len(state.EgressFlows) == 0 {
		return
	}
	maxAge := e.egressFragmentMaxAge
	if maxAge <= 0 {
		maxAge = defaultEgressFragmentAge
	}
	cutoff := now - maxAge.Nanoseconds()
	for k, flow := range state.EgressFlows {
		if flow == nil || flow.LastAppendNS < cutoff {
			delete(state.EgressFlows, k)
		}
	}
}

func (e *Engine) enforceEgressFlowCap(state *model.SessionState) {
	maxFlows := e.egressMaxFlows
	if maxFlows <= 0 {
		maxFlows = defaultEgressMaxFlows
	}
	if len(state.EgressFlows) < maxFlows {
		return
	}
	var oldestKey string
	oldest := int64(1<<63 - 1)
	for k, flow := range state.EgressFlows {
		ts := int64(0)
		if flow != nil {
			ts = flow.LastAppendNS
		}
		if ts < oldest {
			oldest = ts
			oldestKey = k
		}
	}
	if oldestKey != "" {
		delete(state.EgressFlows, oldestKey)
	}
}

func (e *Engine) egressFlowKey(ev model.SyscallEvent) (key string, destination string) {
	destination = fmt.Sprintf("%s:%d", ev.DestIP, ev.DestPort)
	if ev.DestIP == "" && ev.DestPort == 0 {
		destination = ev.Syscall
	}
	key = fmt.Sprintf("%d|%s", ev.PID, destination)
	return key, destination
}

func (e *Engine) egressEventTime(ev model.SyscallEvent) int64 {
	if ev.TSMono > 0 {
		return ev.TSMono
	}
	return time.Now().UnixNano()
}

// attachChunksAll precomputes long-secret chunks for each tainted value using
// the engine's configured chunk size / min-length thresholds.
func (e *Engine) attachChunksAll(values []model.TaintedValue) {
	n := e.chunkMatchBytes
	minLen := e.chunkMatchMinLen
	if n <= 0 {
		n = defaultChunkMatchBytes
	}
	if minLen <= 0 {
		minLen = defaultChunkMatchMinLen
	}
	for i := range values {
		if len(values[i].Chunks) == 0 {
			AttachChunks(&values[i], n, minLen)
		}
	}
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
