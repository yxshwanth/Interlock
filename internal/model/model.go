// Package model defines the shared data types used across Interlock.
// See docs/architecture.md §8 for the full specification.
package model

import (
	"encoding/json"
	"time"
)

// ---------------------------------------------------------------------------
// Plane 1: proxy
// ---------------------------------------------------------------------------

// Direction indicates which way a JSON-RPC frame is traveling.
type Direction string

const (
	AgentToServer Direction = "agent_to_server"
	ServerToAgent Direction = "server_to_agent"
)

// InterceptedEvent is emitted for every JSON-RPC frame the proxy sees.
type InterceptedEvent struct {
	SessionID   string          `json:"session_id"`
	Seq         uint64          `json:"seq"`
	TSWall      time.Time       `json:"ts_wall"`
	TSMono      int64           `json:"ts_mono_ns"`
	Direction   Direction       `json:"direction"`
	Method      string          `json:"jsonrpc_method"`
	ToolName    string          `json:"tool_name,omitempty"`
	ToolArgs    json.RawMessage `json:"tool_args,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	ServerID    string          `json:"server_id"`
	ServerPID   int             `json:"server_pid"`
	Tags        []string        `json:"tags,omitempty"`
	Decision    string          `json:"decision"`
	BlockReason string          `json:"block_reason,omitempty"`
}

// JSONRPCMessage is the generic envelope for parsing any JSON-RPC 2.0 message.
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// IsRequest returns true if this message has a method and an id (a JSON-RPC request).
func (m *JSONRPCMessage) IsRequest() bool {
	return m.Method != "" && len(m.ID) > 0
}

// IsNotification returns true if this message has a method but no id.
func (m *JSONRPCMessage) IsNotification() bool {
	return m.Method != "" && len(m.ID) == 0
}

// IsResponse returns true if this message has no method (it's a response).
func (m *JSONRPCMessage) IsResponse() bool {
	return m.Method == ""
}

// ToolCallParams holds the parsed params for a "tools/call" request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ParseToolCallParams extracts tool name and arguments from a tools/call params blob.
func ParseToolCallParams(params json.RawMessage) (ToolCallParams, error) {
	var tc ToolCallParams
	if err := json.Unmarshal(params, &tc); err != nil {
		return tc, err
	}
	return tc, nil
}

// ---------------------------------------------------------------------------
// Plane 2: kernel (eBPF sensor — Week 3)
// ---------------------------------------------------------------------------

// SyscallEvent represents a single syscall observation from the eBPF sensor.
type SyscallEvent struct {
	TSMono         int64  `json:"ts_mono_ns"`
	PID            int    `json:"pid"`
	TID            int    `json:"tid"`
	Comm           string `json:"comm"`
	Syscall        string `json:"syscall"` // connect | sendto | write | openat | dns
	DestIP         string `json:"dest_ip,omitempty"`
	DestPort       int    `json:"dest_port,omitempty"`
	Allowlisted    bool   `json:"allowlisted,omitempty"`
	Path           string `json:"path,omitempty"`
	PayloadExcerpt string `json:"payload_excerpt,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
}

// SecurityAuditEvent records a security-relevant observation outside normal
// JSON-RPC intercept flow (e.g. unattributed eBPF events during PID teardown).
type SecurityAuditEvent struct {
	Kind    string       `json:"kind"`
	Reason  string       `json:"reason"`
	TSWall  time.Time    `json:"ts_wall"`
	Syscall SyscallEvent `json:"syscall,omitempty"`
}

// ---------------------------------------------------------------------------
// Engine state: trifecta state machine
// ---------------------------------------------------------------------------

// Leg represents one leg of the trifecta: a boolean flag plus the event
// that lit it and a human-readable detail string.
type Leg struct {
	Lit        bool   `json:"lit"`
	TriggerSeq uint64 `json:"trigger_seq,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// TrifectaLegs holds the three legs of the lethal trifecta.
type TrifectaLegs struct {
	SensitiveSourceTouched  Leg `json:"sensitive_source_touched"`
	UntrustedContentPresent Leg `json:"untrusted_content_present"`
	ExternalSinkInvoked     Leg `json:"external_sink_invoked"`
}

// AllLit returns true when all three legs are lit.
func (t *TrifectaLegs) AllLit() bool {
	return t.SensitiveSourceTouched.Lit &&
		t.UntrustedContentPresent.Lit &&
		t.ExternalSinkInvoked.Lit
}

// TaintedValue tracks a candidate secret extracted from a sensitive_source result.
// The raw Value is held in memory only and is NEVER serialized to JSON.
type TaintedValue struct {
	Value        string `json:"-"`
	Hash         string `json:"hash"`
	Preview      string `json:"preview"`
	Source       string `json:"source"`
	Seq          uint64 `json:"seq"`
	RegisteredAt int64  `json:"registered_at_ns"`
}

// Status describes the lifecycle state of a session.
type Status string

const (
	Monitoring Status = "monitoring"
	Tripped    Status = "tripped"
	Terminated Status = "terminated"
)

// SessionState is the per-session trifecta state machine.
type SessionState struct {
	SessionID      string            `json:"session_id"`
	Status         Status            `json:"status"`
	Legs           TrifectaLegs      `json:"legs"`
	Tainted        []TaintedValue    `json:"tainted_values"`
	Confidence     float64           `json:"confidence"`
	Timeline       []uint64          `json:"timeline"`
	TimelineLabels map[uint64]string `json:"-"`
	CreatedAt      int64             `json:"created_at_ns"`
	LastActivity   int64             `json:"last_activity_ns"`
}

// ---------------------------------------------------------------------------
// Evidence (feeds the viewer)
// ---------------------------------------------------------------------------

// Verdict describes what was concluded — the detection result, independent
// of what enforcement action was taken. Separated from Action so Week 3's
// eBPF containment (kill-on-detect) has a place in the vocabulary.
type Verdict string

const (
	VerdictExfil      Verdict = "EXFIL"      // high confidence: all legs + value overlap
	VerdictSuspicious Verdict = "SUSPICIOUS"  // lower confidence: all legs, no overlap
)

// Action describes what was done about a detected trifecta. Verdict says
// "what did we conclude"; Action says "what did we do about it."
type Action string

const (
	ActionPrevented    Action = "prevented"        // Variant A block mode: call never forwarded
	ActionAllowed      Action = "allowed_monitor"   // monitor mode: call went through, evidence logged
	ActionContained    Action = "contained_by_kill" // Variant B: child process killed (Week 3)
	ActionDetectedOnly Action = "detected_only"     // detected but no enforcement (e.g. SUSPICIOUS via eBPF, kill too aggressive)
)

// Variant identifies which detection plane caught the attack.
type Variant string

const (
	VariantA Variant = "A_chained_tool"  // caught by proxy hold-before-forward
	VariantB Variant = "B_server_channel" // caught by eBPF sensor
)

// EvidenceRecord is the full forensic record emitted when a trifecta trips.
type EvidenceRecord struct {
	SessionID    string         `json:"session_id"`
	TripTS       int64          `json:"trip_ts_ns"`
	Verdict      Verdict        `json:"verdict"`
	Action       Action         `json:"action"`
	Variant      Variant        `json:"variant"`
	Confidence   float64        `json:"confidence"`
	Legs         TrifectaLegs   `json:"legs"`
	SinkCall     any            `json:"sink_call"`
	ValueOverlap *OverlapHit    `json:"value_overlap,omitempty"`
	Timeline     []TimelineItem `json:"timeline"`
}

// OverlapHit records a tainted value found in sink arguments or egress payload.
type OverlapHit struct {
	TaintedHash string `json:"tainted_hash"`
	Preview     string `json:"preview"`
	WhereFound  string `json:"where_found"` // "sink args" | "egress payload"
}

// TimelineItem is one entry in the evidence timeline.
// TimelineSeq is an engine-assigned causal ordering — sort on this, not
// ts_mono_ns, because proxy and kernel clocks use different references.
type TimelineItem struct {
	TimelineSeq int    `json:"timeline_seq"`
	TSMono      int64  `json:"ts_mono_ns"`
	Kind        string `json:"kind"` // intercepted | syscall
	Label       string `json:"label"`
	Ref         uint64 `json:"ref,omitempty"`
}

// ---------------------------------------------------------------------------
// Engine interfaces / decision types (architecture.md §11)
// ---------------------------------------------------------------------------

// Decision is the engine's response to a pre-forward evaluation.
type Decision struct {
	Allow    bool            `json:"allow"`
	Verdict  Verdict         `json:"verdict,omitempty"`
	Action   Action          `json:"action,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	Evidence *EvidenceRecord `json:"evidence,omitempty"`
}
