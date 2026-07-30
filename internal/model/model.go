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

// PodContext identifies the Kubernetes pod that owns a monitored process.
// Present on sensor-mode Variant B evidence; omitted for proxy-local demos.
type PodContext struct {
	Namespace string `json:"namespace"`
	PodName   string `json:"pod_name"`
	PodUID    string `json:"pod_uid"`
	NodeName  string `json:"node_name,omitempty"`
}

// SyscallEvent represents a single syscall observation from the eBPF sensor.
type SyscallEvent struct {
	TSMono         int64       `json:"ts_mono_ns"`
	PID            int         `json:"pid"`
	TID            int         `json:"tid"`
	Comm           string      `json:"comm"`
	Syscall        string      `json:"syscall"` // connect | sendto | sendmsg | write | writev | openat | dns | lsm_deny
	DestIP         string      `json:"dest_ip,omitempty"`
	DestPort       int         `json:"dest_port,omitempty"`
	Allowlisted    bool        `json:"allowlisted,omitempty"`
	Path           string      `json:"path,omitempty"`
	PayloadExcerpt string      `json:"payload_excerpt,omitempty"`
	SessionID      string      `json:"session_id,omitempty"`
	CgroupID       uint64      `json:"cgroup_id,omitempty"`
	Pod            *PodContext `json:"pod_context,omitempty"`
	// FileContents is set by sensor-mode userspace after openat (via /proc/<pid>/root).
	// Never persisted on evidence.
	FileContents string `json:"-"`
}

// SecurityAuditEvent records a security-relevant observation outside normal
// JSON-RPC intercept flow (e.g. unattributed eBPF events during PID teardown).
type SecurityAuditEvent struct {
	Kind    string       `json:"kind"`
	Reason  string       `json:"reason"`
	TSWall  time.Time    `json:"ts_wall"`
	Syscall SyscallEvent `json:"syscall,omitempty"`
}

// ShadowEvent records a cross-server tool-name collision at registration time.
// First owner keeps the route; the shadowing server's duplicate is refused.
type ShadowEvent struct {
	ToolName       string `json:"tool_name"`
	OwnerServerID  string `json:"owner_server_id"`
	ShadowServerID string `json:"shadow_server_id"`
	SessionID      string `json:"session_id"`
}

// ---------------------------------------------------------------------------
// Engine state: trifecta state machine
// ---------------------------------------------------------------------------

// Leg represents one leg of the trifecta: a boolean flag plus the event
// that lit it and a human-readable detail string.
type Leg struct {
	Lit         bool   `json:"lit"`
	TriggerSeq  uint64 `json:"trigger_seq,omitempty"`
	Detail      string `json:"detail,omitempty"`
	LitAt       int64  `json:"lit_at_ns,omitempty"` // wall time when lit (for TTL decay)
	EventsAtLit uint64 `json:"-"`                   // session EventCount when lit (for N-call decay)
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

// TaintedVariant is a precomputed canonical encoding of a tainted value.
type TaintedVariant struct {
	Form  string `json:"-"`
	Value string `json:"-"`
}

// TaintedValue tracks a candidate secret extracted from a sensitive_source result.
// The raw Value is held in memory only and is NEVER serialized to JSON.
type TaintedValue struct {
	Value        string           `json:"-"`
	Variants     []TaintedVariant `json:"-"` // precomputed canonical encodings for overlap checks
	Chunks       []TaintedVariant `json:"-"` // contiguous N-byte chunks for long secrets (ROADMAP §8)
	Hash         string           `json:"hash"`
	Preview      string           `json:"preview"`
	Source       string           `json:"source"`
	Seq          uint64           `json:"seq"`
	RegisteredAt int64            `json:"registered_at_ns"`
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
	// EventCount increments on each ingest/evaluate/syscall observation.
	// Used with Leg.EventsAtLit for N-call leg decay.
	EventCount uint64 `json:"-"`
	// UntrustedExcerpts are bounded raw excerpts from non-sensitive tool
	// results, used for SUSPICIOUS content-binding (never persisted on evidence).
	UntrustedExcerpts []string `json:"-"`
	// FragmentChunks is a rolling FIFO of sensitive-source result text used to
	// reassemble secrets split across calls. Raw in memory only — never on evidence.
	FragmentChunks []string `json:"-"`
	// EgressFlows is a per-(pid,destination) rolling payload history used for
	// bounded egress-side reassembly before overlap checks (dns/write splitting).
	// Raw in memory only — never on evidence.
	EgressFlows map[string]*EgressFlowBuffer `json:"-"`
	// Vault maps dummy token → real secret (ROADMAP §10). Memory only; never
	// serialized to evidence. Populated when vault.enabled is on.
	Vault map[string]VaultEntry `json:"-"`
	// PendingSensitiveReadPaths maps server/tool to the path argument from the
	// most recent sensitive-source tools/call request (proxy plane only).
	PendingSensitiveReadPaths map[string]string `json:"-"`
}

// EgressFlowBuffer stores bounded payload fragments for one (pid,destination)
// flow key so overlap can run on concatenated excerpts instead of one syscall.
type EgressFlowBuffer struct {
	PID          int
	Destination  string
	LastAppendNS int64
	Chunks       []string
}

// VaultEntry holds the real secret behind an inert dummy token.
type VaultEntry struct {
	Real  string
	Class string // v1: "extracted"
}

// ---------------------------------------------------------------------------
// Evidence (feeds the viewer)
// ---------------------------------------------------------------------------

// Verdict describes what was concluded — the detection result, independent
// of what enforcement action was taken. Separated from Action so Week 3's
// eBPF containment (kill-on-detect) has a place in the vocabulary.
type Verdict string

const (
	VerdictExfil      Verdict = "EXFIL"      // overlap against registered taint (AllLit not required)
	VerdictSuspicious Verdict = "SUSPICIOUS" // AllLit + content-bind / bare-connect / container-abort
)

// Action describes what was done about a detected trifecta. Verdict says
// "what did we conclude"; Action says "what did we do about it."
type Action string

const (
	// ActionPrevented covers two enforcement paths that both mean "the call
	// never reached its destination": Variant A block mode (proxy never
	// forwards the call), and Variant B's opt-in LSM kernel quarantine
	// (v0.3 Phase 2, Slice 1 — ebpf.lsm_enforce), where a repeat connect()
	// from a PID/cgroup already confirmed EXFIL is denied in-kernel with
	// -EPERM before the socket forms. The *first* EXFIL-carrying packet is
	// never "prevented" this way — see ActionContained.
	ActionPrevented    Action = "prevented"         // Variant A block mode, or Variant B LSM quarantine (repeat attempt)
	ActionAllowed      Action = "allowed_monitor"   // monitor mode: call went through, evidence logged
	ActionContained    Action = "contained_by_kill" // Variant B: child process killed (Week 3); always the outcome for the first EXFIL packet
	ActionDetectedOnly Action = "detected_only"     // detected but no enforcement (e.g. SUSPICIOUS via eBPF, kill too aggressive)
)

// Variant identifies which detection plane caught the attack.
type Variant string

const (
	VariantA Variant = "A_chained_tool"   // caught by proxy hold-before-forward
	VariantB Variant = "B_server_channel" // caught by eBPF sensor
)

// EvidenceRecord is the full forensic record emitted when a trifecta trips.
// ChainSeq / PrevHash / Hash form an append-only hash chain: each record
// includes the hex SHA-256 of the previous one so edit/delete/truncate-mid-
// chain is detectable via cmd/verify-evidence (see architecture.md §8).
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
	Pod          *PodContext    `json:"pod_context,omitempty"`
	ChainSeq     uint64         `json:"chain_seq"` // 0-indexed position in this evidence stream
	PrevHash     string         `json:"prev_hash"` // hex sha256 of previous record (empty when ChainSeq==0)
	Hash         string         `json:"hash"`      // hex sha256 over this record with Hash==""
}

// OverlapHit records a tainted value found in sink arguments or egress payload.
type OverlapHit struct {
	TaintedHash string `json:"tainted_hash"`
	Preview     string `json:"preview"`
	WhereFound  string `json:"where_found"`          // "sink args" | "egress payload"
	MatchForm   string `json:"match_form,omitempty"` // literal | base64 | hex | … | decoded_base64_hex_…
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
	// ForwardArgs, when non-nil, are detokenized tool args the proxy must
	// write to the child after an allowed authorized-sink call (ROADMAP §10).
	// Never set when Allow is false — the real secret must not leave Interlock.
	ForwardArgs json.RawMessage `json:"-"`
}
