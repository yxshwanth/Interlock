// Package corpus drives the trifecta engine directly (no MCP proxy, no
// kernel) through a catalog of malicious and benign scenarios, and scores
// the results into a confusion matrix. See docs/fp_corpus.md for the
// published detection-rate / false-positive-rate report generated from
// this package.
package corpus

import (
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

// Category labels whether a scenario represents an actual attack or a
// legitimate (non-exfiltrating) agent workflow.
type Category string

const (
	Malicious Category = "malicious"
	Benign    Category = "benign"
)

// Variant identifies which detection plane a scenario exercises.
type Variant string

const (
	VariantProxyA  Variant = "proxy_variant_a"  // internal/engine EvaluateRequest / IngestResult
	VariantEbpfB   Variant = "ebpf_variant_b"   // IngestSyscall (proxy + eBPF, hostPID-attributed)
	VariantSensorB Variant = "sensor_variant_b" // IngestSyscallSensor (v0.3 Phase 1 sensor-only)
)

// StepKind selects which engine method a Step drives.
type StepKind string

const (
	StepResult        StepKind = "result"         // engine.IngestResult
	StepRequest       StepKind = "request"        // engine.EvaluateRequest
	StepSyscall       StepKind = "syscall"        // engine.IngestSyscall
	StepSyscallSensor StepKind = "syscall_sensor" // engine.IngestSyscallSensor
	// StepAdvanceTime rewinds LitAt on lit legs for the step's session so the
	// next ingest/evaluate observes TTL expiry (corpus-only time control).
	StepAdvanceTime StepKind = "advance_time"
)

// Step is one engine call in a scenario's replay sequence.
type Step struct {
	Kind      StepKind
	Event     model.InterceptedEvent // used when Kind is StepResult or StepRequest
	Syscall   model.SyscallEvent     // used when Kind is StepSyscall or StepSyscallSensor
	SessionID string                 // used when Kind is StepAdvanceTime
	AdvanceBy time.Duration          // used when Kind is StepAdvanceTime (rewind LitAt by this amount)
}

// Scenario is one corpus case: labeled engine replay steps plus ground-truth category.
// TrippedAny vs TrippedExfil are scored separately (see runner.go and docs/fp_corpus.md).
type Scenario struct {
	// Unique id, convention: "<category>_<variant>_<short-name>".
	ID          string
	Description string
	Category    Category
	Variant     Variant
	Enforcement string // "block" or "monitor"; defaults to "block" if empty

	// KnownGap: malicious scenario expected to miss EXFIL-tier proof under current scope.
	KnownGap bool
	// GapNote names the corresponding *_KnownGap unit test when one exists.
	GapNote string

	// PreExistingGap: KnownGap scenario landing on a gap already in architecture.md.
	PreExistingGap bool

	// ExpectTripByDesign: benign scenario expected to trip SUSPICIOUS by current design.
	ExpectTripByDesign bool
	// DesignNote explains why ExpectTripByDesign is true.
	DesignNote string

	// CVERef, when non-nil, marks this scenario as reconstructed from a
	// specific published, third-party-disclosed CVE (see
	// internal/corpus/scenarios_cve.go and docs/cve_corpus.md) rather than
	// self-authored. Nil on every scenario in scenarios_malicious.go /
	// scenarios_benign.go.
	CVERef *CVERef

	// VaultEnabled opts this scenario into token vaulting (ROADMAP §10).
	// When true, the runner sets vault.enabled on the fixture config.
	VaultEnabled bool
	// VaultAuthorize lists sink tools that may receive detokenized secrets.
	// Empty with VaultEnabled means no-detokenization-by-default.
	VaultAuthorize []config.VaultAuthorizeEntry

	// InheritSinkSuspicion opts this scenario into ROADMAP §14 tagging.
	InheritSinkSuspicion bool
	// SinkSuspicionAllowlist tools that must not inherit when InheritSinkSuspicion is on.
	SinkSuspicionAllowlist []string

	// MaxDecodeDepth, when > 0, sets trifecta.max_decode_depth for this scenario
	// (ROADMAP §15). Zero means use the engine default (3).
	MaxDecodeDepth int

	Steps []Step
}

// CVERef cites the real-world disclosure a scenario reconstructs, so the
// published report can link each scenario back to its source rather than
// asserting "this is what CVE-X looked like" from memory.
type CVERef struct {
	ID        string // e.g. "CVE-2025-68143"
	Source    string // canonical disclosure/writeup URL
	RealWorld string // one-line description of the actual exploited product/mechanism
}
