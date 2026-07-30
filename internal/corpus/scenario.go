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

// Scenario is one corpus case: a labeled sequence of engine calls plus the
// expected ground truth (attack or legitimate).
//
// Two outcome dimensions matter and are scored separately (see runner.go):
//
//   - TrippedAny — any step returned a non-empty Verdict (SUSPICIOUS or
//     EXFIL). This is the OPERATIONAL signal: in block mode this is exactly
//     when a call is refused or a process is killed. SUSPICIOUS trips on
//     its own once all three legs are lit, regardless of whether any
//     secret value actually appears in the sink call/payload — the legs
//     are session-scoped, sticky, and content-blind by design (see
//     architecture.md §7). That means many "sensitive read, then any
//     external call" benign sequences legitimately trip SUSPICIOUS today;
//     the corpus measures this rather than hiding it.
//   - TrippedExfil — a step specifically achieved verdict EXFIL, meaning
//     CheckOverlap/CheckOverlapPayload proved a tainted value appears in
//     the sink args/payload. This is what actually exercises the encoding
//     coverage and is the correct bar for "did detection logic work",
//     independent of the always-on trifecta tripwire.
type Scenario struct {
	// ID must be unique across the corpus; used for report breakdowns and
	// pinning expected outcomes in corpus_test.go. Convention:
	// "<category>_<variant>_<short-name>", e.g. "malicious_proxy_a_base64".
	ID          string
	Description string
	Category    Category
	Variant     Variant
	Enforcement string // "block" or "monitor"; defaults to "block" if empty

	// KnownGap (malicious only) marks a scenario that is EXPECTED to miss
	// EXFIL-tier proof under the current, documented detection scope (e.g.
	// cross-call secret splits, depth-3 encoding nests). It may still trip
	// SUSPICIOUS (TrippedAny) via the sticky trifecta tripwire — that is
	// not the gap being documented. Known-gap misses are excluded from the
	// EXFIL detection-rate denominator so a catalogued gap never
	// masquerades as a regression, and a newly-undetected non-gap
	// scenario still fails the build immediately.
	KnownGap bool
	// GapNote explains why a KnownGap scenario is expected to miss EXFIL
	// proof, and names the corresponding *_KnownGap unit test if one
	// exists in internal/engine.
	GapNote string

	// PreExistingGap (KnownGap scenarios only) marks a miss that was
	// entailed before the scenario ever ran, because it lands on a gap
	// already catalogued in docs/architecture.md (e.g. the depth-4+
	// recursive-decode KnownGap, the container-inspect-bomb KnownGap) rather
	// than one this scenario itself surfaced. This matters for
	// docs/cve_corpus.md: a CVE reconstruction that reproduces a
	// pre-catalogued gap confirms the gap catalogue predicts real-world
	// attack shapes — a real but different claim from a reconstruction
	// that probed open ground and told us something new. Leave false
	// (the default) for a scenario whose miss was not already documented
	// as a KnownGap prior to being authored.
	PreExistingGap bool

	// ExpectTripByDesign (benign only) pins whether this benign scenario is
	// expected to trip SUSPICIOUS (TrippedAny) under the CURRENT trifecta
	// design, even though no exfiltration occurred — e.g. the sticky,
	// content-blind leg-lighting described above, or the sensor
	// connect-only tripwire (architecture.md §5). This distinguishes a
	// known, documented design trade-off from a new, unexpected false
	// positive; either direction of change fails corpus_test.go so a human
	// notices. TrippedExfil is always expected false for benign scenarios
	// — that invariant is not configurable.
	ExpectTripByDesign bool
	// DesignNote explains why ExpectTripByDesign is true, when set.
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
