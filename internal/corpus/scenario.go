// Package corpus drives the trifecta engine directly (no MCP proxy, no
// kernel) through a catalog of malicious and benign scenarios, and scores
// the results into a confusion matrix. See docs/fp_corpus.md for the
// published detection-rate / false-positive-rate report generated from
// this package.
package corpus

import (
	"time"

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

	Steps []Step
}
