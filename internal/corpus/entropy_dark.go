package corpus

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/model"
)

// ROADMAP §12 research thresholds — not product config / not alert wiring.
const (
	entropyDarkMinLen     = 32
	entropyDarkMinEntropy = 7.0
)

// EntropyDarkHit is one scenario where the dark signal would have fired.
type EntropyDarkHit struct {
	ID       string
	Category Category
	Entropy  float64
	BlobLen  int
	KnownGap bool
}

// MeasureShannonEntropyDark walks each scenario with a live engine (for taint
// state) and evaluates the §12 signal offline — never changing Decision/Verdict.
// If cfgFn is nil, the shared fp-corpus fixture (testConfig) is used.
func MeasureShannonEntropyDark(scenarios []Scenario, cfgFn func(mode string) *config.Config) (benignHits, gapHits []EntropyDarkHit, benignTotal, gapTotal int) {
	if cfgFn == nil {
		cfgFn = testConfig
	}
	for _, sc := range scenarios {
		hits := measureOneEntropyDark(sc, cfgFn)
		switch sc.Category {
		case Benign:
			benignTotal++
			benignHits = append(benignHits, hits...)
		case Malicious:
			if sc.KnownGap {
				gapTotal++
				gapHits = append(gapHits, hits...)
			}
		}
	}
	return benignHits, gapHits, benignTotal, gapTotal
}

func measureOneEntropyDark(sc Scenario, cfgFn func(mode string) *config.Config) []EntropyDarkHit {
	mode := sc.Enforcement
	if mode == "" {
		mode = "block"
	}
	store := engine.NewSessionStore()
	cfg := cfgFn(mode)
	if sc.VaultEnabled {
		cfg.Vault.Enabled = true
		cfg.Vault.Authorize = sc.VaultAuthorize
	}
	if sc.InheritSinkSuspicion {
		cfg.ServerDefaults.InheritSinkSuspicion = true
		cfg.ServerDefaults.SinkSuspicionAllowlist = sc.SinkSuspicionAllowlist
	}
	if sc.MaxDecodeDepth > 0 {
		cfg.Trifecta.MaxDecodeDepth = sc.MaxDecodeDepth
	}
	tagger := engine.NewTagger(cfg)
	eng := engine.NewEngine(store, tagger, mode, nil)
	eng.Configure(cfg)

	var hits []EntropyDarkHit
	fired := false
	for _, step := range sc.Steps {
		switch step.Kind {
		case StepResult:
			eng.IngestResult(step.Event)
		case StepAdvanceTime:
			eng.RewindLegClocks(step.SessionID, step.AdvanceBy)
		case StepRequest:
			sid := step.Event.SessionID
			state := store.Get(sid)
			blob := []byte(step.Event.ToolArgs)
			if len(blob) == 0 {
				eng.EvaluateRequest(step.Event)
				continue
			}
			if hit := evalEntropyDark(sc, state, blob, true); hit != nil && !fired {
				hits = append(hits, *hit)
				fired = true
			}
			eng.EvaluateRequest(step.Event)
		case StepSyscall:
			sid := step.Syscall.SessionID
			state := store.Get(sid)
			blob := []byte(step.Syscall.PayloadExcerpt)
			if len(blob) == 0 {
				eng.IngestSyscall(step.Syscall)
				continue
			}
			if hit := evalEntropyDark(sc, state, blob, false); hit != nil && !fired {
				hits = append(hits, *hit)
				fired = true
			}
			eng.IngestSyscall(step.Syscall)
		case StepSyscallSensor:
			sid := step.Syscall.SessionID
			state := store.Get(sid)
			blob := []byte(step.Syscall.PayloadExcerpt)
			if len(blob) == 0 {
				eng.IngestSyscallSensor(step.Syscall)
				continue
			}
			if hit := evalEntropyDark(sc, state, blob, false); hit != nil && !fired {
				hits = append(hits, *hit)
				fired = true
			}
			eng.IngestSyscallSensor(step.Syscall)
		}
	}
	return hits
}

func evalEntropyDark(sc Scenario, state *model.SessionState, blob []byte, proxyArgs bool) *EntropyDarkHit {
	if state == nil {
		return nil
	}
	sensitive := state.Legs.SensitiveSourceTouched.Lit || len(state.Tainted) > 0
	var overlap *model.OverlapHit
	if proxyArgs {
		overlap = engine.CheckOverlap(state.Tainted, json.RawMessage(blob))
	} else {
		overlap = engine.CheckOverlapPayload(state.Tainted, string(blob))
	}
	h := engine.ShannonEntropy(blob)
	if !engine.EntropyDarkWouldFire(sensitive, blob, overlap == nil, entropyDarkMinLen, entropyDarkMinEntropy) {
		return nil
	}
	return &EntropyDarkHit{
		ID:       sc.ID,
		Category: sc.Category,
		Entropy:  h,
		BlobLen:  len(blob),
		KnownGap: sc.KnownGap,
	}
}

// EntropyDarkMarkdown renders the §12 measurement section for fp_corpus.md.
func EntropyDarkMarkdown(benignHits, gapHits []EntropyDarkHit, benignTotal, gapTotal int) string {
	var b strings.Builder
	b.WriteString("## ROADMAP §12 — Shannon entropy dark measurement\n\n")
	b.WriteString("Research-only signal: sensitive read already registered, then a sink/egress blob ")
	fmt.Fprintf(&b, "of length ≥ %d with Shannon entropy ≥ %.1f bits/byte, where standard ", entropyDarkMinLen, entropyDarkMinEntropy)
	b.WriteString("`CheckOverlap` / `CheckOverlapPayload` would miss. ")
	b.WriteString("**Not wired** to `classifyTrip`, evidence emit, webhooks, or SIEM — measurement only.\n\n")
	fmt.Fprintf(&b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Thresholds | min_len=%d, min_entropy=%.1f bits/byte |\n", entropyDarkMinLen, entropyDarkMinEntropy)
	rate := 0.0
	if benignTotal > 0 {
		rate = float64(len(benignHits)) / float64(benignTotal)
	}
	fmt.Fprintf(&b, "| Benign would-fire rate | **%s** (%d/%d) |\n", pct(rate), len(benignHits), benignTotal)
	fmt.Fprintf(&b, "| KnownGap malicious would-fire | %d/%d |\n\n", len(gapHits), gapTotal)

	if len(benignHits) > 0 {
		b.WriteString("### Benign scenarios that would fire (dark)\n\n")
		b.WriteString("| Scenario | Entropy (bits/byte) | Blob len |\n|---|---:|---:|\n")
		sort.Slice(benignHits, func(i, j int) bool { return benignHits[i].ID < benignHits[j].ID })
		for _, h := range benignHits {
			fmt.Fprintf(&b, "| `%s` | %.2f | %d |\n", h.ID, h.Entropy, h.BlobLen)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("No benign scenario would fire under these thresholds.\n\n")
	}

	if len(gapHits) > 0 {
		b.WriteString("### KnownGap malicious that would fire (informational)\n\n")
		b.WriteString("| Scenario | Entropy | Blob len |\n|---|---:|---:|\n")
		sort.Slice(gapHits, func(i, j int) bool { return gapHits[i].ID < gapHits[j].ID })
		for _, h := range gapHits {
			fmt.Fprintf(&b, "| `%s` | %.2f | %d |\n", h.ID, h.Entropy, h.BlobLen)
		}
		b.WriteString("\n")
	}

	b.WriteString("**Product call:** ")
	if len(benignHits) > 0 {
		b.WriteString("Benign would-fire rate is non-zero (entropy lights compressed/encrypted/protobuf-like ")
		b.WriteString("and high-entropy binary traffic). Signal **stays dark** — do not graduate to ")
		b.WriteString("`SUSPICIOUS` or `EXFIL`. See [`detection_boundary.md`](detection_boundary.md) / INTERLOCK §17.\n")
	} else {
		b.WriteString("Benign surface is clean under these thresholds; SUSPICIOUS-tier discussion is allowed ")
		b.WriteString("but not implemented in this release (still measurement-only).\n")
	}
	return b.String()
}

