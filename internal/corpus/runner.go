package corpus

import (
	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/model"
)

// Outcome classifies a scored scenario result. See scenario.go for the
// TrippedAny / TrippedExfil distinction this taxonomy is built on.
type Outcome string

const (
	// Malicious, non-gap.
	OutcomeTruePositive  Outcome = "true_positive"  // EXFIL achieved as expected
	OutcomeFalseNegative Outcome = "false_negative" // EXFIL missed — regression, fails corpus_test.go

	// Malicious, KnownGap.
	OutcomeKnownGapMiss Outcome = "known_gap_miss" // EXFIL missed as expected (documented gap)
	OutcomeBonusCatch   Outcome = "bonus_catch"    // EXFIL achieved unexpectedly — gap closed, good news

	// Benign.
	OutcomeTrueNegative          Outcome = "true_negative"           // never tripped
	OutcomeFalsePositiveTripwire Outcome = "false_positive_tripwire" // SUSPICIOUS tripped, no value overlap
	OutcomeFalsePositiveExfil    Outcome = "false_positive_exfil"    // EXFIL tripped — severe, never expected
)

// Result is the scored outcome of replaying one Scenario against a fresh engine.
type Result struct {
	Scenario     Scenario
	TrippedAny   bool
	TrippedExfil bool
	Verdicts     []model.Verdict // in the order steps produced them
	Outcome      Outcome
}

// testConfig builds the tool-tags/servers config every scenario replays
// against, matching the demo fixture shape (servers/tickets, messenger,
// exfil) used throughout internal/engine's own tests.
func testConfig(mode string) *config.Config {
	return &config.Config{
		Enforcement: mode,
		Servers: []config.ServerConfig{
			{ID: "tickets", Command: "./tickets", ProvidesTags: []string{"sensitive_source"}},
			{ID: "messenger", Command: "./messenger", ProvidesTags: []string{"external_sink"}},
			{ID: "web", Command: "./web", ProvidesTags: []string{}},
		},
		ToolTags: map[string][]string{
			"read_ticket":   {"sensitive_source"},
			"send_message":  {"external_sink"},
			"http_post":     {"external_sink"},
			"fetch_page":    {},
			// Untagged override on the sensitive tickets server — neither
			// sensitive_source nor external_sink (covers intra-server relay gap).
			"internal_note": {},
		},
		UntrustedOrigins: struct {
			ToolResults bool `yaml:"tool_results"`
			WebFetches  bool `yaml:"web_fetches"`
		}{ToolResults: true},
	}
}

// Run replays every scenario against a fresh Engine + SessionStore
// (one session per scenario, no shared state across scenarios) and scores
// the outcome.
func Run(scenarios []Scenario) []Result {
	results := make([]Result, 0, len(scenarios))
	for _, sc := range scenarios {
		results = append(results, runOne(sc))
	}
	return results
}

// All returns the full published corpus (malicious + benign).
func All() []Scenario {
	return append(MaliciousScenarios(), BenignScenarios()...)
}

func runOne(sc Scenario) Result {
	mode := sc.Enforcement
	if mode == "" {
		mode = "block"
	}

	store := engine.NewSessionStore()
	cfg := testConfig(mode)
	tagger := engine.NewTagger(cfg)
	eng := engine.NewEngine(store, tagger, mode, nil)
	eng.Configure(cfg)

	res := Result{Scenario: sc}
	for _, step := range sc.Steps {
		switch step.Kind {
		case StepResult:
			eng.IngestResult(step.Event)
		case StepRequest:
			recordDecision(&res, eng.EvaluateRequest(step.Event))
		case StepSyscall:
			recordDecision(&res, eng.IngestSyscall(step.Syscall))
		case StepSyscallSensor:
			recordDecision(&res, eng.IngestSyscallSensor(step.Syscall))
		case StepAdvanceTime:
			eng.RewindLegClocks(step.SessionID, step.AdvanceBy)
		}
	}

	res.Outcome = classify(res)
	return res
}

func recordDecision(res *Result, dec model.Decision) {
	if dec.Verdict == "" {
		return
	}
	res.TrippedAny = true
	res.Verdicts = append(res.Verdicts, dec.Verdict)
	if dec.Verdict == model.VerdictExfil {
		res.TrippedExfil = true
	}
}

func classify(res Result) Outcome {
	sc := res.Scenario
	switch sc.Category {
	case Malicious:
		if sc.KnownGap {
			if res.TrippedExfil {
				return OutcomeBonusCatch
			}
			return OutcomeKnownGapMiss
		}
		if res.TrippedExfil {
			return OutcomeTruePositive
		}
		return OutcomeFalseNegative
	case Benign:
		if res.TrippedExfil {
			return OutcomeFalsePositiveExfil
		}
		if res.TrippedAny {
			return OutcomeFalsePositiveTripwire
		}
		return OutcomeTrueNegative
	default:
		return ""
	}
}
