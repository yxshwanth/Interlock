package corpus

import (
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/engine"
)

// TestCorpus_DecodeDepthFPCurve measures EXFIL-tier and any-trip FP at
// trifecta.max_decode_depth 3/4/5. Decode-miss latency is flat (~380µs);
// DefaultMaxDecodeDepth was raised to 5 because EXFIL FP stayed 0.0% at
// every depth (ROADMAP §15 follow-up — FP picks the default, not latency).
func TestCorpus_DecodeDepthFPCurve(t *testing.T) {
	t.Cleanup(func() { engine.SetMaxDecodeDepth(engine.DefaultMaxDecodeDepth) })

	if engine.DefaultMaxDecodeDepth != 5 {
		t.Fatalf("DefaultMaxDecodeDepth=%d, want 5 (FP-driven raise)", engine.DefaultMaxDecodeDepth)
	}

	const fetchDepth5ID = "cve_2025_65513_fetch_ssrf_cloud_metadata_depth5_nest"

	for _, depth := range []int{3, 4, 5} {
		exfilFP, anyFP, benign, detTP, detDenom, cveExfil := 0, 0, 0, 0, 0, 0
		var exfilIDs []string
		results := RunWithConfig(All(), func(mode string) *config.Config {
			cfg := testConfig(mode)
			cfg.Trifecta.MaxDecodeDepth = depth
			return cfg
		})
		for _, res := range results {
			sc := res.Scenario
			switch sc.Category {
			case Benign:
				benign++
				if res.TrippedAny {
					anyFP++
				}
				if res.TrippedExfil {
					exfilFP++
					exfilIDs = append(exfilIDs, sc.ID)
				}
			case Malicious:
				if !sc.KnownGap {
					detDenom++
					if res.TrippedExfil {
						detTP++
					}
				}
			}
		}
		cve := RunWithConfig(CVEScenarios(), func(mode string) *config.Config {
			cfg := cveTestConfig(mode)
			cfg.Trifecta.MaxDecodeDepth = depth
			return cfg
		})
		for _, res := range cve {
			if res.Scenario.ID == fetchDepth5ID && res.TrippedExfil {
				cveExfil = 1
			}
		}
		t.Logf("depth=%d EXFIL-FP=%d/%d any-trip=%d/%d detection=%d/%d cve_depth5_exfil=%d ids=%v",
			depth, exfilFP, benign, anyFP, benign, detTP, detDenom, cveExfil, exfilIDs)
		if exfilFP != 0 {
			t.Errorf("depth=%d: EXFIL FP %d/%d — default must not sit at this depth; ids=%v",
				depth, exfilFP, benign, exfilIDs)
		}
		if depth == 3 && cveExfil != 0 {
			t.Errorf("depth=3 should miss Fetch depth-5 nest (operator can lower from default)")
		}
		if depth == 5 && cveExfil != 1 {
			t.Errorf("depth=5 must catch Fetch depth-5 nest at default budget")
		}
	}
}
