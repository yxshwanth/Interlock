// SPDX-License-Identifier: Apache-2.0

package corpus

// The corpus lives in data/*.json (see data.go). These accessors are the only
// Go entry points; they read the same files any other implementation reads.

// MaliciousScenarios returns the self-authored attack scenarios (profile fp).
func MaliciousScenarios() []Scenario { return loadScenarios("malicious.json") }

// BenignScenarios returns the self-authored legitimate-workflow scenarios (profile fp).
func BenignScenarios() []Scenario { return loadScenarios("benign.json") }

// CVEScenarios returns the reconstructed, engine-driven CVE corpus (profile cve).
func CVEScenarios() []Scenario { return loadScenarios("cve.json") }

// Fixture configs the two published corpora replay against. cve is kept
// separate from fp so it can never perturb docs/fp_corpus.md's numbers.
var (
	testConfig    = profileConfig("fp")
	cveTestConfig = profileConfig("cve")
)

// RunCVEScenarios replays the CVE corpus against the real engine, for
// callers outside this package (cmd/cve-corpus).
func RunCVEScenarios(scenarios []Scenario) []Result {
	return RunWithConfig(scenarios, cveTestConfig)
}
