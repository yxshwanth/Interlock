package engine

import "math"

// ShannonEntropy returns Shannon entropy in bits per byte (0–8) for data.
// Empty input returns 0. Used for ROADMAP §12 dark measurement only —
// never wired to classifyTrip / verdicts / evidence emit.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// EntropyDarkWouldFire is the §12 research signal: sensitive material was
// seen, egress/sink blob is long and high-entropy, and standard overlap
// would miss. Thresholds are research constants — not product config.
func EntropyDarkWouldFire(sensitiveLit bool, blob []byte, overlapMiss bool, minLen int, minEntropy float64) bool {
	if !sensitiveLit || !overlapMiss {
		return false
	}
	if minLen <= 0 {
		minLen = 32
	}
	if minEntropy <= 0 {
		minEntropy = 7.0
	}
	if len(blob) < minLen {
		return false
	}
	return ShannonEntropy(blob) >= minEntropy
}
