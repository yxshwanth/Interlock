// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"strings"
	"testing"
)

func TestShannonEntropy_Empty(t *testing.T) {
	if ShannonEntropy(nil) != 0 || ShannonEntropy([]byte{}) != 0 {
		t.Fatal("empty must be 0")
	}
}

func TestShannonEntropy_UniformLow(t *testing.T) {
	h := ShannonEntropy([]byte("aaaaaaaa"))
	if h != 0 {
		t.Fatalf("identical bytes: got %v want 0", h)
	}
}

func TestShannonEntropy_TwoSymbols(t *testing.T) {
	h := ShannonEntropy([]byte("abababab"))
	if h < 0.99 || h > 1.01 {
		t.Fatalf("two equal symbols: got %v want ~1", h)
	}
}

func TestShannonEntropy_HighRandom(t *testing.T) {
	// A fixed permutation of all byte values: entropy is exactly 8 bits, so
	// the check cannot fail on an unlucky random draw.
	buf := make([]byte, 256)
	for i := range buf {
		buf[i] = byte(i*167 + 13)
	}
	h := ShannonEntropy(buf)
	if h < 7.0 {
		t.Fatalf("random buffer entropy %.2f < 7.0", h)
	}
}

func TestEntropyDarkWouldFire(t *testing.T) {
	// One of each byte → maximum entropy for a 256-byte alphabet sample.
	high := make([]byte, 256)
	for i := range high {
		high[i] = byte(i)
	}
	low := []byte(strings.Repeat("a", 64))

	cases := []struct {
		name     string
		sens     bool
		blob     []byte
		miss     bool
		wantFire bool
	}{
		{"no sensitive", false, high, true, false},
		{"overlap hit", true, high, false, false},
		{"short", true, high[:16], true, false},
		{"low entropy", true, low, true, false},
		{"fire", true, high, true, true},
	}
	for _, tc := range cases {
		got := EntropyDarkWouldFire(tc.sens, tc.blob, tc.miss, 32, 7.0)
		if got != tc.wantFire {
			t.Fatalf("%s: got %v want %v (H=%.3f)", tc.name, got, tc.wantFire, ShannonEntropy(tc.blob))
		}
	}
}
