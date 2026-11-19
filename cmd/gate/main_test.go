// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestCheckBench(t *testing.T) {
	const name = "BenchmarkScale/10000"
	tests := []struct {
		name       string
		output     string
		wantFailed bool
	}{
		{
			name: "one sample over budget",
			output: "BenchmarkScale/10000-8 100 120 ns/op\n" +
				"BenchmarkScale/10000-8 100 80 ns/op\n" +
				"BenchmarkScale/10000-8 100 90 ns/op\n",
		},
		{
			name: "all samples over budget",
			output: "BenchmarkScale/10000-8 100 120 ns/op\n" +
				"BenchmarkScale/10000-8 100 110 ns/op\n" +
				"BenchmarkScale/10000-8 100 130 ns/op\n",
			wantFailed: true,
		},
		{
			name:       "missing benchmark",
			output:     "BenchmarkScale/1000-8 100 80 ns/op\n",
			wantFailed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "bench.txt")
			if err := os.WriteFile(file, []byte(tt.output), 0600); err != nil {
				t.Fatal(err)
			}

			previous := failed
			t.Cleanup(func() { failed = previous })
			failed = false
			checkBench(file, map[string]float64{name: 100}, regexp.MustCompile(""))
			if failed != tt.wantFailed {
				t.Errorf("failed = %t, want %t", failed, tt.wantFailed)
			}
		})
	}
}
