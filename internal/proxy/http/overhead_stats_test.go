package mcphttp_test

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"
)

func overheadSampleCount() int {
	if s := os.Getenv("OVERHEAD_SAMPLES"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 10_000
}

func concurrentSessionCount() int {
	if s := os.Getenv("CONCURRENT_SESSIONS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 4
}

type latencyStats struct {
	N    int
	Mean time.Duration
	P50  time.Duration
	P95  time.Duration
	P99  time.Duration
	P999 time.Duration
}

func computeLatencyStats(samples []time.Duration) latencyStats {
	if len(samples) == 0 {
		return latencyStats{}
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var sum time.Duration
	for _, d := range sorted {
		sum += d
	}

	return latencyStats{
		N:    len(sorted),
		Mean: sum / time.Duration(len(sorted)),
		P50:  percentile(sorted, 0.50),
		P95:  percentile(sorted, 0.95),
		P99:  percentile(sorted, 0.99),
		P999: percentile(sorted, 0.999),
	}
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func logLatencyStats(t *testing.T, label string, stats latencyStats) {
	t.Helper()
	t.Logf("%s (n=%d): mean=%s p50=%s p95=%s p99=%s p999=%s",
		label, stats.N,
		stats.Mean, stats.P50, stats.P95, stats.P99, stats.P999)
}

func formatMs(d time.Duration) string {
	return fmt.Sprintf("%.3fms", float64(d)/float64(time.Millisecond))
}
