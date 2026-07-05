package mcphttp_test

import (
	"testing"
	"time"
)

func TestHTTP_OverheadReport_ReadTicket(t *testing.T) {
	env := setupBenchEnv(t, benchOpts{
		EngineOn:    true,
		Enforcement: "block",
		PreferSSE:   true,
	})
	defer env.Cleanup()

	warmupHTTPSession(t, env.Client)
	// One call before measurement to populate taint/session state.
	if _, err := callReadTicket(env.Client); err != nil {
		t.Fatalf("warmup read_ticket: %v", err)
	}

	n := overheadSampleCount()
	samples := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		res, err := callReadTicket(env.Client)
		if err != nil {
			t.Fatalf("read_ticket iteration %d: %v", i, err)
		}
		if !jsonHasResult(res.Body) {
			t.Fatalf("read_ticket iteration %d: no result", i)
		}
		samples = append(samples, res.Duration)
	}

	stats := computeLatencyStats(samples)
	logLatencyStats(t, "HTTP tools/call read_ticket (block config, benign — no trip; SSE)", stats)
	t.Logf("absolute p99 (mostly backend I/O): %s — use engine delta (C) for Interlock overhead", formatMs(stats.P99))
}

func TestHTTP_OverheadReport_MonitorSinkBenign(t *testing.T) {
	env := setupBenchEnv(t, benchOpts{
		EngineOn:    true,
		Enforcement: "monitor",
		PreferSSE:   true,
	})
	defer env.Cleanup()

	warmupHTTPSession(t, env.Client)
	if _, err := callReadTicket(env.Client); err != nil {
		t.Fatalf("warmup read_ticket: %v", err)
	}
	if res, err := callSendMessageBenign(env.Client); err != nil {
		t.Fatalf("warmup send_message: %v", err)
	} else if !jsonHasResult(res.Body) {
		t.Fatalf("warmup send_message: no result: %s", res.Body)
	}

	n := overheadSampleCount()
	samples := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		res, err := callSendMessageBenign(env.Client)
		if err != nil {
			t.Fatalf("send_message iteration %d: %v", i, err)
		}
		if !jsonHasResult(res.Body) {
			t.Fatalf("send_message iteration %d: no result", i)
		}
		samples = append(samples, res.Duration)
	}

	stats := computeLatencyStats(samples)
	logLatencyStats(t, "HTTP tools/call send_message benign (monitor, full trifecta eval, SSE)", stats)
	t.Logf("full-eval p99: %s (includes monitor-mode evidence emit on trip)", formatMs(stats.P99))
}

func TestHTTP_ConcurrentLoad_KnownGap(t *testing.T) {
	t.Skip("known gap: concurrent multi-session HTTP load p99 — single-session overhead covered by TestHTTP_OverheadReport_*")
}
