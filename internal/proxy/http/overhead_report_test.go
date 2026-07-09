package mcphttp_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	mcphttp "github.com/yxshwanth/Interlock/internal/proxy/http"
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

func TestHTTP_ConcurrentLoad_ReadTicket(t *testing.T) {
	sessions := concurrentSessionCount()
	env := setupBenchEnv(t, benchOpts{
		EngineOn:      true,
		Enforcement:   "block",
		PreferSSE:     true,
		MaxConcurrent: sessions + 2,
	})
	defer env.Cleanup()

	clients := make([]*mcphttp.Client, sessions)
	for i := range clients {
		if i == 0 {
			clients[i] = env.Client
		} else {
			clients[i] = newBenchClient(env, "2025-11-25")
		}
		warmupHTTPSession(t, clients[i])
		if _, err := callReadTicket(clients[i]); err != nil {
			t.Fatalf("warmup read_ticket session %d: %v", i, err)
		}
	}

	n := overheadSampleCount()
	if n < sessions {
		n = sessions
	}
	perSession := n / sessions
	total := perSession * sessions
	samples := make([]time.Duration, total)

	var ready, done sync.WaitGroup
	ready.Add(sessions)
	done.Add(sessions)
	release := make(chan struct{})

	for i, client := range clients {
		go func(idx int, c *mcphttp.Client) {
			defer done.Done()
			ready.Done()
			<-release
			offset := idx * perSession
			for j := 0; j < perSession; j++ {
				res, err := callReadTicket(c)
				if err != nil {
					t.Errorf("session %d iter %d: %v", idx, j, err)
					return
				}
				if !jsonHasResult(res.Body) {
					t.Errorf("session %d iter %d: no result", idx, j)
					return
				}
				samples[offset+j] = res.Duration
			}
		}(i, client)
	}

	ready.Wait()
	close(release)
	done.Wait()

	stats := computeLatencyStats(samples)
	logLatencyStats(t, fmt.Sprintf("HTTP concurrent read_ticket (%d sessions, block, SSE)", sessions), stats)
	t.Logf("concurrent p99 (backend-dominated, multi-session): %s", formatMs(stats.P99))
}
