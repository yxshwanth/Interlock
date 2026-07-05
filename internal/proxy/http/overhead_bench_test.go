package mcphttp_test

import (
	"testing"
)

func BenchmarkHTTP_EngineDelta_ReadTicket(b *testing.B) {
	for _, tc := range []struct {
		name     string
		engineOn bool
	}{
		{"EngineOn", true},
		{"Passthrough", false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			env := setupBenchEnv(b, benchOpts{
				EngineOn:    tc.engineOn,
				Enforcement: "block",
				PreferSSE:   true,
			})
			defer env.Cleanup()

			warmupHTTPSession(b, env.Client)
			if _, err := callReadTicket(env.Client); err != nil {
				b.Fatalf("warmup read_ticket: %v", err)
			}

			b.ResetTimer()
			for b.Loop() {
				res, err := callReadTicket(env.Client)
				if err != nil {
					b.Fatal(err)
				}
				if !jsonHasResult(res.Body) {
					b.Fatal("no result")
				}
			}
		})
	}
}

func BenchmarkHTTP_EngineDelta_MonitorSinkBenign(b *testing.B) {
	for _, tc := range []struct {
		name     string
		engineOn bool
	}{
		{"EngineOn", true},
		{"Passthrough", false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			env := setupBenchEnv(b, benchOpts{
				EngineOn:    tc.engineOn,
				Enforcement: "monitor",
				PreferSSE:   true,
			})
			defer env.Cleanup()

			warmupHTTPSession(b, env.Client)
			if _, err := callReadTicket(env.Client); err != nil {
				b.Fatalf("warmup read_ticket: %v", err)
			}
			if res, err := callSendMessageBenign(env.Client); err != nil {
				b.Fatalf("warmup send_message: %v", err)
			} else if !jsonHasResult(res.Body) {
				b.Fatalf("warmup send_message: no result")
			}

			b.ResetTimer()
			for b.Loop() {
				res, err := callSendMessageBenign(env.Client)
				if err != nil {
					b.Fatal(err)
				}
				if !jsonHasResult(res.Body) {
					b.Fatal("no result")
				}
			}
		})
	}
}
