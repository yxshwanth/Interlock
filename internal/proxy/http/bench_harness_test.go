package mcphttp_test

import (
	"context"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/proxy"
	mcphttp "github.com/yxshwanth/Interlock/internal/proxy/http"
)

// benchOpts configures the HTTP overhead benchmark harness.
type benchOpts struct {
	EngineOn    bool
	Enforcement string // "block" | "monitor"
	PreferSSE   bool
}

type benchEnv struct {
	Client  *mcphttp.Client
	Cancel  context.CancelFunc
	Cleanup func()
}

func requireBenchPrereqs(tb testing.TB) (ticketsBin, messengerBin string) {
	tb.Helper()
	if testing.Short() {
		tb.Skip("skipping HTTP overhead bench in -short mode")
	}
	root := findProjectRoot(tb)
	ticketsBin = filepath.Join(root, "servers/tickets/tickets")
	messengerBin = filepath.Join(root, "servers/messenger/messenger")
	if _, err := os.Stat(ticketsBin); err != nil {
		tb.Skip("server binaries not built; run make build")
	}
	if _, err := os.Stat(messengerBin); err != nil {
		tb.Skip("server binaries not built; run make build")
	}
	return ticketsBin, messengerBin
}

func benchConfig(ticketsBin, messengerBin string, opts benchOpts) *config.Config {
	return &config.Config{
		Transport: config.TransportConfig{
			Mode:               "http",
			Endpoint:           "/mcp",
			ProtocolVersion:    "2025-11-25",
			PreferSSEResponses: opts.PreferSSE,
		},
		Enforcement: opts.Enforcement,
		Servers: []config.ServerConfig{
			{ID: "tickets", Command: ticketsBin, ProvidesTags: []string{"sensitive_source"}},
			{ID: "messenger", Command: messengerBin, ProvidesTags: []string{"external_sink"}},
		},
		ToolTags: map[string][]string{
			"read_ticket":  {"sensitive_source"},
			"send_message": {"external_sink"},
		},
		UntrustedOrigins: struct {
			ToolResults bool `yaml:"tool_results"`
			WebFetches  bool `yaml:"web_fetches"`
		}{ToolResults: true},
	}
}

func setupBenchEnv(tb testing.TB, opts benchOpts) *benchEnv {
	tb.Helper()
	ticketsBin, messengerBin := requireBenchPrereqs(tb)
	cfg := benchConfig(ticketsBin, messengerBin, opts)

	evLogger, err := proxy.NewEventLogger("", config.LoggingConfig{Backpressure: "drop"}, nil)
	if err != nil {
		tb.Fatal(err)
	}

	var eng *engine.Engine
	if opts.EngineOn {
		store := engine.NewSessionStore()
		tagger := engine.NewTagger(cfg)
		eng = engine.NewEngine(store, tagger, cfg.Enforcement, nil)
	}

	p := proxy.New(cfg, evLogger, eng)
	ctx, cancel := context.WithCancel(context.Background())
	if err := p.StartHTTP(ctx); err != nil {
		cancel()
		evLogger.Close()
		tb.Fatal(err)
	}

	logger := log.New(os.Stderr, "[bench] ", 0)
	ts := httptest.NewServer(mcphttp.NewServer(p, cfg, logger).Handler())
	client := mcphttp.NewClient(ts.URL+cfg.Transport.Endpoint, cfg.Transport.ProtocolVersion)

	cleanup := func() {
		ts.Close()
		cancel()
		evLogger.Close()
	}

	return &benchEnv{
		Client:  client,
		Cancel:  cancel,
		Cleanup: cleanup,
	}
}

func warmupHTTPSession(tb testing.TB, client *mcphttp.Client) {
	tb.Helper()
	if _, err := client.Call("initialize", map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "bench", "version": "1.0"},
	}, "initialize"); err != nil {
		tb.Fatalf("initialize: %v", err)
	}
	if client.SessionID() == "" {
		tb.Fatal("expected Mcp-Session-Id after initialize")
	}
	if err := client.Notify("notifications/initialized"); err != nil {
		tb.Fatalf("notifications/initialized: %v", err)
	}
}

func callReadTicket(client *mcphttp.Client) (mcphttp.CallResult, error) {
	return client.CallDuration("tools/call", map[string]any{
		"name":      "read_ticket",
		"arguments": map[string]any{"ticket_id": "T-1234"},
	}, "read_ticket")
}

func callSendMessageBenign(client *mcphttp.Client) (mcphttp.CallResult, error) {
	return client.CallDuration("tools/call", map[string]any{
		"name": "send_message",
		"arguments": map[string]any{
			"to":   "alice@example.com",
			"body": "hello",
		},
	}, "send_message")
}
