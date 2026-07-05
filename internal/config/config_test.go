package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "interlock.yaml")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValidConfig(t *testing.T) {
	yaml := `
enforcement: monitor
egress_allowlist:
  - 127.0.0.1
  - api.anthropic.com
servers:
  - id: tickets
    command: ./servers/tickets
    provides_tags: [sensitive_source]
  - id: messenger
    command: ./servers/messenger
    args: ["--port", "8080"]
    provides_tags: [external_sink]
tool_tags:
  read_ticket: [sensitive_source]
  send_message: [external_sink]
untrusted_origins:
  tool_results: true
  web_fetches: true
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Enforcement != "monitor" {
		t.Errorf("enforcement = %q, want %q", cfg.Enforcement, "monitor")
	}
	if len(cfg.EgressAllowlist) != 2 {
		t.Errorf("egress_allowlist len = %d, want 2", len(cfg.EgressAllowlist))
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("servers len = %d, want 2", len(cfg.Servers))
	}
	if cfg.Servers[0].ID != "tickets" {
		t.Errorf("servers[0].id = %q, want %q", cfg.Servers[0].ID, "tickets")
	}
	if cfg.Servers[1].Command != "./servers/messenger" {
		t.Errorf("servers[1].command = %q", cfg.Servers[1].Command)
	}
	if len(cfg.Servers[1].Args) != 2 {
		t.Errorf("servers[1].args len = %d, want 2", len(cfg.Servers[1].Args))
	}
	if len(cfg.Servers[0].ProvidesTags) != 1 || cfg.Servers[0].ProvidesTags[0] != "sensitive_source" {
		t.Errorf("servers[0].provides_tags = %v", cfg.Servers[0].ProvidesTags)
	}
	tags, ok := cfg.ToolTags["read_ticket"]
	if !ok || len(tags) != 1 || tags[0] != "sensitive_source" {
		t.Errorf("tool_tags[read_ticket] = %v", tags)
	}
	if !cfg.UntrustedOrigins.ToolResults {
		t.Error("untrusted_origins.tool_results should be true")
	}
	if !cfg.UntrustedOrigins.WebFetches {
		t.Error("untrusted_origins.web_fetches should be true")
	}
}

func TestLoadDefaultEnforcement(t *testing.T) {
	yaml := `
servers:
  - id: s1
    command: echo
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Enforcement != "block" {
		t.Errorf("default enforcement = %q, want %q", cfg.Enforcement, "block")
	}
}

func TestLoadInvalidEnforcement(t *testing.T) {
	yaml := `
enforcement: banana
servers:
  - id: s1
    command: echo
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected error for invalid enforcement")
	}
}

func TestLoadNoServers(t *testing.T) {
	yaml := `
enforcement: block
servers: []
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected error for empty servers")
	}
}

func TestLoadMissingServerID(t *testing.T) {
	yaml := `
servers:
  - command: echo
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected error for missing server id")
	}
}

func TestLoadMissingServerCommand(t *testing.T) {
	yaml := `
servers:
  - id: s1
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected error for missing server command")
	}
}

func TestLoadDuplicateServerID(t *testing.T) {
	yaml := `
servers:
  - id: s1
    command: echo
  - id: s1
    command: cat
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected error for duplicate server id")
	}
}

func TestLoadHTTPTransport(t *testing.T) {
	yaml := `
transport:
  mode: http
  listen: 127.0.0.1:9090
  endpoint: /mcp
  protocol_version: "2025-11-25"
  prefer_sse_responses: true
enforcement: block
servers:
  - id: s1
    command: echo
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Transport.Mode != "http" {
		t.Errorf("transport.mode = %q, want http", cfg.Transport.Mode)
	}
	if cfg.Transport.Listen != "127.0.0.1:9090" {
		t.Errorf("transport.listen = %q", cfg.Transport.Listen)
	}
	if cfg.Transport.Endpoint != "/mcp" {
		t.Errorf("transport.endpoint = %q", cfg.Transport.Endpoint)
	}
	if cfg.Transport.ProtocolVersion != "2025-11-25" {
		t.Errorf("transport.protocol_version = %q", cfg.Transport.ProtocolVersion)
	}
	if !cfg.Transport.PreferSSEResponses {
		t.Error("prefer_sse_responses should be true")
	}
}

func TestLoadDefaultTransport(t *testing.T) {
	yaml := `
servers:
  - id: s1
    command: echo
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Transport.Mode != "stdio" {
		t.Errorf("default transport.mode = %q, want stdio", cfg.Transport.Mode)
	}
}

func TestLoadInvalidTransport(t *testing.T) {
	yaml := `
transport:
  mode: websocket
servers:
  - id: s1
    command: echo
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected error for invalid transport mode")
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/interlock.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}
