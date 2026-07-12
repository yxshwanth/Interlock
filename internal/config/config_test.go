package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestLoadSensorAllowsNoServers(t *testing.T) {
	yaml := `
enforcement: block
egress_allowlist:
  - 10.96.0.1
sensitive_paths:
  - /etc/shadow
`
	cfg, err := LoadSensor(writeTemp(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Servers) != 0 {
		t.Fatalf("servers=%v", cfg.Servers)
	}
	if len(cfg.EgressAllowlist) != 1 {
		t.Fatalf("allowlist=%v", cfg.EgressAllowlist)
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

func TestLoadSessionsConfig(t *testing.T) {
	yaml := `
sessions:
  max_concurrent: 16
  idle_timeout: 5m
servers:
  - id: s1
    command: echo
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sessions.MaxConcurrent != 16 {
		t.Errorf("max_concurrent = %d, want 16", cfg.Sessions.MaxConcurrent)
	}
	if cfg.Sessions.IdleTimeoutDuration() != 5*time.Minute {
		t.Errorf("idle_timeout = %v", cfg.Sessions.IdleTimeoutDuration())
	}
}

func TestLoadEvidenceAndLoggingConfig(t *testing.T) {
	yaml := `
evidence:
  backend: sqlite
  path: /tmp/evidence.db
  max_records: 500
  backpressure: drop
  queue_size: 64
logging:
  backpressure: drop
  queue_size: 128
servers:
  - id: s1
    command: echo
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Evidence.Backend != "sqlite" {
		t.Errorf("evidence.backend = %q", cfg.Evidence.Backend)
	}
	if cfg.Evidence.MaxRecords != 500 {
		t.Errorf("max_records = %d", cfg.Evidence.MaxRecords)
	}
	if cfg.Evidence.Backpressure != "drop" {
		t.Errorf("evidence.backpressure = %q", cfg.Evidence.Backpressure)
	}
	if cfg.Evidence.QueueSize != 64 {
		t.Errorf("evidence.queue_size = %d", cfg.Evidence.QueueSize)
	}
	if cfg.Logging.Backpressure != "drop" {
		t.Errorf("backpressure = %q", cfg.Logging.Backpressure)
	}
	if cfg.Logging.QueueSize != 128 {
		t.Errorf("queue_size = %d", cfg.Logging.QueueSize)
	}
}

func TestLoadInvalidEvidenceBackend(t *testing.T) {
	yaml := `
evidence:
  backend: postgres
servers:
  - id: s1
    command: echo
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected error for invalid evidence backend")
	}
}

func TestLoadObservabilityConfig(t *testing.T) {
	yaml := `
observability:
  listen: "0.0.0.0:9090"
  metrics_path: /metrics
  health_path: /healthz
servers:
  - id: s1
    command: echo
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Observability.Listen != "0.0.0.0:9090" {
		t.Errorf("listen = %q", cfg.Observability.Listen)
	}
	if cfg.Observability.MetricsPath != "/metrics" {
		t.Errorf("metrics_path = %q", cfg.Observability.MetricsPath)
	}
	if cfg.Observability.HealthPath != "/healthz" {
		t.Errorf("health_path = %q", cfg.Observability.HealthPath)
	}
}

func TestLoadObservabilityDefaults(t *testing.T) {
	yaml := `
observability:
  listen: "127.0.0.1:9090"
servers:
  - id: s1
    command: echo
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Observability.MetricsPath != "/metrics" || cfg.Observability.HealthPath != "/healthz" {
		t.Fatalf("defaults: metrics=%q health=%q", cfg.Observability.MetricsPath, cfg.Observability.HealthPath)
	}
}

func TestLoadObservabilityInvalidPath(t *testing.T) {
	yaml := `
observability:
  listen: "127.0.0.1:9090"
  metrics_path: metrics
servers:
  - id: s1
    command: echo
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected error for metrics_path without leading /")
	}
}

func TestLoadAlertingAndSIEMConfig(t *testing.T) {
	yaml := `
alerting:
  webhook:
    url: https://hooks.example/slack
    format: slack
    min_verdict: EXFIL
    timeout: 3s
siem:
  format: ocsf
  path: /tmp/ocsf.jsonl
  min_verdict: SUSPICIOUS
servers:
  - id: s1
    command: echo
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Alerting.Webhook.Enabled() || cfg.Alerting.Webhook.Format != "slack" {
		t.Fatalf("webhook=%+v", cfg.Alerting.Webhook)
	}
	if cfg.Alerting.Webhook.MinVerdict != "EXFIL" {
		t.Fatalf("min_verdict=%q", cfg.Alerting.Webhook.MinVerdict)
	}
	if !cfg.SIEM.Enabled() || cfg.SIEM.Format != "ocsf" {
		t.Fatalf("siem=%+v", cfg.SIEM)
	}
}

func TestLoadPagerDutyRequiresKey(t *testing.T) {
	yaml := `
alerting:
  webhook:
    url: https://events.pagerduty.com/v2/enqueue
    format: pagerduty
servers:
  - id: s1
    command: echo
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected error for missing pagerduty_routing_key")
	}
}

func TestLoadSIEMInvalidFormat(t *testing.T) {
	yaml := `
siem:
  format: cef
  path: /tmp/x
servers:
  - id: s1
    command: echo
`
	_, err := Load(writeTemp(t, yaml))
	if err == nil {
		t.Fatal("expected error for cef")
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/interlock.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestTrifectaDefaults(t *testing.T) {
	yaml := `
enforcement: block
servers:
  - id: tickets
    command: ./servers/tickets
tool_tags:
  read_ticket: [sensitive_source]
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Trifecta.LegTTLDuration() != 30*time.Minute {
		t.Errorf("default leg_ttl = %v", cfg.Trifecta.LegTTLDuration())
	}
	if cfg.Trifecta.DecayAfterCallsOrDefault() != 32 {
		t.Errorf("default decay_after_calls = %d", cfg.Trifecta.DecayAfterCallsOrDefault())
	}
	if cfg.Trifecta.ContentBindMinLenOrDefault() != 16 {
		t.Errorf("default content_bind_min_len = %d", cfg.Trifecta.ContentBindMinLenOrDefault())
	}
	if cfg.Trifecta.FragmentMaxChunksOrDefault() != 16 {
		t.Errorf("default fragment_max_chunks = %d", cfg.Trifecta.FragmentMaxChunksOrDefault())
	}
	if cfg.Trifecta.FragmentMaxBytesOrDefault() != 64*1024 {
		t.Errorf("default fragment_max_bytes = %d", cfg.Trifecta.FragmentMaxBytesOrDefault())
	}
}

func TestTrifectaCustom(t *testing.T) {
	yaml := `
enforcement: block
trifecta:
  leg_ttl: 5m
  decay_after_calls: 8
  content_bind_min_len: 24
servers:
  - id: tickets
    command: ./servers/tickets
tool_tags:
  read_ticket: [sensitive_source]
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Trifecta.LegTTLDuration() != 5*time.Minute {
		t.Errorf("leg_ttl = %v", cfg.Trifecta.LegTTLDuration())
	}
	if cfg.Trifecta.DecayAfterCallsOrDefault() != 8 {
		t.Errorf("decay_after_calls = %d", cfg.Trifecta.DecayAfterCallsOrDefault())
	}
	if cfg.Trifecta.ContentBindMinLenOrDefault() != 24 {
		t.Errorf("content_bind_min_len = %d", cfg.Trifecta.ContentBindMinLenOrDefault())
	}
}
