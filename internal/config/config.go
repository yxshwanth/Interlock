package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ServerConfig describes a single MCP server that Interlock proxies.
type ServerConfig struct {
	ID           string   `yaml:"id"`
	Command      string   `yaml:"command"`
	Args         []string `yaml:"args,omitempty"`
	ProvidesTags []string `yaml:"provides_tags,omitempty"`
}

// TransportConfig controls how agents connect to Interlock.
type TransportConfig struct {
	Mode               string `yaml:"mode"` // stdio | http
	Listen             string `yaml:"listen"`
	Endpoint           string `yaml:"endpoint"`
	ProtocolVersion    string `yaml:"protocol_version"`
	PreferSSEResponses bool   `yaml:"prefer_sse_responses"`
}

// SessionsConfig controls multi-session lifecycle.
type SessionsConfig struct {
	MaxConcurrent int    `yaml:"max_concurrent"`
	IdleTimeout   string `yaml:"idle_timeout"` // Go duration string, e.g. "30m"
}

// EvidenceConfig controls forensic evidence persistence.
type EvidenceConfig struct {
	Backend      string `yaml:"backend"`      // jsonl | sqlite (default jsonl)
	Path         string `yaml:"path"`         // evidence.jsonl or evidence.db
	MaxRecords   int    `yaml:"max_records"`  // sqlite retention cap; 0 = unlimited
	Backpressure string `yaml:"backpressure"` // block | drop (default block) — async emit queue
	QueueSize    int    `yaml:"queue_size"`   // async emit bounded queue (default 256)
}

// LoggingConfig controls event log behavior.
type LoggingConfig struct {
	Backpressure string `yaml:"backpressure"` // block | drop (default block)
	QueueSize    int    `yaml:"queue_size"`   // drop mode bounded queue
}

// ObservabilityConfig controls the metrics/health HTTP endpoint.
// Empty Listen disables the server (default).
type ObservabilityConfig struct {
	Listen      string `yaml:"listen"`       // e.g. "0.0.0.0:9090"; empty = disabled
	MetricsPath string `yaml:"metrics_path"` // default /metrics
	HealthPath  string `yaml:"health_path"`  // default /healthz
}

// WebhookConfig controls trip alerting via HTTP webhook.
// Empty URL disables the webhook.
type WebhookConfig struct {
	URL                 string `yaml:"url"`
	Format              string `yaml:"format"`                // generic | slack | pagerduty
	MinVerdict          string `yaml:"min_verdict"`           // SUSPICIOUS | EXFIL
	Timeout             string `yaml:"timeout"`               // Go duration; default 5s
	PagerDutyRoutingKey string `yaml:"pagerduty_routing_key"` // required when format=pagerduty
}

// AlertingConfig groups outbound trip alerts.
type AlertingConfig struct {
	Webhook WebhookConfig `yaml:"webhook"`
}

// SIEMConfig controls OCSF export (file and/or HTTP).
// Enabled when Path or URL is non-empty.
type SIEMConfig struct {
	Format     string `yaml:"format"`      // ocsf (only)
	Path       string `yaml:"path"`        // append OCSF JSONL
	URL        string `yaml:"url"`         // optional HTTP POST
	MinVerdict string `yaml:"min_verdict"` // SUSPICIOUS | EXFIL
	Timeout    string `yaml:"timeout"`     // Go duration; default 5s
}

// TimeoutDuration parses Timeout with a default of 5 seconds.
func (w WebhookConfig) TimeoutDuration() time.Duration {
	return parseTimeout(w.Timeout)
}

// TimeoutDuration parses Timeout with a default of 5 seconds.
func (s SIEMConfig) TimeoutDuration() time.Duration {
	return parseTimeout(s.Timeout)
}

func parseTimeout(s string) time.Duration {
	if s == "" {
		return 5 * time.Second
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 5 * time.Second
	}
	return d
}

// Enabled reports whether the webhook is configured.
func (w WebhookConfig) Enabled() bool {
	return strings.TrimSpace(w.URL) != ""
}

// Enabled reports whether SIEM export is configured.
func (s SIEMConfig) Enabled() bool {
	return strings.TrimSpace(s.Path) != "" || strings.TrimSpace(s.URL) != ""
}

// IdleTimeoutDuration parses IdleTimeout with a default of 30 minutes.
func (s SessionsConfig) IdleTimeoutDuration() time.Duration {
	if s.IdleTimeout == "" {
		return 30 * time.Minute
	}
	d, err := time.ParseDuration(s.IdleTimeout)
	if err != nil {
		return 30 * time.Minute
	}
	return d
}

// TrifectaConfig controls leg decay and SUSPICIOUS content-binding thresholds.
type TrifectaConfig struct {
	LegTTL            string `yaml:"leg_ttl"`              // Go duration; default 30m
	DecayAfterCalls   int    `yaml:"decay_after_calls"`    // default 32; 0 keeps default
	ContentBindMinLen int    `yaml:"content_bind_min_len"` // default 16; 0 keeps default
	FragmentMaxChunks int    `yaml:"fragment_max_chunks"`  // rolling sensitive-text buffer; default 16
	FragmentMaxBytes  int    `yaml:"fragment_max_bytes"`   // total buffer budget; default 65536
}

// LegTTLDuration parses LegTTL with a default of 30 minutes.
func (t TrifectaConfig) LegTTLDuration() time.Duration {
	if t.LegTTL == "" {
		return 30 * time.Minute
	}
	d, err := time.ParseDuration(t.LegTTL)
	if err != nil || d <= 0 {
		return 30 * time.Minute
	}
	return d
}

// DecayAfterCallsOrDefault returns the N-call decay threshold (default 32).
func (t TrifectaConfig) DecayAfterCallsOrDefault() int {
	if t.DecayAfterCalls <= 0 {
		return 32
	}
	return t.DecayAfterCalls
}

// ContentBindMinLenOrDefault returns the minimum shared substring length (default 16).
func (t TrifectaConfig) ContentBindMinLenOrDefault() int {
	if t.ContentBindMinLen <= 0 {
		return 16
	}
	return t.ContentBindMinLen
}

// FragmentMaxChunksOrDefault returns the rolling fragment chunk cap (default 16).
func (t TrifectaConfig) FragmentMaxChunksOrDefault() int {
	if t.FragmentMaxChunks <= 0 {
		return 16
	}
	return t.FragmentMaxChunks
}

// FragmentMaxBytesOrDefault returns the rolling fragment byte budget (default 64 KiB).
func (t TrifectaConfig) FragmentMaxBytesOrDefault() int {
	if t.FragmentMaxBytes <= 0 {
		return 64 * 1024
	}
	return t.FragmentMaxBytes
}

// EBPFConfig controls kernel capture knobs for Variant B / sensor mode.
type EBPFConfig struct {
	// PayloadCaptureBytes limits how many bytes of each write/sendto are
	// copied into the ring buffer (default 512). Clamped to [64, 1024];
	// raising above the compiled PAYLOAD_MAX requires rebuilding the BPF object.
	PayloadCaptureBytes int `yaml:"payload_capture_bytes"`
}

// PayloadCaptureBytesOrDefault returns the runtime capture window (default 512).
func (e EBPFConfig) PayloadCaptureBytesOrDefault() int {
	if e.PayloadCaptureBytes <= 0 {
		return 512
	}
	return e.PayloadCaptureBytes
}

// Config is the top-level Interlock configuration, loaded from interlock.yaml.
type Config struct {
	Transport        TransportConfig     `yaml:"transport"`
	Sessions         SessionsConfig      `yaml:"sessions"`
	Evidence         EvidenceConfig      `yaml:"evidence"`
	Logging          LoggingConfig       `yaml:"logging"`
	Observability    ObservabilityConfig `yaml:"observability"`
	Alerting         AlertingConfig      `yaml:"alerting"`
	SIEM             SIEMConfig          `yaml:"siem"`
	EBPF             EBPFConfig          `yaml:"ebpf"`
	Enforcement      string              `yaml:"enforcement"`
	Trifecta         TrifectaConfig      `yaml:"trifecta"`
	TaintBridge      TaintBridgeConfig   `yaml:"taint_bridge"`
	EgressAllowlist  []string            `yaml:"egress_allowlist"`
	SensitivePaths   []string            `yaml:"sensitive_paths"` // openat pathname prefixes; empty = ignore
	Servers          []ServerConfig      `yaml:"servers"`
	ToolTags         map[string][]string `yaml:"tool_tags"`
	UntrustedOrigins struct {
		ToolResults bool `yaml:"tool_results"`
		WebFetches  bool `yaml:"web_fetches"`
	} `yaml:"untrusted_origins"`
}

// TaintBridgeConfig configures the node-local Unix-socket proxy↔sensor taint bridge.
// Sensor listens when enabled; proxy dials the same socket_path when enabled.
type TaintBridgeConfig struct {
	Enabled    bool   `yaml:"enabled"`
	SocketPath string `yaml:"socket_path"` // default /var/run/interlock/taint.sock
}

// SocketPathOrDefault returns the bridge socket path.
func (c TaintBridgeConfig) SocketPathOrDefault() string {
	if c.SocketPath == "" {
		return "/var/run/interlock/taint.sock"
	}
	return c.SocketPath
}

// Load reads and parses the YAML config at path, then validates it for proxy mode
// (requires at least one MCP server).
func Load(path string) (*Config, error) {
	return load(path, false)
}

// LoadSensor reads and parses the YAML config for sensor-only mode.
// MCP servers may be omitted — the DaemonSet does not run the proxy.
func LoadSensor(path string) (*Config, error) {
	return load(path, true)
}

func load(path string, sensorMode bool) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if err := cfg.validate(sensorMode); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}

	return &cfg, nil
}

func (c *Config) validate(sensorMode bool) error {
	switch c.Enforcement {
	case "block", "monitor":
	case "":
		c.Enforcement = "block"
	default:
		return fmt.Errorf("enforcement must be \"block\" or \"monitor\", got %q", c.Enforcement)
	}

	switch c.Transport.Mode {
	case "", "stdio":
		c.Transport.Mode = "stdio"
	case "http":
	default:
		return fmt.Errorf("transport.mode must be \"stdio\" or \"http\", got %q", c.Transport.Mode)
	}
	if c.Transport.Mode == "http" {
		if c.Transport.Listen == "" {
			c.Transport.Listen = "127.0.0.1:8080"
		}
		if c.Transport.Endpoint == "" {
			c.Transport.Endpoint = "/mcp"
		}
		if c.Transport.ProtocolVersion == "" {
			c.Transport.ProtocolVersion = "2025-11-25"
		}
	}
	if c.Sessions.MaxConcurrent == 0 {
		c.Sessions.MaxConcurrent = 32
	}

	switch c.Evidence.Backend {
	case "", "jsonl":
		c.Evidence.Backend = "jsonl"
	case "sqlite":
	default:
		return fmt.Errorf("evidence.backend must be \"jsonl\" or \"sqlite\", got %q", c.Evidence.Backend)
	}
	if c.Evidence.Path == "" {
		if c.Evidence.Backend == "sqlite" {
			c.Evidence.Path = "evidence.db"
		} else {
			c.Evidence.Path = "evidence.jsonl"
		}
	}
	if c.Evidence.MaxRecords == 0 {
		c.Evidence.MaxRecords = 1000
	}
	switch c.Evidence.Backpressure {
	case "", "block":
		c.Evidence.Backpressure = "block"
	case "drop":
	default:
		return fmt.Errorf("evidence.backpressure must be \"block\" or \"drop\", got %q", c.Evidence.Backpressure)
	}
	if c.Evidence.QueueSize == 0 {
		c.Evidence.QueueSize = 256
	}

	switch c.Logging.Backpressure {
	case "", "block":
		c.Logging.Backpressure = "block"
	case "drop":
	default:
		return fmt.Errorf("logging.backpressure must be \"block\" or \"drop\", got %q", c.Logging.Backpressure)
	}
	if c.Logging.QueueSize == 0 {
		c.Logging.QueueSize = 256
	}

	if c.Observability.Listen != "" {
		if c.Observability.MetricsPath == "" {
			c.Observability.MetricsPath = "/metrics"
		}
		if c.Observability.HealthPath == "" {
			c.Observability.HealthPath = "/healthz"
		}
		if !strings.HasPrefix(c.Observability.MetricsPath, "/") {
			return fmt.Errorf("observability.metrics_path must start with /, got %q", c.Observability.MetricsPath)
		}
		if !strings.HasPrefix(c.Observability.HealthPath, "/") {
			return fmt.Errorf("observability.health_path must start with /, got %q", c.Observability.HealthPath)
		}
	}

	if err := c.validateAlerting(); err != nil {
		return err
	}
	if err := c.validateSIEM(); err != nil {
		return err
	}

	if len(c.Servers) == 0 {
		if !sensorMode {
			return fmt.Errorf("at least one server must be defined")
		}
		return nil
	}

	seen := make(map[string]bool)
	for i, s := range c.Servers {
		if s.ID == "" {
			return fmt.Errorf("server[%d]: id is required", i)
		}
		if s.Command == "" {
			return fmt.Errorf("server[%d] (%s): command is required", i, s.ID)
		}
		if seen[s.ID] {
			return fmt.Errorf("server[%d]: duplicate id %q", i, s.ID)
		}
		seen[s.ID] = true
	}

	return nil
}

func (c *Config) validateAlerting() error {
	w := &c.Alerting.Webhook
	if !w.Enabled() {
		return nil
	}
	switch strings.ToLower(w.Format) {
	case "", "generic":
		w.Format = "generic"
	case "slack", "pagerduty":
		w.Format = strings.ToLower(w.Format)
	default:
		return fmt.Errorf("alerting.webhook.format must be generic, slack, or pagerduty, got %q", w.Format)
	}
	mv, err := normalizeMinVerdict(w.MinVerdict)
	if err != nil {
		return fmt.Errorf("alerting.webhook.min_verdict: %w", err)
	}
	w.MinVerdict = mv
	if w.Format == "pagerduty" && strings.TrimSpace(w.PagerDutyRoutingKey) == "" {
		return fmt.Errorf("alerting.webhook.pagerduty_routing_key is required when format=pagerduty")
	}
	if w.Timeout != "" {
		if _, err := time.ParseDuration(w.Timeout); err != nil {
			return fmt.Errorf("alerting.webhook.timeout: %w", err)
		}
	}
	return nil
}

func (c *Config) validateSIEM() error {
	s := &c.SIEM
	if !s.Enabled() {
		return nil
	}
	switch strings.ToLower(s.Format) {
	case "", "ocsf":
		s.Format = "ocsf"
	default:
		return fmt.Errorf("siem.format must be \"ocsf\", got %q", s.Format)
	}
	mv, err := normalizeMinVerdict(s.MinVerdict)
	if err != nil {
		return fmt.Errorf("siem.min_verdict: %w", err)
	}
	s.MinVerdict = mv
	if s.Timeout != "" {
		if _, err := time.ParseDuration(s.Timeout); err != nil {
			return fmt.Errorf("siem.timeout: %w", err)
		}
	}
	return nil
}

func normalizeMinVerdict(v string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "", "SUSPICIOUS":
		return "SUSPICIOUS", nil
	case "EXFIL":
		return "EXFIL", nil
	default:
		return "", fmt.Errorf("must be SUSPICIOUS or EXFIL, got %q", v)
	}
}
