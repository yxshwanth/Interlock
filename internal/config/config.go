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

// SIEMConfig controls OCSF or CEF export (file and/or HTTP).
// Enabled when Path or URL is non-empty.
type SIEMConfig struct {
	Format     string `yaml:"format"`      // ocsf | cef
	Path       string `yaml:"path"`        // append OCSF JSONL or CEF lines
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

// SandboxConfig controls spawn-time isolation for proxy-mode child MCP servers.
// Defaults are all false (opt-in). Sensor-only / DaemonSet deployments do not
// spawn children and ignore this block.
type SandboxConfig struct {
	// NetNS, when true, places each spawned child in a fresh network namespace
	// (CLONE_NEWNET): loopback-only, no route to the host NIC, no resolver.
	// Requires CAP_SYS_ADMIN (or root) at spawn. Default false.
	NetNS bool `yaml:"netns"`
	// SpawnAllowlist lists additional resolved executables permitted at spawn
	// beyond each server's declared command (e.g. helper binaries).
	SpawnAllowlist []string `yaml:"spawn_allowlist"`
}

// VaultConfig controls opt-in token vaulting (ROADMAP §10): replace extracted
// secrets with inert dummies in agent-visible payloads. Default disabled.
// When enabled, detokenization is off unless a tool appears in Authorize.
type VaultConfig struct {
	Enabled   bool                  `yaml:"enabled"`
	Authorize []VaultAuthorizeEntry `yaml:"authorize"`
}

// VaultAuthorizeEntry names a sink tool that may receive real secrets after
// EvaluateRequest allows the call. SecretClasses lists classes (v1: "extracted"
// or "*") the tool may receive.
type VaultAuthorizeEntry struct {
	Tool          string   `yaml:"tool"`
	SecretClasses []string `yaml:"secret_classes"`
}

// ServerDefaultsConfig controls opt-in tagging inheritance (ROADMAP §14).
// Default InheritSinkSuspicion=false preserves explicit-tag Option C.
type ServerDefaultsConfig struct {
	// InheritSinkSuspicion, when true, treats any tool on a server whose
	// provides_tags include sensitive_source as an external_sink candidate
	// unless the tool is listed in SinkSuspicionAllowlist. Restart-required
	// (tagger is not SIGHUP-rebuilt).
	//
	// Empty tool_tags overrides (e.g. internal_note: []) do NOT exempt a tool —
	// they still inherit. The sole exemption path is SinkSuspicionAllowlist.
	InheritSinkSuspicion   bool     `yaml:"inherit_sink_suspicion"`
	SinkSuspicionAllowlist []string `yaml:"sink_suspicion_allowlist"`
}

// TrifectaConfig controls leg decay and SUSPICIOUS content-binding thresholds.
type TrifectaConfig struct {
	LegTTL            string `yaml:"leg_ttl"`                   // Go duration; default 30m
	DecayAfterCalls   int    `yaml:"decay_after_calls"`         // default 32; 0 keeps default
	ContentBindMinLen int    `yaml:"content_bind_min_len"`      // default 16; 0 keeps default
	FragmentMaxChunks int    `yaml:"fragment_max_chunks"`       // rolling sensitive-text buffer; default 16
	FragmentMaxBytes  int    `yaml:"fragment_max_bytes"`        // total buffer budget; default 65536
	ChunkMatchBytes   int    `yaml:"chunk_match_bytes"`         // long-secret chunk size N; default 32
	ChunkMatchMinLen  int    `yaml:"chunk_match_min_value_len"` // only chunk values ≥ this; default 64
	MaxDecodeDepth    int    `yaml:"max_decode_depth"`          // recursive decoder depth; default 5, clamp [3,5]
	// EgressReassemblyEnabled controls bounded payload reassembly on the eBPF
	// egress path (write/writev/sendto/sendmsg/dns) before overlap checks.
	// Default true; set false to disable and return to per-syscall excerpts only.
	EgressReassemblyEnabled *bool `yaml:"egress_reassembly_enabled"`
	// EgressFragmentMaxChunks is the per-(pid,destination) FIFO chunk cap.
	// Default 16.
	EgressFragmentMaxChunks int `yaml:"egress_fragment_max_chunks"`
	// EgressFragmentMaxBytes is the per-(pid,destination) byte budget for
	// reassembled payload history. Default 4096 bytes.
	EgressFragmentMaxBytes int `yaml:"egress_fragment_max_bytes"`
	// EgressFragmentMaxAge bounds how long fragments may accumulate for one
	// flow before reset (slow-trickle boundary). Default 10s.
	EgressFragmentMaxAge string `yaml:"egress_fragment_max_age"`
	// EgressMaxDestinationsPerSession bounds active (pid,destination) reassembly
	// flows retained per session. Default 32.
	EgressMaxDestinationsPerSession int `yaml:"egress_max_destinations_per_session"`
	// ContainerInspectEnabled controls bounded ZIP/gzip/zlib/tar descent on
	// registration and overlap paths (ROADMAP §20). Default true.
	ContainerInspectEnabled *bool `yaml:"container_inspect_enabled"`
	// ContainerMaxDecompressedBytes is the cumulative decompressed budget
	// per InspectContainer walk. Default 10 MiB.
	ContainerMaxDecompressedBytes int `yaml:"container_max_decompressed_bytes"`
	// ContainerMaxDescentDepth caps nested container walks. Default 2.
	ContainerMaxDescentDepth int `yaml:"container_max_descent_depth"`
	// ContainerMaxParts caps archive members walked. Default 100.
	ContainerMaxParts int `yaml:"container_max_parts"`
	// ContainerMaxInspectMs is the wall-time budget per walk. Default 50ms.
	ContainerMaxInspectMs int `yaml:"container_max_inspect_ms"`
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

// ChunkMatchBytesOrDefault returns the contiguous chunk size N (default 32).
func (t TrifectaConfig) ChunkMatchBytesOrDefault() int {
	if t.ChunkMatchBytes <= 0 {
		return 32
	}
	return t.ChunkMatchBytes
}

// ChunkMatchMinLenOrDefault returns the minimum tainted-value length before
// chunk precomputation (default 64). Short tokens stay full-string-only so
// partial prefixes do not EXFIL.
func (t TrifectaConfig) ChunkMatchMinLenOrDefault() int {
	if t.ChunkMatchMinLen <= 0 {
		return 64
	}
	return t.ChunkMatchMinLen
}

// MaxDecodeDepthOrDefault returns the recursive decoder depth budget
// (default 5, clamped to [3, 5] — ROADMAP §15). Default was raised from 3→5
// after the benign corpus showed EXFIL FP 0.0% at depths 3/4/5 (latency flat).
func (t TrifectaConfig) MaxDecodeDepthOrDefault() int {
	return ClampMaxDecodeDepth(t.MaxDecodeDepth)
}

// EgressReassemblyEnabledOrDefault returns whether egress flow reassembly is
// enabled (default true).
func (t TrifectaConfig) EgressReassemblyEnabledOrDefault() bool {
	if t.EgressReassemblyEnabled == nil {
		return true
	}
	return *t.EgressReassemblyEnabled
}

// EgressFragmentMaxChunksOrDefault returns per-flow chunk cap (default 16).
func (t TrifectaConfig) EgressFragmentMaxChunksOrDefault() int {
	if t.EgressFragmentMaxChunks <= 0 {
		return 16
	}
	return t.EgressFragmentMaxChunks
}

// EgressFragmentMaxBytesOrDefault returns per-flow byte budget (default 4096).
func (t TrifectaConfig) EgressFragmentMaxBytesOrDefault() int {
	if t.EgressFragmentMaxBytes <= 0 {
		return 4 * 1024
	}
	return t.EgressFragmentMaxBytes
}

// EgressFragmentMaxAgeOrDefault returns max fragment window age (default 10s).
func (t TrifectaConfig) EgressFragmentMaxAgeOrDefault() time.Duration {
	return parsePositiveDuration(t.EgressFragmentMaxAge, 10*time.Second)
}

// EgressMaxDestinationsOrDefault returns active flow cap per session (default 32).
func (t TrifectaConfig) EgressMaxDestinationsOrDefault() int {
	if t.EgressMaxDestinationsPerSession <= 0 {
		return 32
	}
	return t.EgressMaxDestinationsPerSession
}

// ContainerInspectEnabledOrDefault returns whether container descent is on (default true).
func (t TrifectaConfig) ContainerInspectEnabledOrDefault() bool {
	if t.ContainerInspectEnabled == nil {
		return true
	}
	return *t.ContainerInspectEnabled
}

// ContainerMaxDecompressedBytesOrDefault returns cumulative decompress budget (default 10 MiB).
func (t TrifectaConfig) ContainerMaxDecompressedBytesOrDefault() int {
	if t.ContainerMaxDecompressedBytes <= 0 {
		return 10 * 1024 * 1024
	}
	return t.ContainerMaxDecompressedBytes
}

// ContainerMaxDescentDepthOrDefault returns nested container depth cap (default 2).
func (t TrifectaConfig) ContainerMaxDescentDepthOrDefault() int {
	if t.ContainerMaxDescentDepth <= 0 {
		return 2
	}
	return t.ContainerMaxDescentDepth
}

// ContainerMaxPartsOrDefault returns archive member walk cap (default 100).
func (t TrifectaConfig) ContainerMaxPartsOrDefault() int {
	if t.ContainerMaxParts <= 0 {
		return 100
	}
	return t.ContainerMaxParts
}

// ContainerMaxInspectMsOrDefault returns per-walk wall budget in ms (default 50).
func (t TrifectaConfig) ContainerMaxInspectMsOrDefault() int {
	if t.ContainerMaxInspectMs <= 0 {
		return 50
	}
	return t.ContainerMaxInspectMs
}

// DefaultMaxDecodeDepth is the recursive decoder default (ROADMAP §15).
// Chosen by EXFIL-FP curve (0% at 3/4/5), not latency — see
// TestCorpus_DecodeDepthFPCurve.
const DefaultMaxDecodeDepth = 5

// minMaxDecodeDepth is the lowest operator-selectable budget (reduce from default).
const minMaxDecodeDepth = 3

// ClampMaxDecodeDepth clamps n into [3, 5]. Zero / negative → default 5.
func ClampMaxDecodeDepth(n int) int {
	if n <= 0 {
		return DefaultMaxDecodeDepth
	}
	if n < minMaxDecodeDepth {
		return minMaxDecodeDepth
	}
	if n > 5 {
		return 5
	}
	return n
}

// EBPFConfig controls kernel capture knobs for Variant B / sensor mode.
type EBPFConfig struct {
	// PayloadCaptureBytes limits how many bytes of each write/sendto are
	// copied into the ring buffer. Default is 1024 = compiled PAYLOAD_MAX
	// (ROADMAP §16 raised 512→1024), so this knob only reduces capture
	// (ring-buffer pressure on high-throughput nodes). Clamped to [64, 1024];
	// values above PAYLOAD_MAX require rebuilding the BPF object with a
	// higher PAYLOAD_MAX (eBPF stack / verifier limits).
	PayloadCaptureBytes int `yaml:"payload_capture_bytes"`

	// LSMEnforce opts into the kernel-level connect() quarantine hook
	// (v0.3 Phase 2, Slice 1): once the existing write/sendto payload-overlap
	// path confirms EXFIL for a PID/cgroup, any further connect() from it is
	// denied in-kernel with -EPERM. Requires CONFIG_BPF_LSM=y and "bpf"
	// active in /sys/kernel/security/lsm (see deploy/k8s/PRIVILEGE.md);
	// attach failure fails soft with a logged warning. Default false — the
	// existing SIGKILL-on-detect containment is unchanged either way.
	// Required when fail_closed.enabled in sensor mode.
	LSMEnforce bool `yaml:"lsm_enforce"`
}

// PayloadCaptureBytesOrDefault returns the runtime capture window (default 1024).
func (e EBPFConfig) PayloadCaptureBytesOrDefault() int {
	if e.PayloadCaptureBytes <= 0 {
		return 1024
	}
	return e.PayloadCaptureBytes
}

// FailClosedConfig opts into blocking monitored egress when Interlock's own
// health degrades (routine or critical ringbuf drop rate, evidence sink
// failure, engine/sensor panic) instead of fail-open with [SECURITY] warnings.
// Scope is always all currently watched PIDs/cgroups — drop counters are
// severity-class globals, not per-pod. Sensor mode requires ebpf.lsm_enforce
// (kernel -EPERM via quarantine maps).
type FailClosedConfig struct {
	Enabled                      bool    `yaml:"enabled"`
	RingbufDropRateThreshold     float64 `yaml:"ringbuf_drop_rate_threshold"`     // drops/sec; default 50
	RingbufRecoveryRateThreshold float64 `yaml:"ringbuf_recovery_rate_threshold"` // hysteresis low; default 10
	SinkFailureThreshold         int     `yaml:"sink_failure_threshold"`          // consecutive write failures; default 3
	PanicThreshold               int     `yaml:"panic_threshold"`                 // panics to trip; default 1
	MinTripDuration              string  `yaml:"min_trip_duration"`               // default 30s
	RecoveryWindow               string  `yaml:"recovery_window"`                 // default 30s
	BackoffMultiplier            float64 `yaml:"backoff_multiplier"`              // default 2.0
	MaxTripDuration              string  `yaml:"max_trip_duration"`               // default 10m
}

// RingbufDropRateThresholdOrDefault returns the high-water drop rate (default 50/s).
func (f FailClosedConfig) RingbufDropRateThresholdOrDefault() float64 {
	if f.RingbufDropRateThreshold <= 0 {
		return 50
	}
	return f.RingbufDropRateThreshold
}

// RingbufRecoveryRateThresholdOrDefault returns the low-water drop rate (default 10/s).
func (f FailClosedConfig) RingbufRecoveryRateThresholdOrDefault() float64 {
	if f.RingbufRecoveryRateThreshold <= 0 {
		return 10
	}
	return f.RingbufRecoveryRateThreshold
}

// SinkFailureThresholdOrDefault returns consecutive sink failures to trip (default 3).
func (f FailClosedConfig) SinkFailureThresholdOrDefault() int {
	if f.SinkFailureThreshold <= 0 {
		return 3
	}
	return f.SinkFailureThreshold
}

// PanicThresholdOrDefault returns panics required to trip (default 1).
func (f FailClosedConfig) PanicThresholdOrDefault() int {
	if f.PanicThreshold <= 0 {
		return 1
	}
	return f.PanicThreshold
}

// MinTripDurationOrDefault returns the minimum time spent tripped (default 30s).
func (f FailClosedConfig) MinTripDurationOrDefault() time.Duration {
	return parsePositiveDuration(f.MinTripDuration, 30*time.Second)
}

// RecoveryWindowOrDefault returns the sustained-clean window before clear (default 30s).
func (f FailClosedConfig) RecoveryWindowOrDefault() time.Duration {
	return parsePositiveDuration(f.RecoveryWindow, 30*time.Second)
}

// BackoffMultiplierOrDefault returns the re-trip backoff multiplier (default 2.0).
func (f FailClosedConfig) BackoffMultiplierOrDefault() float64 {
	if f.BackoffMultiplier <= 1 {
		return 2.0
	}
	return f.BackoffMultiplier
}

// MaxTripDurationOrDefault returns the backoff ceiling (default 10m).
func (f FailClosedConfig) MaxTripDurationOrDefault() time.Duration {
	return parsePositiveDuration(f.MaxTripDuration, 10*time.Minute)
}

func parsePositiveDuration(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
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
	FailClosed       FailClosedConfig    `yaml:"fail_closed"`
	Enforcement      string              `yaml:"enforcement"`
	Trifecta         TrifectaConfig      `yaml:"trifecta"`
	Sandbox          SandboxConfig       `yaml:"sandbox"`
	Vault            VaultConfig         `yaml:"vault"`
	ServerDefaults   ServerDefaultsConfig `yaml:"server_defaults"`
	TaintBridge      TaintBridgeConfig   `yaml:"taint_bridge"`
	EgressAllowlist  []string            `yaml:"egress_allowlist"`
	SensitivePaths   []string            `yaml:"sensitive_paths"` // openat pathname prefixes; empty = ignore
	Servers               []ServerConfig      `yaml:"servers"`
	ResolvedSpawnCommands map[string]string `yaml:"-"` // server ID -> resolved executable (set at load)
	ResolvedSpawnAllowlist []string         `yaml:"-"` // resolved sandbox.spawn_allowlist
	ToolTags              map[string][]string `yaml:"tool_tags"`
	UntrustedOrigins struct {
		ToolResults bool `yaml:"tool_results"`
		WebFetches  bool `yaml:"web_fetches"`
	} `yaml:"untrusted_origins"`
}

// TaintBridgeConfig configures the node-local Unix-socket proxy↔sensor taint bridge.
// Sensor listens when enabled; proxy dials the same socket_path when enabled.
// When enabled, at least one of allowed_uids / allowed_gids is required (SO_PEERCRED).
type TaintBridgeConfig struct {
	Enabled     bool   `yaml:"enabled"`
	SocketPath  string `yaml:"socket_path"` // default /var/run/interlock/taint.sock
	AllowedUIDs []int  `yaml:"allowed_uids"`
	AllowedGIDs []int  `yaml:"allowed_gids"`
	SocketGID   int    `yaml:"socket_gid"` // optional; chown socket after bind for non-root peers
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
	if err := c.validateFailClosed(sensorMode); err != nil {
		return err
	}
	if err := c.validateTaintBridge(); err != nil {
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

	if !sensorMode {
		resolved, err := c.BuildResolvedSpawnCommands()
		if err != nil {
			return err
		}
		c.ResolvedSpawnCommands = resolved
		extras, err := c.BuildResolvedSpawnExtras()
		if err != nil {
			return err
		}
		c.ResolvedSpawnAllowlist = extras
	}

	return nil
}

func (c *Config) validateFailClosed(sensorMode bool) error {
	if !c.FailClosed.Enabled {
		return nil
	}
	if sensorMode && !c.EBPF.LSMEnforce {
		return fmt.Errorf("fail_closed.enabled in sensor mode requires ebpf.lsm_enforce: true (kernel quarantine is the only deny path for watched egress)")
	}
	hi := c.FailClosed.RingbufDropRateThresholdOrDefault()
	lo := c.FailClosed.RingbufRecoveryRateThresholdOrDefault()
	if lo >= hi {
		return fmt.Errorf("fail_closed.ringbuf_recovery_rate_threshold (%g) must be < ringbuf_drop_rate_threshold (%g)", lo, hi)
	}
	if c.FailClosed.MinTripDuration != "" {
		if _, err := time.ParseDuration(c.FailClosed.MinTripDuration); err != nil {
			return fmt.Errorf("fail_closed.min_trip_duration: %w", err)
		}
	}
	if c.FailClosed.RecoveryWindow != "" {
		if _, err := time.ParseDuration(c.FailClosed.RecoveryWindow); err != nil {
			return fmt.Errorf("fail_closed.recovery_window: %w", err)
		}
	}
	if c.FailClosed.MaxTripDuration != "" {
		if _, err := time.ParseDuration(c.FailClosed.MaxTripDuration); err != nil {
			return fmt.Errorf("fail_closed.max_trip_duration: %w", err)
		}
	}
	return nil
}

func (c *Config) validateTaintBridge() error {
	if !c.TaintBridge.Enabled {
		return nil
	}
	if len(c.TaintBridge.AllowedUIDs) == 0 && len(c.TaintBridge.AllowedGIDs) == 0 {
		return fmt.Errorf("taint_bridge.enabled requires allowed_uids and/or allowed_gids (SO_PEERCRED peer authentication)")
	}
	for _, u := range c.TaintBridge.AllowedUIDs {
		if u < 0 {
			return fmt.Errorf("taint_bridge.allowed_uids entries must be >= 0")
		}
	}
	for _, g := range c.TaintBridge.AllowedGIDs {
		if g < 0 {
			return fmt.Errorf("taint_bridge.allowed_gids entries must be >= 0")
		}
	}
	if c.TaintBridge.SocketGID < 0 {
		return fmt.Errorf("taint_bridge.socket_gid must be >= 0")
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
	case "cef":
		s.Format = "cef"
	default:
		return fmt.Errorf("siem.format must be \"ocsf\" or \"cef\", got %q", s.Format)
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
