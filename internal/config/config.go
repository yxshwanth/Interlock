package config

import (
	"fmt"
	"os"
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

// Config is the top-level Interlock configuration, loaded from interlock.yaml.
type Config struct {
	Transport        TransportConfig     `yaml:"transport"`
	Sessions         SessionsConfig      `yaml:"sessions"`
	Enforcement      string              `yaml:"enforcement"`
	EgressAllowlist  []string            `yaml:"egress_allowlist"`
	Servers          []ServerConfig      `yaml:"servers"`
	ToolTags         map[string][]string `yaml:"tool_tags"`
	UntrustedOrigins struct {
		ToolResults bool `yaml:"tool_results"`
		WebFetches  bool `yaml:"web_fetches"`
	} `yaml:"untrusted_origins"`
}

// Load reads and parses the YAML config at path, then validates it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
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

	if len(c.Servers) == 0 {
		return fmt.Errorf("at least one server must be defined")
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
