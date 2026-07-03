package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig describes a single MCP server that Interlock proxies.
type ServerConfig struct {
	ID           string   `yaml:"id"`
	Command      string   `yaml:"command"`
	Args         []string `yaml:"args,omitempty"`
	ProvidesTags []string `yaml:"provides_tags,omitempty"`
}

// Config is the top-level Interlock configuration, loaded from interlock.yaml.
type Config struct {
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
