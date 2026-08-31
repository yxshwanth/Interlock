package config

import (
	"fmt"
	"strings"
)

func (c *Config) validateEnforcement() error {
	switch c.Enforcement {
	case "block", "monitor":
	case "":
		c.Enforcement = "block"
	default:
		return fmt.Errorf("enforcement must be \"block\" or \"monitor\", got %q", c.Enforcement)
	}
	return nil
}

func (c *Config) validateTransport() error {
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
		if c.Transport.RateLimitRPS < 0 {
			return fmt.Errorf("transport.rate_limit_rps must be >= 0, got %g", c.Transport.RateLimitRPS)
		}
	}
	if c.Sessions.MaxConcurrent == 0 {
		c.Sessions.MaxConcurrent = 32
	}
	return nil
}

func (c *Config) validateEvidenceSettings() error {
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
	return nil
}

func (c *Config) validateLoggingSettings() error {
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
	return nil
}

func (c *Config) validateObservability() error {
	if c.Observability.Listen == "" {
		return nil
	}
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
	return nil
}

func (c *Config) validateServers(sensorMode bool) error {
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
	if sensorMode {
		return nil
	}
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
	return nil
}
