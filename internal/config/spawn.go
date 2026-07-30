package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveSpawnExecutable canonicalizes command to an absolute, symlink-resolved
// executable path for spawn-time allowlist checks.
func ResolveSpawnExecutable(command string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("spawn command is empty")
	}
	if strings.Contains(command, "..") {
		return "", fmt.Errorf("spawn command %q contains path traversal", command)
	}
	cleaned := filepath.Clean(command)
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("spawn command %q: %w", command, err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return abs, nil
		}
		return "", fmt.Errorf("spawn command %q: %w", command, err)
	}
	return real, nil
}

// BuildResolvedSpawnCommands maps each server ID to its pinned resolved executable.
func (c *Config) BuildResolvedSpawnCommands() (map[string]string, error) {
	out := make(map[string]string, len(c.Servers))
	for _, s := range c.Servers {
		resolved, err := ResolveSpawnExecutable(s.Command)
		if err != nil {
			return nil, fmt.Errorf("server %q: %w", s.ID, err)
		}
		out[s.ID] = resolved
	}
	return out, nil
}

// ResolvedSpawnExtras returns canonical paths for sandbox.spawn_allowlist entries.
func (c *Config) BuildResolvedSpawnExtras() ([]string, error) {
	if len(c.Sandbox.SpawnAllowlist) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(c.Sandbox.SpawnAllowlist))
	for _, cmd := range c.Sandbox.SpawnAllowlist {
		resolved, err := ResolveSpawnExecutable(cmd)
		if err != nil {
			return nil, fmt.Errorf("sandbox.spawn_allowlist entry %q: %w", cmd, err)
		}
		out = append(out, resolved)
	}
	return out, nil
}
