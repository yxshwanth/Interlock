package proxy

import (
	"fmt"

	"github.com/yxshwanth/Interlock/internal/config"
)

// SpawnPolicy pins per-server resolved executables and optional extras.
type SpawnPolicy struct {
	Allowed map[string]string // server ID -> resolved executable path
	Extras  []string          // additional resolved paths (sandbox.spawn_allowlist)
}

// ValidateSpawnCommand resolves command and ensures it matches the pinned path
// for serverID or appears in Extras.
func ValidateSpawnCommand(serverID, command string, policy SpawnPolicy) (string, error) {
	resolved, err := config.ResolveSpawnExecutable(command)
	if err != nil {
		return "", fmt.Errorf("server %s: %w", serverID, err)
	}

	if want, ok := policy.Allowed[serverID]; ok && resolved == want {
		return resolved, nil
	}
	for _, extra := range policy.Extras {
		if resolved == extra {
			return resolved, nil
		}
	}
	if want, ok := policy.Allowed[serverID]; ok {
		return "", fmt.Errorf("server %s: executable %q resolves to %q, want pinned %q",
			serverID, command, resolved, want)
	}
	return "", fmt.Errorf("server %s: executable %q not in spawn allowlist", serverID, command)
}
