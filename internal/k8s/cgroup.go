// Package k8s implements node-local pod attribution for the sensor-only DaemonSet.
package k8s

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Container ID patterns from /proc/<pid>/cgroup (cri-o, containerd, docker).
var (
	reContainerd = regexp.MustCompile(`(?:cri-containerd-)?([0-9a-f]{64})(?:\.scope)?`)
	reCRIO       = regexp.MustCompile(`crio-([0-9a-f]{64})`)
	reDocker     = regexp.MustCompile(`docker-([0-9a-f]{64})`)
	reGeneric64  = regexp.MustCompile(`(?:^|[^0-9a-f])([0-9a-f]{64})(?:[^0-9a-f]|$)`)
)

// ExtractContainerID parses a container runtime ID from cgroup file contents.
// Returns the 64-hex ID without runtime prefix, or empty if not found.
func ExtractContainerID(cgroupData string) string {
	for _, line := range strings.Split(cgroupData, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// cgroup v1: hierarchy-ID:controller:path
		// cgroup v2: 0::path
		path := line
		if i := strings.LastIndex(line, ":"); i >= 0 {
			path = line[i+1:]
		}
		if id := matchContainerID(path); id != "" {
			return id
		}
	}
	return ""
}

func matchContainerID(path string) string {
	if m := reCRIO.FindStringSubmatch(path); len(m) == 2 {
		return m[1]
	}
	if m := reDocker.FindStringSubmatch(path); len(m) == 2 {
		return m[1]
	}
	if m := reContainerd.FindStringSubmatch(path); len(m) == 2 {
		return m[1]
	}
	// Fallback: any 64-hex token in a kubepods path.
	if strings.Contains(path, "kubepods") || strings.Contains(path, "pod") {
		if m := reGeneric64.FindStringSubmatch(path); len(m) == 2 {
			return m[1]
		}
	}
	return ""
}

// NormalizeContainerID strips runtime scheme prefixes from kubelet status IDs
// (e.g. "containerd://abc..." → "abc...").
func NormalizeContainerID(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	// Some runtimes append .scope or similar; keep leading hex only.
	if m := reGeneric64.FindStringSubmatch(" " + raw + " "); len(m) == 2 {
		return m[1]
	}
	if len(raw) >= 64 {
		return raw[:64]
	}
	return raw
}

// ContainerIDFromPID reads /proc/<pid>/cgroup and extracts a container ID.
func ContainerIDFromPID(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	id := ExtractContainerID(string(data))
	if id == "" {
		return "", fmt.Errorf("no container id in /proc/%d/cgroup", pid)
	}
	return id, nil
}
