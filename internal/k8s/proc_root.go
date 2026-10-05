package k8s

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maxSeedFileBytes = 64 * 1024

// ReadContainerFile reads path from a container's rootfs via /proc/<pid>/root.
// nodePIDs must be PIDs visible in the sensor's PID namespace (hostPID DaemonSet).
// Requires hostPID: true and read access to the node's procfs.
//
// path comes verbatim from an eBPF openat event — i.e. from userspace memory
// in a monitored, potentially malicious pod — so it must never be trusted as
// already-safe. It is treated as an absolute path and cleaned before use:
// filepath.Clean on a rooted path collapses any ".." components at or above
// "/" rather than letting them escape (Go's documented rule 4), so a crafted
// "/var/run/secrets/../../../../../etc/shadow" cannot walk the /proc/<pid>/root
// magic-symlink resolution past the container's own rootfs and onto the host.
// A defensive re-check after Clean rejects anything that still isn't rooted.
func ReadContainerFile(nodePIDs []int, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	cleaned := filepath.Clean(path)
	if !strings.HasPrefix(cleaned, "/") || strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("rejected path traversal attempt: %q", path)
	}
	var lastErr error
	for _, pid := range nodePIDs {
		if pid <= 0 {
			continue
		}
		rootPath := fmt.Sprintf("/proc/%d/root%s", pid, cleaned)
		data, err := readFileLimited(rootPath, maxSeedFileBytes)
		if err == nil {
			return string(data), nil
		}
		lastErr = err
	}
	// No blind fallback to reading `cleaned` directly against the sensor's
	// own filesystem: since a monitored pod controls `path`, that fallback
	// previously let it name any host-readable file that merely doesn't
	// exist inside its own container rootfs and have the (often privileged,
	// host-rooted) sensor read it instead — an attacker-steerable read
	// oracle onto the host, independent of any real container mapping.
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("no PID available to resolve container root for %q", cleaned)
}

func readFileLimited(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, max+1)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	if n > max {
		n = max
	}
	return buf[:n], nil
}
