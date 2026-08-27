package k8s

import (
	"fmt"
	"os"
	"strings"
)

const maxSeedFileBytes = 64 * 1024

// ReadContainerFile reads path from a container's rootfs via /proc/<pid>/root.
// nodePIDs must be PIDs visible in the sensor's PID namespace (hostPID DaemonSet).
// Requires hostPID: true and read access to the node's procfs.
func ReadContainerFile(nodePIDs []int, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var lastErr error
	for _, pid := range nodePIDs {
		if pid <= 0 {
			continue
		}
		rootPath := fmt.Sprintf("/proc/%d/root%s", pid, path)
		data, err := readFileLimited(rootPath, maxSeedFileBytes)
		if err == nil {
			return string(data), nil
		}
		lastErr = err
	}
	// Fallback: path visible directly to the sensor (rare; hostPath mounts).
	data, err := readFileLimited(path, maxSeedFileBytes)
	if err == nil {
		return string(data), nil
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", err
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
