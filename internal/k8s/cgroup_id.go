package k8s

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// CgroupIDFromPID returns the cgroup v2 ID (directory inode) for a process.
// This matches bpf_get_current_cgroup_id() and is stable across PID namespaces.
func CgroupIDFromPID(pid int, procRoot, cgroupRoot string) (uint64, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/cgroup", procRoot, pid))
	if err != nil {
		return 0, err
	}
	rel := cgroupV2Path(string(data))
	if rel == "" {
		return 0, fmt.Errorf("no cgroup v2 path for pid %d", pid)
	}
	// Normalize relative paths like /../../../kubelet...
	full := filepath.Join(cgroupRoot, strings.TrimPrefix(rel, "/"))
	full = filepath.Clean(full)
	st, err := os.Stat(full)
	if err != nil {
		return 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("stat cgroup %s: no Stat_t", full)
	}
	return sys.Ino, nil
}

func cgroupV2Path(cgroupData string) string {
	for _, line := range strings.Split(cgroupData, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// cgroup v2: 0::/path
		if strings.HasPrefix(line, "0::") {
			return line[3:]
		}
	}
	return ""
}
