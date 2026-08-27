package k8s

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ProcessKey uniquely identifies a process instance (PID + start time).
type ProcessKey struct {
	PID         int
	StartTimeNs uint64
}

// ProcScanner finds host PIDs belonging to watched container IDs via /proc.
type ProcScanner struct {
	ProcRoot string // default "/proc"
}

func (s *ProcScanner) procRoot() string {
	if s.ProcRoot == "" {
		return "/proc"
	}
	return s.ProcRoot
}

// PIDsForContainers returns host PIDs whose cgroup matches any of the given
// container IDs (64-hex, no runtime prefix).
func (s *ProcScanner) PIDsForContainers(containerIDs map[string]struct{}) ([]ProcessKey, error) {
	if len(containerIDs) == 0 {
		return nil, nil
	}
	entries, err := os.ReadDir(s.procRoot())
	if err != nil {
		return nil, err
	}
	var out []ProcessKey
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cgPath := filepath.Join(s.procRoot(), e.Name(), "cgroup")
		data, err := os.ReadFile(cgPath)
		if err != nil {
			continue
		}
		id := ExtractContainerID(string(data))
		if id == "" {
			continue
		}
		if _, ok := containerIDs[id]; !ok {
			// Also match by prefix (short IDs in some paths).
			matched := false
			for want := range containerIDs {
				if strings.HasPrefix(want, id) || strings.HasPrefix(id, want) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		startNs, err := processStartTimeNs(s.procRoot(), pid)
		if err != nil {
			startNs = uint64(time.Now().UnixNano())
		}
		out = append(out, ProcessKey{PID: pid, StartTimeNs: startNs})
	}
	return out, nil
}

func processStartTimeNs(procRoot string, pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/stat", procRoot, pid))
	if err != nil {
		return 0, err
	}
	s := string(data)
	closeParen := strings.LastIndex(s, ")")
	if closeParen < 0 {
		return 0, fmt.Errorf("parse %s/%d/stat: malformed comm", procRoot, pid)
	}
	rest := strings.Fields(s[closeParen+2:])
	if len(rest) < 20 {
		return 0, fmt.Errorf("parse %s/%d/stat: short fields", procRoot, pid)
	}
	startTicks, err := strconv.ParseUint(rest[19], 10, 64)
	if err != nil {
		return 0, err
	}
	const clkTck = 100
	nsPerTick := uint64(time.Second) / clkTck
	return startTicks * nsPerTick, nil
}
