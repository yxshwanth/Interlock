//go:build !linux

package proxy

import "fmt"

// ProcessStartTimeNs is only supported on Linux (/proc).
func ProcessStartTimeNs(pid int) (uint64, error) {
	return 0, fmt.Errorf("process start time unsupported on this platform (pid=%d)", pid)
}
