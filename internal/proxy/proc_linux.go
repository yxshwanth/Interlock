//go:build linux

package proxy

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ProcessStartTimeNs returns the process start time in nanoseconds since boot.
func ProcessStartTimeNs(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}

	s := string(data)
	close := strings.LastIndex(s, ")")
	if close < 0 {
		return 0, fmt.Errorf("parse /proc/%d/stat: malformed comm", pid)
	}
	rest := strings.Fields(s[close+2:])
	if len(rest) < 20 {
		return 0, fmt.Errorf("parse /proc/%d/stat: short fields", pid)
	}

	startTicks, err := strconv.ParseUint(rest[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse /proc/%d/stat starttime: %w", pid, err)
	}

	// Linux USER_HZ is typically 100 on x86_64.
	const clkTck = 100
	nsPerTick := uint64(time.Second) / clkTck
	return startTicks * nsPerTick, nil
}
