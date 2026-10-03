//go:build linux

package ebpf

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// DropPostAttach clears CAP_SYS_ADMIN from the process effective and
// permitted sets after eBPF load/attach (ROADMAP §13). Keeps CAP_KILL
// (containment), CAP_BPF, and CAP_PERFMON (map updates / conservative residual).
// When keepSYSAdmin is true (proxy sandbox.netns), SYS_ADMIN is left alone.
func DropPostAttach(keepSYSAdmin bool) error {
	before, _ := ReadCapEff()
	if keepSYSAdmin {
		log.Printf("[SECURITY] caps post-attach: keep SYS_ADMIN (sandbox.netns); CapEff=%s", before)
		return nil
	}

	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}

	clearCap(&data, unix.CAP_SYS_ADMIN)

	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}

	after, _ := ReadCapEff()
	log.Printf("[SECURITY] caps post-attach: dropped SYS_ADMIN before=%s after=%s (kept KILL/BPF/PERFMON)", before, after)
	return nil
}

func clearCap(data *[2]unix.CapUserData, cap int) {
	idx := cap >> 5
	bit := uint32(1) << (uint(cap) & 31)
	if idx < 0 || idx >= len(data) {
		return
	}
	data[idx].Effective &^= bit
	data[idx].Permitted &^= bit
}

// CapBitSet reports whether cap is set in CapEff (for tests).
func CapBitSet(capEffHex string, cap int) bool {
	v, err := parseCapHex(capEffHex)
	if err != nil {
		return false
	}
	return v&(1<<uint(cap)) != 0
}

// ReadCapEff returns the CapEff hex string from /proc/self/status.
func ReadCapEff() (string, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1], nil
			}
		}
	}
	return "", fmt.Errorf("CapEff not found")
}

func parseCapHex(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(s), 16, 64)
}

// FormatCapSummary names the DaemonSet-relevant bits present in CapEff hex.
func FormatCapSummary(capEffHex string) string {
	v, err := parseCapHex(capEffHex)
	if err != nil {
		return capEffHex
	}
	var parts []string
	check := func(name string, cap int) {
		if v&(1<<uint(cap)) != 0 {
			parts = append(parts, name)
		}
	}
	check("KILL", unix.CAP_KILL)
	check("SYS_ADMIN", unix.CAP_SYS_ADMIN)
	check("PERFMON", unix.CAP_PERFMON)
	check("BPF", unix.CAP_BPF)
	if len(parts) == 0 {
		return capEffHex + " (none of KILL/SYS_ADMIN/PERFMON/BPF)"
	}
	return fmt.Sprintf("%s [%s]", capEffHex, strings.Join(parts, ","))
}
