package ebpf_test

import (
	"testing"

	interlockebpf "github.com/yxshwanth/Interlock/internal/ebpf"
)

func TestSensor_UpdateAllowlistAndSensitivePaths(t *testing.T) {
	// NewSensor requires BPF load — skip if not root / no BTF.
	s, err := interlockebpf.NewSensor([]string{"10.0.0.1"}, []string{"/secrets"}, nil)
	if err != nil {
		t.Skipf("eBPF unavailable: %v", err)
	}
	defer s.Stop()

	s.UpdateAllowlist([]string{"203.0.113.1", "203.0.113.2"})
	s.UpdateSensitivePaths([]string{"/etc/shadow", "/var/run/secrets"})
	// Second update replaces prior set.
	s.UpdateAllowlist(nil)
	s.UpdateSensitivePaths(nil)
}
