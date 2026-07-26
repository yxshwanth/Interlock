package ebpf

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// requireRootAndBPFLSM skips the test unless running as root on a kernel with
// CONFIG_BPF_LSM=y and "bpf" active in /sys/kernel/security/lsm — the
// prerequisite documented in deploy/k8s/PRIVILEGE.md and only satisfied on
// the throwaway EC2 VM (deploy/ec2/) today, not in normal CI.
func requireRootAndBPFLSM(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF LSM programs")
	}
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil || !strings.Contains(string(data), "bpf") {
		t.Skip(`requires CONFIG_BPF_LSM=y and "bpf" active in /sys/kernel/security/lsm (see deploy/k8s/PRIVILEGE.md)`)
	}
}

// --- CI-safe: unloaded Loader must fail closed/clear, never panic. ---

func TestLoader_LSMEnforced_DefaultFalse(t *testing.T) {
	var l Loader
	if l.LSMEnforced() {
		t.Fatal("LSMEnforced must be false on a zero-value/unloaded Loader")
	}
}

func TestLoader_Quarantine_UnloadedReturnsError(t *testing.T) {
	var l Loader
	if err := l.Quarantine(1234, 0); err == nil {
		t.Fatal("expected a clear error quarantining without an attached LSM hook")
	}
}

func TestLoader_Unquarantine_UnloadedNoop(t *testing.T) {
	var l Loader
	if err := l.Unquarantine(1234, 0); err != nil {
		t.Fatalf("Unquarantine on an unloaded Loader should no-op, got: %v", err)
	}
}

func TestLoader_QuarantineAllWatched_UnloadedReturnsError(t *testing.T) {
	var l Loader
	if err := l.QuarantineAllWatched(); err == nil {
		t.Fatal("expected error from QuarantineAllWatched without attached LSM")
	}
}

func TestLoader_ListQuarantined_UnloadedReturnsError(t *testing.T) {
	var l Loader
	if _, _, err := l.ListQuarantined(); err == nil {
		t.Fatal("expected error from ListQuarantined without attached LSM")
	}
}

func TestLoader_UnquarantineWatched_UnloadedNoop(t *testing.T) {
	var l Loader
	if err := l.UnquarantineWatched([]int{1}, []uint64{2}); err != nil {
		t.Fatalf("UnquarantineWatched unloaded should no-op, got: %v", err)
	}
}

// --- Root + BPF-LSM-gated: only actually execute on the throwaway VM. ---

// dialUDPTestNet performs a UDP "connect" (sets a default peer; no handshake,
// no listener required) to a TEST-NET-3 (RFC 5737) address — the same
// non-routable range already used for EXFIL fixtures in
// internal/engine/engine_test.go. connect() on a UDP socket still invokes
// security_socket_connect, so this is sufficient to exercise the LSM hook
// without needing a live listener or sending real traffic anywhere.
func dialUDPTestNet() error {
	conn, err := net.DialTimeout("udp", "203.0.113.5:4444", time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

func TestLSM_QuarantineDeniesConnect(t *testing.T) {
	requireRootAndBPFLSM(t)

	loader, err := NewLoader(true)
	if err != nil {
		t.Fatalf("NewLoader(true): %v", err)
	}
	defer loader.Close()
	if !loader.LSMEnforced() {
		t.Skip("LSM hook did not attach on this kernel")
	}

	if err := dialUDPTestNet(); err != nil {
		t.Fatalf("baseline dial before quarantine unexpectedly failed: %v", err)
	}

	pid := os.Getpid()
	if err := loader.Quarantine(pid, 0); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	defer loader.Unquarantine(pid, 0)

	if err := dialUDPTestNet(); err == nil {
		t.Fatal("expected connect() to be denied for a quarantined pid, got nil error")
	} else if !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("expected an EPERM-flavored error, got: %v", err)
	}

	// Negative control (same pid): lifting the quarantine restores normal
	// connect() behavior — the denial is not a stuck/global side effect.
	if err := loader.Unquarantine(pid, 0); err != nil {
		t.Fatalf("Unquarantine: %v", err)
	}
	if err := dialUDPTestNet(); err != nil {
		t.Fatalf("dial after unquarantine unexpectedly failed: %v", err)
	}
}

func TestLSM_QuarantineNegativeControl_OtherPIDUnaffected(t *testing.T) {
	requireRootAndBPFLSM(t)

	loader, err := NewLoader(true)
	if err != nil {
		t.Fatalf("NewLoader(true): %v", err)
	}
	defer loader.Close()
	if !loader.LSMEnforced() {
		t.Skip("LSM hook did not attach on this kernel")
	}

	// Quarantine an unrelated, near-certainly-nonexistent PID — must not
	// affect this (unquarantined) test process's own connect() calls.
	const unrelatedPID = 999999
	if err := loader.Quarantine(unrelatedPID, 0); err != nil {
		t.Fatalf("Quarantine(unrelated pid): %v", err)
	}
	defer loader.Unquarantine(unrelatedPID, 0)

	if err := dialUDPTestNet(); err != nil {
		t.Fatalf("connect from an unquarantined pid should succeed, got: %v", err)
	}
}

// TestLSM_FailClosedQuarantineAllDeniesConnect proves SetFailClosedActive
// quarantines watched PIDs (kernel -EPERM) and clearing restores connect,
// without lifting a pre-existing EXFIL quarantine on a different PID.
func TestLSM_FailClosedQuarantineAllDeniesConnect(t *testing.T) {
	requireRootAndBPFLSM(t)

	sensor, err := NewSensor(nil, nil, true, nil)
	if err != nil {
		t.Fatalf("NewSensor: %v", err)
	}
	defer sensor.Stop()
	if !sensor.LSMEnforced() {
		t.Skip("LSM hook did not attach on this kernel")
	}

	pid := os.Getpid()
	if err := sensor.AddPIDs(pid); err != nil {
		t.Fatalf("AddPIDs: %v", err)
	}

	// Pre-existing EXFIL quarantine on an unrelated PID — must survive clear.
	const exfilPID = 999998
	if err := sensor.Quarantine(0, exfilPID); err != nil {
		t.Fatalf("pre-EXFIL Quarantine: %v", err)
	}
	defer sensor.loader.Unquarantine(exfilPID, 0)

	if err := dialUDPTestNet(); err != nil {
		t.Fatalf("baseline dial: %v", err)
	}

	if err := sensor.SetFailClosedActive(true); err != nil {
		t.Fatalf("SetFailClosedActive(true): %v", err)
	}
	if err := dialUDPTestNet(); err == nil {
		t.Fatal("expected EPERM while fail-closed active")
	} else if !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("expected EPERM, got: %v", err)
	}

	if err := sensor.SetFailClosedActive(false); err != nil {
		t.Fatalf("SetFailClosedActive(false): %v", err)
	}
	if err := dialUDPTestNet(); err != nil {
		t.Fatalf("dial after clear: %v", err)
	}

	// EXFIL quarantine on unrelated PID still present.
	still, _, err := sensor.loader.ListQuarantined()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range still {
		if p == exfilPID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("EXFIL quarantine on unrelated PID was lifted by fail-closed clear")
	}
}

// TestLSM_DenySurvivesConnectFlood proves dual ringbufs: a connect storm that
// fills the routine ring (undrained) must not starve lsm_deny on the critical
// path. Kernel -EPERM still happens; userspace still receives the deny record.
func TestLSM_DenySurvivesConnectFlood(t *testing.T) {
	requireRootAndBPFLSM(t)

	loader, err := NewLoader(true)
	if err != nil {
		t.Fatalf("NewLoader(true): %v", err)
	}
	defer loader.Close()
	if !loader.LSMEnforced() {
		t.Skip("LSM hook did not attach on this kernel")
	}

	pid := os.Getpid()
	if err := loader.AddPID(pid); err != nil {
		t.Fatalf("AddPID: %v", err)
	}

	// Fill the undrained routine ring with connect events, then stop flooding
	// before quarantine so denied connects do not also pressure critical_events.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for i := 0; i < 256; i++ {
			c, err := net.DialTimeout("tcp", "127.0.0.1:1", time.Millisecond)
			if err == nil {
				_ = c.Close()
			}
		}
		if drops, err := loader.DropCount(); err == nil && drops > 0 {
			break
		}
	}
	drops, err := loader.DropCount()
	if err != nil {
		t.Fatalf("DropCount: %v", err)
	}
	t.Logf("pre-quarantine drop_count=%d (routine undrained)", drops)

	if err := loader.Quarantine(pid, 0); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	gotDeny := make(chan *LSMDenyEvent, 1)
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			ev, err := loader.ReadCriticalEvent()
			if err != nil {
				continue
			}
			if ev != nil && ev.LSMDeny != nil && int(ev.LSMDeny.PID) == pid {
				gotDeny <- ev.LSMDeny
				return
			}
		}
	}()

	if err := dialUDPTestNet(); err == nil {
		t.Fatal("expected EPERM for quarantined pid")
	} else if !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("expected EPERM, got: %v", err)
	}

	select {
	case <-gotDeny:
		// ok
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for lsm_deny on critical ring after connect flood")
	}

	crit, err := loader.CriticalDropCount()
	if err != nil {
		t.Fatalf("CriticalDropCount: %v", err)
	}
	t.Logf("after deny: drop_count=%d critical_drop_count=%d", drops, crit)
	if crit != 0 {
		t.Fatalf("unexpected critical drops while delivering lsm_deny: %d", crit)
	}
}
