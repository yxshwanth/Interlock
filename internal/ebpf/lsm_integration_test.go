package ebpf_test

import (
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
	interlockebpf "github.com/yxshwanth/Interlock/internal/ebpf"
	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/model"
)

// syncSink is a concurrency-safe evidence sink for the async sensor readLoop.
type syncSink struct {
	mu      sync.Mutex
	records []model.EvidenceRecord
}

func (s *syncSink) Emit(rec model.EvidenceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	return nil
}

func (s *syncSink) snapshot() []model.EvidenceRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.EvidenceRecord(nil), s.records...)
}

// requireRootAndBPFLSMForIntegration mirrors the unexported helper in
// lsm_test.go (package ebpf) — duplicated here since this file is in the
// separate ebpf_test package.
func requireRootAndBPFLSMForIntegration(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF LSM programs")
	}
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil || !strings.Contains(string(data), "bpf") {
		t.Skip(`requires CONFIG_BPF_LSM=y and "bpf" active in /sys/kernel/security/lsm (see deploy/k8s/PRIVILEGE.md)`)
	}
}

// TestSensor_LSMDenyEmitsEvidence proves the full round trip: once a session
// is already confirmed EXFIL (tripped exactly like a real write/sendto
// payload-overlap would do — seeded directly here to avoid a second real
// SIGKILL-triggering trip in-process), a real connect() attempt denied by the
// kernel LSM hook flows all the way through the real ring buffer, the real
// Sensor.handleLSMDeny, and back into the engine as a "prevented" follow-up
// EvidenceRecord — without re-running leg/overlap classification.
func TestSensor_LSMDenyEmitsEvidence(t *testing.T) {
	requireRootAndBPFLSMForIntegration(t)

	const sessionID = "lsm-e2e-test"
	pid := os.Getpid()

	store := engine.NewSessionStore()
	tagger := engine.NewTagger(&config.Config{})
	sink := &syncSink{}
	eng := engine.NewEngine(store, tagger, "block", sink)

	// Seed the session as already-tripped EXFIL via the same path a real
	// write/sendto payload-overlap trip would take (internal/engine/engine_test.go's
	// TestEngine_IngestSyscallSensor_WriteOverlapEXFIL) — deliberately not via the
	// real sensor, so no real SIGKILL races the test process itself.
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	_ = eng.IngestSyscallSensor(model.SyscallEvent{
		SessionID:    sessionID,
		Syscall:      "openat",
		Path:         "/secrets/demo-token",
		FileContents: secret,
		PID:          pid,
		Comm:         "test",
	})
	tripDec := eng.IngestSyscallSensor(model.SyscallEvent{
		SessionID:      sessionID,
		Syscall:        "write",
		DestIP:         "203.0.113.66",
		DestPort:       4444,
		PID:            pid,
		Comm:           "test",
		PayloadExcerpt: secret,
	})
	if tripDec.Verdict != model.VerdictExfil || tripDec.Action != model.ActionContained {
		t.Fatalf("seed trip: want EXFIL/contained_by_kill, got verdict=%q action=%q", tripDec.Verdict, tripDec.Action)
	}

	handler := func(ev model.SyscallEvent) model.Decision {
		if ev.PID == pid {
			ev.SessionID = sessionID
		}
		return eng.IngestSyscallSensor(ev)
	}

	sensor, err := interlockebpf.NewSensor(nil, nil, true, handler)
	if err != nil {
		t.Fatalf("NewSensor(lsmEnforce=true): %v", err)
	}
	defer sensor.Stop()
	if !sensor.LSMEnforced() {
		t.Skip("LSM hook did not attach on this kernel")
	}
	sensor.Start()

	// Arm the kernel-level quarantine directly (this is exactly what
	// sensor.go's handleWrite would have done alongside containPIDs, had the
	// trip above gone through the real sensor instead of being seeded).
	if err := sensor.Quarantine(0, pid); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	if err := dialUDPTestNet(); err == nil {
		t.Fatal("expected connect() to be denied for a quarantined pid")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, rec := range sink.snapshot() {
			if rec.SessionID == sessionID && rec.Action == model.ActionPrevented && rec.Verdict == model.VerdictExfil {
				return // success
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for prevented follow-up evidence; got records: %+v", sink.snapshot())
}

// dialUDPTestNet performs a UDP "connect" (sets a default peer; no handshake,
// no listener required) to a TEST-NET-3 (RFC 5737) address, matching
// lsm_test.go's helper — duplicated here since this file is in the separate
// ebpf_test package.
func dialUDPTestNet() error {
	conn, err := net.DialTimeout("udp", "203.0.113.5:4444", time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}
