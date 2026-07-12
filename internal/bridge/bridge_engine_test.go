package bridge_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/bridge"
	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/k8s"
	"github.com/yxshwanth/Interlock/internal/model"
)

// End-to-end: proxy-shaped client → Unix socket → RegisterRemoteTaint → EXFIL on write.
func TestBridge_ClientToEngine_EXFIL(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "taint.sock")

	store := engine.NewSessionStore()
	eng := engine.NewEngine(store, nil, "block", nil)

	done := make(chan struct{}, 1)
	srv := bridge.NewServer(sock, func(msg bridge.RegisterTaintMsg) error {
		eng.RegisterRemoteTaint(k8s.SessionIDForPod(msg.PodUID), bridge.ToTaintedValue(msg))
		done <- struct{}{}
		return nil
	}, nil)
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Serve()

	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	cli := bridge.NewClient(sock)
	defer cli.Close()
	tv := model.TaintedValue{
		Value:    secret,
		Variants: engine.CanonicalEncodings(secret),
		Hash:     engine.HashValue(secret),
		Preview:  engine.MaskValue(secret),
		Source:   "tickets/read_ticket",
	}
	if err := cli.Register("uid-bridge-e2e", tv); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for bridge register")
	}

	dec := eng.IngestSyscallSensor(model.SyscallEvent{
		SessionID:      k8s.SessionIDForPod("uid-bridge-e2e"),
		Syscall:        "write",
		DestIP:         "203.0.113.66",
		DestPort:       4444,
		PID:            42,
		Comm:           "exfil",
		PayloadExcerpt: "leaking " + secret,
	})
	if dec.Allow || dec.Verdict != model.VerdictExfil {
		t.Fatalf("want EXFIL, got allow=%v verdict=%q action=%q", dec.Allow, dec.Verdict, dec.Action)
	}
}
