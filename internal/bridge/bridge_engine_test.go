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
	}, nil, nil, bridge.SelfUIDAuth())
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

// End-to-end: proxy-shaped client → Unix socket → RegisterRemoteTaint +
// RegisterRemoteUntrusted → SUSPICIOUS on a payload-less sensor connect().
// This is the real fix for the gap TestEngine_IngestSyscallSensor_
// NeverReachesSuspicious_KnownGap pins: without an unprivileged proxy
// forwarding both signals over the bridge, sensor-only mode can never light
// untrusted_content_present on its own. With it, AllLit() and the soft
// connect-only tripwire are both reachable. See docs/architecture.md §13,
// docs/cve_corpus.md.
func TestBridge_ClientToEngine_UntrustedClosesSensorSuspiciousGap(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "taint.sock")

	store := engine.NewSessionStore()
	eng := engine.NewEngine(store, nil, "block", nil)

	taintDone := make(chan struct{}, 1)
	untrustedDone := make(chan struct{}, 1)
	srv := bridge.NewServer(sock, func(msg bridge.RegisterTaintMsg) error {
		eng.RegisterRemoteTaint(k8s.SessionIDForPod(msg.PodUID), bridge.ToTaintedValue(msg))
		taintDone <- struct{}{}
		return nil
	}, func(msg bridge.RegisterUntrustedMsg) error {
		eng.RegisterRemoteUntrusted(k8s.SessionIDForPod(msg.PodUID), msg.Source, msg.Seq)
		untrustedDone <- struct{}{}
		return nil
	}, nil, bridge.SelfUIDAuth())
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
	if err := cli.Register("uid-bridge-untrusted", tv); err != nil {
		t.Fatal(err)
	}
	if err := cli.RegisterUntrusted("uid-bridge-untrusted", "web/fetch_page", 2); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-taintDone:
		case <-untrustedDone:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for bridge register")
		}
	}

	dec := eng.IngestSyscallSensor(model.SyscallEvent{
		SessionID: k8s.SessionIDForPod("uid-bridge-untrusted"),
		Syscall:   "connect",
		DestIP:    "203.0.113.62",
		DestPort:  4444,
		PID:       1,
		Comm:      "reverse-shell",
		// No PayloadExcerpt.
	})
	if dec.Verdict != model.VerdictSuspicious {
		t.Fatalf("want SUSPICIOUS on payload-less connect() via bridge-forwarded untrusted content, got allow=%v verdict=%q", dec.Allow, dec.Verdict)
	}
	if !dec.Allow || dec.Action != model.ActionDetectedOnly {
		t.Fatalf("SUSPICIOUS must stay soft: allow=%v action=%q", dec.Allow, dec.Action)
	}
}
