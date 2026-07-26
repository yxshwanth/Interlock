package bridge

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

func TestClientServer_RegisterRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "taint.sock")

	got := make(chan RegisterTaintMsg, 1)
	srv := NewServer(sock, func(msg RegisterTaintMsg) error {
		got <- msg
		return nil
	}, nil, nil, SelfUIDAuth())
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Serve()

	cli := NewClient(sock)
	defer cli.Close()

	tv := model.TaintedValue{
		Value:    "sk-live-testsecret1234567890abcdef",
		Hash:     "abc",
		Preview:  "sk-...def",
		Source:   "tickets/read_ticket",
		Seq:      7,
		Variants: []model.TaintedVariant{{Form: "literal", Value: "sk-live-testsecret1234567890abcdef"}},
	}
	if err := cli.Register("pod-uid-1", tv); err != nil {
		t.Fatal(err)
	}

	select {
	case msg := <-got:
		if msg.PodUID != "pod-uid-1" {
			t.Fatalf("pod_uid=%q", msg.PodUID)
		}
		if msg.Value != tv.Value || msg.Hash != tv.Hash {
			t.Fatalf("msg=%+v", msg)
		}
		converted := ToTaintedValue(msg)
		if converted.Value != tv.Value || len(converted.Variants) != 1 {
			t.Fatalf("converted=%+v", converted)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for register")
	}
}

func TestClientServer_RegisterUntrustedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "taint.sock")

	got := make(chan RegisterUntrustedMsg, 1)
	srv := NewServer(sock, nil, func(msg RegisterUntrustedMsg) error {
		got <- msg
		return nil
	}, nil, SelfUIDAuth())
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Serve()

	cli := NewClient(sock)
	defer cli.Close()

	if err := cli.RegisterUntrusted("pod-uid-2", "web/fetch_page", 3); err != nil {
		t.Fatal(err)
	}

	select {
	case msg := <-got:
		if msg.PodUID != "pod-uid-2" || msg.Source != "web/fetch_page" || msg.Seq != 3 {
			t.Fatalf("msg=%+v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for register_untrusted")
	}
}

func TestParseRejectsEmptyPodUID_Untrusted(t *testing.T) {
	_, err := parseRegisterUntrustedLine([]byte(`{"op":"register_untrusted","pod_uid":"","source":"web/fetch_page"}`))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuthPolicy_Allow(t *testing.T) {
	p := AuthPolicy{AllowedUIDs: []int{1000}, AllowedGIDs: []int{1500}}
	if !p.Active() {
		t.Fatal("expected active")
	}
	if !p.Allow(1000, 1500) {
		t.Fatal("expected allow matching uid+gid")
	}
	if p.Allow(1001, 1500) {
		t.Fatal("expected reject wrong uid")
	}
	if p.Allow(1000, 1) {
		t.Fatal("expected reject wrong gid")
	}
	uidOnly := AuthPolicy{AllowedUIDs: []int{os.Geteuid()}}
	if !uidOnly.Allow(uint32(os.Geteuid()), 0) {
		t.Fatal("uid-only should ignore gid")
	}
}

func TestClientServer_RejectsDisallowedUID(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "taint.sock")

	got := make(chan RegisterTaintMsg, 1)
	// Impossible UID — peer (this process) must be rejected.
	srv := NewServer(sock, func(msg RegisterTaintMsg) error {
		got <- msg
		return nil
	}, nil, nil, AuthPolicy{AllowedUIDs: []int{1 << 30}})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Serve()

	cli := NewClient(sock)
	defer cli.Close()
	tv := model.TaintedValue{Value: "v", Hash: "h", Preview: "p"}
	_ = cli.Register("pod", tv) // dial may succeed; write may succeed; server drops conn

	select {
	case <-got:
		t.Fatal("handler must not run for disallowed peer")
	case <-time.After(300 * time.Millisecond):
		// ok
	}
}

func TestParseRejectsEmptyPodUID(t *testing.T) {
	_, err := parseRegisterLine([]byte(`{"op":"register_taint","pod_uid":"","hash":"h","value":"v"}`))
	if err == nil {
		t.Fatal("expected error")
	}
}
