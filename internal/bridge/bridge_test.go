package bridge

import (
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
	}, nil)
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

func TestParseRejectsEmptyPodUID(t *testing.T) {
	_, err := parseRegisterLine([]byte(`{"op":"register_taint","pod_uid":"","hash":"h","value":"v"}`))
	if err == nil {
		t.Fatal("expected error")
	}
}
