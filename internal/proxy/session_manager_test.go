package proxy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
)

func TestSessionManager_Isolation(t *testing.T) {
	root := findModuleRoot(t)
	ticketsBin := filepath.Join(root, "servers/tickets/tickets")
	messengerBin := filepath.Join(root, "servers/messenger/messenger")
	if _, err := os.Stat(ticketsBin); err != nil {
		t.Skip("server binaries not built; run make build")
	}
	if _, err := os.Stat(messengerBin); err != nil {
		t.Skip("server binaries not built; run make build")
	}

	cfg := &config.Config{
		Sessions: config.SessionsConfig{MaxConcurrent: 4, IdleTimeout: "30m"},
		Servers: []config.ServerConfig{
			{ID: "tickets", Command: ticketsBin},
			{ID: "messenger", Command: messengerBin},
		},
	}

	p := New(cfg, nil, nil)
	p.Sessions().StartIdleSweeper(context.Background())

	rtA, err := p.Sessions().Create(NewSession())
	if err != nil {
		t.Fatal(err)
	}
	rtB, err := p.Sessions().Create(NewSession())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Sessions().Cleanup(rtA.Session.ID)
	defer p.Sessions().Cleanup(rtB.Session.ID)

	if rtA.Session.ID == rtB.Session.ID {
		t.Fatal("sessions should have distinct IDs")
	}

	pidA := rtA.servers["tickets"].proc.PID
	pidB := rtB.servers["tickets"].proc.PID
	if pidA == pidB {
		t.Fatalf("sessions must not share backend PIDs: both %d", pidA)
	}
}

func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
