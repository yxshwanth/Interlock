package proxy

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
)

func TestSessionManager_ConcurrentCreate(t *testing.T) {
	root := findModuleRoot(t)
	ticketsBin := filepath.Join(root, "servers/tickets/tickets")
	if _, err := os.Stat(ticketsBin); err != nil {
		t.Skip("server binaries not built; run make build")
	}

	cfg := &config.Config{
		Sessions: config.SessionsConfig{MaxConcurrent: 8, IdleTimeout: "30m"},
		Servers: []config.ServerConfig{
			{ID: "tickets", Command: ticketsBin},
		},
	}

	p := New(cfg, nil, nil)
	p.Sessions().StartIdleSweeper(context.Background())

	const n = 4
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(n)

	var wg sync.WaitGroup
	errCh := make(chan error, n)
	ids := make([]string, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ready.Done()
			<-start
			rt, err := p.Sessions().Create(NewSession())
			if err != nil {
				errCh <- err
				return
			}
			ids[idx] = rt.Session.ID
		}(i)
	}

	ready.Wait()
	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" {
			t.Fatal("empty session id")
		}
		if seen[id] {
			t.Fatalf("duplicate session id %q", id)
		}
		seen[id] = true
		p.Sessions().Cleanup(id)
	}
}

func TestPIDRegistry_ConcurrentRegisterLookup(t *testing.T) {
	reg := NewPIDRegistry()
	const n = 50

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			pid := 10000 + i
			reg.Register(pid, uint64(100+i), "sess", "srv")
			reg.Lookup(pid)
			reg.Unregister(pid, uint64(100+i))
		}(i)
	}

	close(start)
	wg.Wait()
}
