package proxy_test

import (
	"testing"

	"github.com/yxshwanth/Interlock/internal/proxy"
)

func TestPIDRegistry_ReuseSafety(t *testing.T) {
	reg := proxy.NewPIDRegistry()
	pid := 4242

	reg.Register(pid, 100, "session-a", "tickets")
	sid, _, ok := reg.Lookup(pid)
	if !ok || sid != "session-a" {
		t.Fatalf("lookup session-a: got %q ok=%v", sid, ok)
	}

	reg.Unregister(pid, 100)
	reg.Register(pid, 200, "session-b", "messenger")

	sid, srv, ok := reg.Lookup(pid)
	if !ok || sid != "session-b" || srv != "messenger" {
		t.Fatalf("lookup session-b: session=%q server=%q ok=%v", sid, srv, ok)
	}
}

func TestPIDRegistry_DistinctSessions(t *testing.T) {
	reg := proxy.NewPIDRegistry()
	reg.Register(100, 1, "s1", "tickets")
	reg.Register(200, 2, "s2", "tickets")

	s1, _, ok := reg.Lookup(100)
	if !ok || s1 != "s1" {
		t.Fatalf("pid 100 -> %q", s1)
	}
	s2, _, ok := reg.Lookup(200)
	if !ok || s2 != "s2" {
		t.Fatalf("pid 200 -> %q", s2)
	}
}
