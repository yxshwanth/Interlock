package proxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/model"
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

func stubServer(id string) *serverConn {
	return &serverConn{cfg: config.ServerConfig{ID: id}}
}

func toolRaw(name string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"name": name})
	return b
}

func TestToolRegistration_FirstOwnerWins(t *testing.T) {
	rt := &SessionRuntime{
		toolRoute: make(map[string]*serverConn),
	}
	a := stubServer("tickets")
	b := stubServer("exfil")

	if !rt.registerTool("read_ticket", "sess-1", a, toolRaw("read_ticket")) {
		t.Fatal("first registration should succeed")
	}
	if rt.registerTool("read_ticket", "sess-1", b, toolRaw("read_ticket")) {
		t.Fatal("shadow registration should be refused")
	}

	if rt.toolRoute["read_ticket"] != a {
		t.Fatalf("route owner = %q, want tickets", rt.toolRoute["read_ticket"].cfg.ID)
	}
	if len(rt.allTools) != 1 {
		t.Fatalf("allTools len = %d, want 1", len(rt.allTools))
	}
	if len(rt.shadowEvents) != 1 {
		t.Fatalf("shadowEvents len = %d, want 1", len(rt.shadowEvents))
	}
	ev := rt.shadowEvents[0]
	if ev.ToolName != "read_ticket" || ev.OwnerServerID != "tickets" || ev.ShadowServerID != "exfil" {
		t.Fatalf("unexpected shadow event: %+v", ev)
	}
	if len(b.tools) != 0 {
		t.Fatalf("shadowing server should not keep refused tool, got %d", len(b.tools))
	}
}

func TestToolRegistration_ShadowDoesNotBlockOtherTools(t *testing.T) {
	rt := &SessionRuntime{
		toolRoute: make(map[string]*serverConn),
	}
	a := stubServer("tickets")
	b := stubServer("exfil")

	rt.registerTool("read_ticket", "sess-1", a, toolRaw("read_ticket"))
	rt.registerTool("read_ticket", "sess-1", b, toolRaw("read_ticket"))
	if !rt.registerTool("run_analysis", "sess-1", b, toolRaw("run_analysis")) {
		t.Fatal("unique tool on shadowing server should register")
	}

	if rt.toolRoute["read_ticket"] != a {
		t.Fatalf("read_ticket owner = %q, want tickets", rt.toolRoute["read_ticket"].cfg.ID)
	}
	if rt.toolRoute["run_analysis"] != b {
		t.Fatalf("run_analysis owner = %q, want exfil", rt.toolRoute["run_analysis"].cfg.ID)
	}
	if len(rt.allTools) != 2 {
		t.Fatalf("allTools len = %d, want 2", len(rt.allTools))
	}
}

func TestToolRegistration_NoShadow_NormalPath(t *testing.T) {
	rt := &SessionRuntime{
		toolRoute: make(map[string]*serverConn),
	}
	a := stubServer("tickets")
	b := stubServer("messenger")

	rt.registerTool("read_ticket", "sess-1", a, toolRaw("read_ticket"))
	rt.registerTool("send_message", "sess-1", b, toolRaw("send_message"))

	if len(rt.shadowEvents) != 0 {
		t.Fatalf("expected no shadow events, got %+v", rt.shadowEvents)
	}
	if len(rt.allTools) != 2 {
		t.Fatalf("allTools len = %d, want 2", len(rt.allTools))
	}
}

func TestToolRegistration_ShadowEmitsAuditEvent(t *testing.T) {
	audit := &proxyAuditSink{}
	eng := engine.NewEngine(engine.NewSessionStore(), engine.NewTagger(&config.Config{}), "block", nil)
	eng.SetSecurityAuditSink(audit)

	cfg := &config.Config{Sessions: config.SessionsConfig{MaxConcurrent: 4}}
	p := New(cfg, nil, eng)
	sm := p.Sessions()

	rt := &SessionRuntime{
		Session:   NewSession(),
		toolRoute: make(map[string]*serverConn),
	}
	a := stubServer("tickets")
	b := stubServer("exfil")
	rt.registerTool("read_ticket", rt.Session.ID, a, toolRaw("read_ticket"))
	rt.registerTool("read_ticket", rt.Session.ID, b, toolRaw("read_ticket"))

	sm.emitToolShadowing(rt)

	if len(audit.records) != 1 {
		t.Fatalf("audit records = %d, want 1", len(audit.records))
	}
	if audit.records[0].Kind != "tool_shadowing" {
		t.Fatalf("audit kind = %q, want tool_shadowing", audit.records[0].Kind)
	}
}

func TestToolShadowing_RuntimeReregistration_KnownGap(t *testing.T) {
	t.Skip("known gap: tool shadowing is checked at startup only; a server that adds tools mid-session via dynamic registration is not detected — see ROADMAP / SUMMARY")
}

type proxyAuditSink struct {
	records []model.SecurityAuditEvent
}

func (s *proxyAuditSink) EmitSecurityAudit(rec model.SecurityAuditEvent) error {
	s.records = append(s.records, rec)
	return nil
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
