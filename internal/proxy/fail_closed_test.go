package proxy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/engine"
)

func TestDispatch_FailClosedBlocksBeforeEngine(t *testing.T) {
	cfg := &config.Config{
		Enforcement: "block",
		Servers: []config.ServerConfig{
			{ID: "messenger", Command: "true", ProvidesTags: []string{"external_sink"}},
		},
		ToolTags: map[string][]string{
			"send_message": {"external_sink"},
		},
	}
	store := engine.NewSessionStore()
	tagger := engine.NewTagger(cfg)
	eng := engine.NewEngine(store, tagger, "block", nil)
	p := New(cfg, nil, eng)

	rt := &SessionRuntime{
		Session:   NewSession(),
		toolRoute: map[string]*serverConn{},
		pending:   map[string]*pendingCall{},
		syncWait:  map[string]chan []byte{},
	}
	rt.toolRoute["send_message"] = &serverConn{proc: &ServerProcess{ID: "messenger", PID: 1}}

	p.SetFailClosed(true, "ringbuf_drop_rate=99.0/s")

	frame, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "send_message",
			"arguments": map[string]any{"text": "hi"},
		},
	})

	res, err := p.HandleAgentRequest(context.Background(), rt, frame)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || !res.Blocked {
		t.Fatal("expected blocked result under fail-closed")
	}
	var msg map[string]any
	if err := json.Unmarshal(res.Response, &msg); err != nil {
		t.Fatal(err)
	}
	errObj, _ := msg["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("expected JSON-RPC error, got %v", msg)
	}
	m, _ := errObj["message"].(string)
	if !strings.Contains(m, "fail_closed") {
		t.Fatalf("expected fail_closed in message, got %q", m)
	}
}

func TestProxy_FailClosedRoundTrip(t *testing.T) {
	cfg := &config.Config{Enforcement: "block"}
	p := New(cfg, nil, nil)
	p.SetFailClosed(true, "test")
	active, reason := p.FailClosed()
	if !active || reason != "test" {
		t.Fatalf("FailClosed=%v %q", active, reason)
	}
	p.SetFailClosed(false, "")
	active, _ = p.FailClosed()
	if active {
		t.Fatal("expected cleared")
	}
}
