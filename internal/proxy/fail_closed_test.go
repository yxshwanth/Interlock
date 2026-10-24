// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
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

func panickingEngine() *engine.Engine {
	// A zero-value SessionStore has a nil map: GetOrCreate (used by
	// EvaluateRequest and IngestResult) panics, Get (RedactEvent) does not.
	return engine.NewEngine(&engine.SessionStore{}, nil, "block", nil)
}

func TestDeliverServerFrame_IngestPanicWithholdsResult(t *testing.T) {
	cfg := &config.Config{Enforcement: "block"}
	p := New(cfg, nil, panickingEngine())
	var breakerHits int
	p.SetOnEnginePanic(func(any) { breakerHits++ })
	var agentOut bytes.Buffer
	p.agentWriter = NewFrameWriter(&agentOut)

	rt := &SessionRuntime{
		Session:  NewSession(),
		pending:  map[string]*pendingCall{"1": {toolName: "read_file"}},
		syncWait: map[string]chan []byte{},
	}
	sc := &serverConn{proc: &ServerProcess{ID: "fs", PID: 1}}
	waiter := make(chan []byte, 1)
	rt.syncWait["1"] = waiter

	result := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"SECRET-RESULT-BODY"}]}}`
	p.deliverServerFrame(rt, sc, []byte(result))

	if breakerHits != 1 {
		t.Fatalf("breaker notified %d times, want 1", breakerHits)
	}
	got := <-waiter
	if strings.Contains(string(got), "SECRET-RESULT-BODY") || strings.Contains(agentOut.String(), "SECRET-RESULT-BODY") {
		t.Fatalf("result forwarded after ingest panic: waiter=%s agent=%s", got, agentOut.String())
	}
	var msg map[string]any
	if err := json.Unmarshal(got, &msg); err != nil || msg["error"] == nil || msg["id"] != float64(1) {
		t.Fatalf("want JSON-RPC error for id 1, got %s", got)
	}
}

func TestDispatch_EvaluatePanicBlocksCall(t *testing.T) {
	cfg := &config.Config{Enforcement: "block"}
	p := New(cfg, nil, panickingEngine())
	var breakerHits int
	p.SetOnEnginePanic(func(any) { breakerHits++ })
	rt := &SessionRuntime{
		Session:   NewSession(),
		toolRoute: map[string]*serverConn{"send_message": {proc: &ServerProcess{ID: "messenger", PID: 1}}},
		pending:   map[string]*pendingCall{},
		syncWait:  map[string]chan []byte{},
	}
	frame := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_message","arguments":{"text":"hi"}}}`)
	// The serverConn has no writer, so a forwarded call would panic or error;
	// a clean Blocked result proves it never reached the server.
	res, err := p.HandleAgentRequest(context.Background(), rt, frame)
	if err != nil || res == nil || !res.Blocked {
		t.Fatalf("want blocked result, got %+v err=%v", res, err)
	}
	if breakerHits != 1 {
		t.Fatalf("breaker notified %d times, want 1", breakerHits)
	}
}
