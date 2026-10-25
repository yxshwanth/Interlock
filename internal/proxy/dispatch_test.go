// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
)

// Review #12: a server that answers one id twice must not wedge the reader
// goroutine on the waiter's already-full channel.
func TestDeliverServerFrame_DuplicateResponseDoesNotBlock(t *testing.T) {
	p := New(&config.Config{}, nil, nil)
	var agentOut bytes.Buffer
	p.agentWriter = NewFrameWriter(&agentOut)
	rt := &SessionRuntime{
		Session:  NewSession(),
		pending:  map[string]*pendingCall{},
		syncWait: map[string]chan []byte{"1": make(chan []byte, 1)},
	}
	sc := &serverConn{proc: &ServerProcess{ID: "s", PID: 1}}

	done := make(chan struct{})
	go func() {
		p.deliverServerFrame(rt, sc, []byte(`{"jsonrpc":"2.0","id":1,"result":{"n":1}}`))
		p.deliverServerFrame(rt, sc, []byte(`{"jsonrpc":"2.0","id":1,"result":{"n":2}}`))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reader goroutine wedged on duplicate response")
	}
	if !strings.Contains(agentOut.String(), `"n":2`) {
		t.Fatalf("duplicate response not passed to agent writer: %q", agentOut.String())
	}
}

func TestReplaceToolCallArguments(t *testing.T) {
	frame := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_message","arguments":{"body":"ilk.vault.abc"}}}`)
	args := json.RawMessage(`{"body":"sk-live-REALSECRET0000000000000000"}`)
	out, err := replaceToolCallArguments(frame, args)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "ilk.vault.abc") {
		t.Fatalf("dummy still present: %s", out)
	}
	if !strings.Contains(string(out), "sk-live-REALSECRET") {
		t.Fatalf("real secret missing: %s", out)
	}
	var msg map[string]any
	if err := json.Unmarshal(out, &msg); err != nil {
		t.Fatal(err)
	}
	params := msg["params"].(map[string]any)
	if params["name"] != "send_message" {
		t.Fatalf("tool name lost: %v", params["name"])
	}
}
