package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

// DispatchResult is the outcome of handling one agent JSON-RPC frame.
type DispatchResult struct {
	Response       []byte
	IsNotification bool
	UseSSE         bool // caller may encode Response as SSE (inspect-then-forward already applied)
	Blocked        bool // blocked tools/call — must use JSON, not SSE
}

// HandleAgentRequest processes one JSON-RPC frame from the agent synchronously.
// For tools/call it waits for the backend response (inspect-then-forward).
func (p *Proxy) HandleAgentRequest(ctx context.Context, frame []byte) (*DispatchResult, error) {
	if p.session == nil {
		return nil, fmt.Errorf("proxy not started")
	}

	var msg model.JSONRPCMessage
	if err := json.Unmarshal(frame, &msg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if msg.IsNotification() {
		ev := p.session.CreateEvent(frame, model.AgentToServer, "proxy", 0)
		p.logEvent(ev)
		return &DispatchResult{IsNotification: true}, nil
	}

	switch msg.Method {
	case "initialize":
		return p.dispatchInitialize(frame, msg), nil
	case "tools/list":
		return p.dispatchToolsList(frame, msg), nil
	case "tools/call":
		return p.dispatchToolsCall(ctx, frame, msg)
	case "ping":
		return p.dispatchPing(frame, msg), nil
	default:
		ev := p.session.CreateEvent(frame, model.AgentToServer, "proxy", 0)
		p.logEvent(ev)
		data := p.buildErrorResponse(msg.ID, -32601, fmt.Sprintf("method not found: %s", msg.Method))
		return &DispatchResult{Response: data}, nil
	}
}

func (p *Proxy) dispatchInitialize(frame []byte, msg model.JSONRPCMessage) *DispatchResult {
	ev := p.session.CreateEvent(frame, model.AgentToServer, "proxy", 0)
	p.logEvent(ev)

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(msg.ID),
		"result": map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "interlock",
				"version": "0.2.0",
			},
		},
	}
	data, _ := json.Marshal(resp)
	respEv := p.session.CreateEvent(data, model.ServerToAgent, "proxy", 0)
	p.logEvent(respEv)
	return &DispatchResult{Response: data}
}

func (p *Proxy) dispatchToolsList(frame []byte, msg model.JSONRPCMessage) *DispatchResult {
	ev := p.session.CreateEvent(frame, model.AgentToServer, "proxy", 0)
	p.logEvent(ev)

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(msg.ID),
		"result": map[string]any{
			"tools": p.allToolsAsAny(),
		},
	}
	data, _ := json.Marshal(resp)
	respEv := p.session.CreateEvent(data, model.ServerToAgent, "proxy", 0)
	p.logEvent(respEv)
	return &DispatchResult{Response: data}
}

func (p *Proxy) dispatchPing(frame []byte, msg model.JSONRPCMessage) *DispatchResult {
	ev := p.session.CreateEvent(frame, model.AgentToServer, "proxy", 0)
	p.logEvent(ev)

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(msg.ID),
		"result":  map[string]any{},
	}
	data, _ := json.Marshal(resp)
	respEv := p.session.CreateEvent(data, model.ServerToAgent, "proxy", 0)
	p.logEvent(respEv)
	return &DispatchResult{Response: data}
}

func (p *Proxy) dispatchToolsCall(ctx context.Context, frame []byte, msg model.JSONRPCMessage) (*DispatchResult, error) {
	var tc model.ToolCallParams
	if len(msg.Params) > 0 {
		tc, _ = model.ParseToolCallParams(msg.Params)
	}

	sc, ok := p.toolRoute[tc.Name]
	if !ok {
		ev := p.session.CreateEvent(frame, model.AgentToServer, "proxy", 0)
		p.logEvent(ev)
		data := p.buildErrorResponse(msg.ID, -32602, fmt.Sprintf("unknown tool: %s", tc.Name))
		return &DispatchResult{Response: data, Blocked: true}, nil
	}

	ev := p.session.CreateEvent(frame, model.AgentToServer, sc.proc.ID, sc.proc.PID)

	if p.engine != nil {
		var decision model.Decision
		func() {
			defer func() {
				if r := recover(); r != nil {
					p.log.Printf("[SECURITY] engine panic during EvaluateRequest — FAIL-OPEN, call forwarded: %v", r)
					decision = model.Decision{Allow: true}
				}
			}()
			decision = p.engine.EvaluateRequest(ev)
		}()
		if !decision.Allow {
			ev.Decision = "blocked"
			ev.BlockReason = decision.Reason
			p.logEvent(ev)
			data := p.buildErrorResponse(msg.ID, -32000,
				fmt.Sprintf("call blocked by Interlock: %s", decision.Reason))
			return &DispatchResult{Response: data, Blocked: true}, nil
		}
	}

	p.logEvent(ev)

	idKey := string(msg.ID)
	ch := make(chan []byte, 1)
	p.mu.Lock()
	p.pending[idKey] = &pendingCall{sc: sc, toolName: tc.Name}
	p.syncWait[idKey] = ch
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.syncWait, idKey)
		delete(p.pending, idKey)
		p.mu.Unlock()
	}()

	if err := sc.writer.WriteFrame(frame); err != nil {
		return nil, fmt.Errorf("forward to server %s: %w", sc.proc.ID, err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	select {
	case resp := <-ch:
		useSSE := p.cfg.Transport.PreferSSEResponses
		return &DispatchResult{Response: resp, UseSSE: useSSE}, nil
	case <-waitCtx.Done():
		return nil, fmt.Errorf("timeout waiting for server response: %w", waitCtx.Err())
	}
}

func (p *Proxy) buildErrorResponse(id json.RawMessage, code int, message string) []byte {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
	data, _ := json.Marshal(resp)
	return data
}

func (p *Proxy) deliverServerFrame(sc *serverConn, frame []byte) {
	ev := p.session.CreateEvent(frame, model.ServerToAgent, sc.proc.ID, sc.proc.PID)

	var msg model.JSONRPCMessage
	var idKey string
	if json.Unmarshal(frame, &msg) == nil && msg.IsResponse() {
		idKey = string(msg.ID)
		p.mu.Lock()
		if pc, ok := p.pending[idKey]; ok {
			ev.ToolName = pc.toolName
		}
		p.mu.Unlock()
	}

	if p.engine != nil && ev.ToolName != "" {
		p.engine.IngestResult(ev)
	}
	p.logEvent(ev)

	if idKey != "" {
		p.mu.Lock()
		ch := p.syncWait[idKey]
		p.mu.Unlock()
		if ch != nil {
			select {
			case ch <- frame:
				return
			}
		}
	}

	if p.agentWriter != nil {
		if err := p.agentWriter.WriteFrame(frame); err != nil {
			p.log.Printf("error writing to agent: %v", err)
		}
	}
}
