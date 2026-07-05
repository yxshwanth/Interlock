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
	UseSSE         bool
	Blocked        bool
}

// HandleAgentRequest processes one JSON-RPC frame for session rt.
func (p *Proxy) HandleAgentRequest(ctx context.Context, rt *SessionRuntime, frame []byte) (*DispatchResult, error) {
	if rt == nil {
		return nil, fmt.Errorf("session runtime required")
	}
	rt.touch()
	p.sessions.Touch(rt.Session.ID)

	var msg model.JSONRPCMessage
	if err := json.Unmarshal(frame, &msg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	sess := rt.Session

	if msg.IsNotification() {
		ev := sess.CreateEvent(frame, model.AgentToServer, "proxy", 0)
		p.logEvent(ev)
		return &DispatchResult{IsNotification: true}, nil
	}

	switch msg.Method {
	case "initialize":
		return p.dispatchInitialize(rt, frame, msg), nil
	case "tools/list":
		return p.dispatchToolsList(rt, frame, msg), nil
	case "tools/call":
		return p.dispatchToolsCall(ctx, rt, frame, msg)
	case "ping":
		return p.dispatchPing(rt, frame, msg), nil
	default:
		ev := sess.CreateEvent(frame, model.AgentToServer, "proxy", 0)
		p.logEvent(ev)
		data := p.buildErrorResponse(msg.ID, -32601, fmt.Sprintf("method not found: %s", msg.Method))
		return &DispatchResult{Response: data}, nil
	}
}

func (p *Proxy) dispatchInitialize(rt *SessionRuntime, frame []byte, msg model.JSONRPCMessage) *DispatchResult {
	sess := rt.Session
	ev := sess.CreateEvent(frame, model.AgentToServer, "proxy", 0)
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
	respEv := sess.CreateEvent(data, model.ServerToAgent, "proxy", 0)
	p.logEvent(respEv)
	return &DispatchResult{Response: data}
}

func (p *Proxy) dispatchToolsList(rt *SessionRuntime, frame []byte, msg model.JSONRPCMessage) *DispatchResult {
	sess := rt.Session
	ev := sess.CreateEvent(frame, model.AgentToServer, "proxy", 0)
	p.logEvent(ev)

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(msg.ID),
		"result": map[string]any{
			"tools": rt.allToolsAsAny(),
		},
	}
	data, _ := json.Marshal(resp)
	respEv := sess.CreateEvent(data, model.ServerToAgent, "proxy", 0)
	p.logEvent(respEv)
	return &DispatchResult{Response: data}
}

func (p *Proxy) dispatchPing(rt *SessionRuntime, frame []byte, msg model.JSONRPCMessage) *DispatchResult {
	sess := rt.Session
	ev := sess.CreateEvent(frame, model.AgentToServer, "proxy", 0)
	p.logEvent(ev)

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(msg.ID),
		"result":  map[string]any{},
	}
	data, _ := json.Marshal(resp)
	respEv := sess.CreateEvent(data, model.ServerToAgent, "proxy", 0)
	p.logEvent(respEv)
	return &DispatchResult{Response: data}
}

func (p *Proxy) dispatchToolsCall(ctx context.Context, rt *SessionRuntime, frame []byte, msg model.JSONRPCMessage) (*DispatchResult, error) {
	sess := rt.Session
	var tc model.ToolCallParams
	if len(msg.Params) > 0 {
		tc, _ = model.ParseToolCallParams(msg.Params)
	}

	sc, ok := rt.toolRoute[tc.Name]
	if !ok {
		ev := sess.CreateEvent(frame, model.AgentToServer, "proxy", 0)
		p.logEvent(ev)
		data := p.buildErrorResponse(msg.ID, -32602, fmt.Sprintf("unknown tool: %s", tc.Name))
		return &DispatchResult{Response: data, Blocked: true}, nil
	}

	ev := sess.CreateEvent(frame, model.AgentToServer, sc.proc.ID, sc.proc.PID)

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
	rt.mu.Lock()
	rt.pending[idKey] = &pendingCall{sc: sc, toolName: tc.Name}
	rt.syncWait[idKey] = ch
	rt.mu.Unlock()

	defer func() {
		rt.mu.Lock()
		delete(rt.syncWait, idKey)
		delete(rt.pending, idKey)
		rt.mu.Unlock()
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

func (p *Proxy) deliverServerFrame(rt *SessionRuntime, sc *serverConn, frame []byte) {
	sess := rt.Session
	ev := sess.CreateEvent(frame, model.ServerToAgent, sc.proc.ID, sc.proc.PID)

	var msg model.JSONRPCMessage
	var idKey string
	if json.Unmarshal(frame, &msg) == nil && msg.IsResponse() {
		idKey = string(msg.ID)
		rt.mu.Lock()
		if pc, ok := rt.pending[idKey]; ok {
			ev.ToolName = pc.toolName
		}
		rt.mu.Unlock()
	}

	if p.engine != nil && ev.ToolName != "" {
		p.engine.IngestResult(ev)
	}
	p.logEvent(ev)

	if idKey != "" {
		rt.mu.Lock()
		ch := rt.syncWait[idKey]
		rt.mu.Unlock()
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
