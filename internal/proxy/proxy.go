package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

// Session tracks per-session state for InterceptedEvent creation.
type Session struct {
	ID        string
	seq       atomic.Uint64
	startMono int64
}

// NewSession creates a session with a random hex ID.
func NewSession() *Session {
	b := make([]byte, 8)
	rand.Read(b)
	return &Session{
		ID:        hex.EncodeToString(b),
		startMono: time.Now().UnixNano(),
	}
}

// CreateEvent builds an InterceptedEvent from a raw JSON-RPC frame.
func (s *Session) CreateEvent(raw []byte, dir model.Direction, serverID string, serverPID int) model.InterceptedEvent {
	seq := s.seq.Add(1)
	now := time.Now()

	ev := model.InterceptedEvent{
		SessionID: s.ID,
		Seq:       seq,
		TSWall:    now,
		TSMono:    now.UnixNano(),
		Direction: dir,
		ServerID:  serverID,
		ServerPID: serverPID,
		Decision:  "forwarded",
	}

	var msg model.JSONRPCMessage
	if err := json.Unmarshal(raw, &msg); err == nil {
		ev.Method = msg.Method

		if msg.Method == "tools/call" && len(msg.Params) > 0 {
			if tc, err := model.ParseToolCallParams(msg.Params); err == nil {
				ev.ToolName = tc.Name
				ev.ToolArgs = tc.Arguments
			}
		}

		if msg.IsResponse() {
			ev.Result = msg.Result
		}
	}

	return ev
}

// serverConn wraps a running MCP server process and its frame I/O.
type serverConn struct {
	proc   *ServerProcess
	reader *FrameReader
	writer *FrameWriter
	cfg    config.ServerConfig
	tools  []json.RawMessage // raw tool definitions from tools/list
}

// Proxy is the multi-server MCP proxy. It launches all configured servers,
// initializes them, builds a tool routing table, and dispatches agent
// requests to the correct server.
type Proxy struct {
	cfg         *config.Config
	logger      *EventLogger
	log         *log.Logger
	servers     map[string]*serverConn
	toolRoute   map[string]*serverConn   // tool name -> server
	allTools    []json.RawMessage        // merged tool list
	session     *Session
	agentWriter *FrameWriter
	pending     map[string]*serverConn   // stringified request ID -> server
	mu          sync.Mutex
}

// New creates a Proxy from the given config. Pass nil for logger to disable JSONL logging.
func New(cfg *config.Config, logger *EventLogger) *Proxy {
	return &Proxy{
		cfg:       cfg,
		logger:    logger,
		log:       log.New(os.Stderr, "[interlock] ", log.LstdFlags),
		servers:   make(map[string]*serverConn),
		toolRoute: make(map[string]*serverConn),
		pending:   make(map[string]*serverConn),
	}
}

func (p *Proxy) logEvent(ev model.InterceptedEvent) {
	if p.logger != nil {
		p.logger.Log(ev)
	} else {
		logEventStderr(ev)
	}
}

// Run starts all servers, initializes them, and runs the proxy dispatch loop.
func (p *Proxy) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p.session = NewSession()
	p.log.Printf("session %s started", p.session.ID)
	p.agentWriter = NewFrameWriter(os.Stdout)

	// Launch and initialize all servers.
	for _, sc := range p.cfg.Servers {
		if err := p.startAndInit(ctx, sc); err != nil {
			return err
		}
	}

	p.log.Printf("all servers initialized, %d tools available", len(p.allTools))

	var wg sync.WaitGroup

	// Per-server: read responses and forward to agent.
	for _, sc := range p.servers {
		wg.Add(1)
		go func(sc *serverConn) {
			defer wg.Done()
			p.readServerFrames(ctx, sc)
		}(sc)

		// stderr passthrough
		wg.Add(1)
		go func(sc *serverConn) {
			defer wg.Done()
			copyStderr(sc.proc.ID, sc.proc.Stderr)
		}(sc)
	}

	// Read agent frames and dispatch.
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.readAgentFrames(ctx)
		cancel()
	}()

	// Wait for any server to exit.
	serverDone := make(chan string, len(p.servers))
	for _, sc := range p.servers {
		go func(sc *serverConn) {
			sc.proc.Wait()
			serverDone <- sc.proc.ID
		}(sc)
	}

	select {
	case id := <-serverDone:
		p.log.Printf("server %q exited, shutting down", id)
		cancel()
	case <-ctx.Done():
		p.log.Printf("shutting down (context cancelled)")
	}

	// Stop all servers.
	for _, sc := range p.servers {
		sc.proc.Stop()
	}

	wg.Wait()
	return nil
}

// startAndInit launches a server, sends initialize + notifications/initialized,
// queries tools/list, and populates the routing table.
func (p *Proxy) startAndInit(ctx context.Context, cfg config.ServerConfig) error {
	p.log.Printf("starting server %q: %s %v", cfg.ID, cfg.Command, cfg.Args)

	proc, err := StartServer(ctx, cfg)
	if err != nil {
		return fmt.Errorf("starting server %s: %w", cfg.ID, err)
	}

	sc := &serverConn{
		proc:   proc,
		reader: NewFrameReader(proc.Stdout),
		writer: NewFrameWriter(proc.Stdin),
		cfg:    cfg,
	}
	p.servers[cfg.ID] = sc
	p.log.Printf("server %q started (pid=%d)", cfg.ID, proc.PID)

	// Send initialize.
	initReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      fmt.Sprintf("interlock-init-%s", cfg.ID),
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "interlock",
				"version": "0.1.0",
			},
		},
	}
	if err := p.sendJSON(sc.writer, initReq); err != nil {
		return fmt.Errorf("server %s: initialize send: %w", cfg.ID, err)
	}
	if _, err := sc.reader.ReadFrame(); err != nil {
		return fmt.Errorf("server %s: initialize response: %w", cfg.ID, err)
	}

	// Send notifications/initialized.
	notif := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	if err := p.sendJSON(sc.writer, notif); err != nil {
		return fmt.Errorf("server %s: initialized notification: %w", cfg.ID, err)
	}

	// Send tools/list.
	listReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      fmt.Sprintf("interlock-tools-%s", cfg.ID),
		"method":  "tools/list",
		"params":  map[string]any{},
	}
	if err := p.sendJSON(sc.writer, listReq); err != nil {
		return fmt.Errorf("server %s: tools/list send: %w", cfg.ID, err)
	}
	toolsFrame, err := sc.reader.ReadFrame()
	if err != nil {
		return fmt.Errorf("server %s: tools/list response: %w", cfg.ID, err)
	}

	// Parse tools/list result.
	var resp struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(toolsFrame, &resp); err != nil {
		return fmt.Errorf("server %s: parse tools/list: %w", cfg.ID, err)
	}

	for _, raw := range resp.Result.Tools {
		var td struct {
			Name string `json:"name"`
		}
		json.Unmarshal(raw, &td)
		p.toolRoute[td.Name] = sc
		sc.tools = append(sc.tools, raw)
		p.allTools = append(p.allTools, raw)
		p.log.Printf("  registered tool %q from server %q", td.Name, cfg.ID)
	}

	return nil
}

func (p *Proxy) sendJSON(fw *FrameWriter, msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return fw.WriteFrame(data)
}

// readAgentFrames reads from the agent's stdin and dispatches to servers.
func (p *Proxy) readAgentFrames(ctx context.Context) {
	agentReader := NewFrameReader(os.Stdin)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		frame, err := agentReader.ReadFrame()
		if err != nil {
			if err == io.EOF {
				p.log.Printf("agent closed stdin")
			}
			return
		}

		var msg model.JSONRPCMessage
		if err := json.Unmarshal(frame, &msg); err != nil {
			p.log.Printf("invalid JSON from agent: %v", err)
			continue
		}

		// Notifications: no response expected.
		if msg.IsNotification() {
			ev := p.session.CreateEvent(frame, model.AgentToServer, "proxy", 0)
			p.logEvent(ev)
			continue
		}

		switch msg.Method {
		case "initialize":
			p.handleInitialize(frame, msg)
		case "tools/list":
			p.handleToolsList(frame, msg)
		case "tools/call":
			p.handleToolsCall(frame, msg)
		case "ping":
			p.handlePing(frame, msg)
		default:
			ev := p.session.CreateEvent(frame, model.AgentToServer, "proxy", 0)
			p.logEvent(ev)
			p.sendAgentError(msg.ID, -32601, fmt.Sprintf("method not found: %s", msg.Method))
		}
	}
}

func (p *Proxy) handleInitialize(frame []byte, msg model.JSONRPCMessage) {
	ev := p.session.CreateEvent(frame, model.AgentToServer, "proxy", 0)
	p.logEvent(ev)

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(msg.ID),
		"result": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "interlock",
				"version": "0.1.0",
			},
		},
	}
	data, _ := json.Marshal(resp)
	respEv := p.session.CreateEvent(data, model.ServerToAgent, "proxy", 0)
	p.logEvent(respEv)
	p.agentWriter.WriteFrame(data)
}

func (p *Proxy) handleToolsList(frame []byte, msg model.JSONRPCMessage) {
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
	p.agentWriter.WriteFrame(data)
}

func (p *Proxy) allToolsAsAny() []any {
	out := make([]any, len(p.allTools))
	for i, raw := range p.allTools {
		var v any
		json.Unmarshal(raw, &v)
		out[i] = v
	}
	return out
}

func (p *Proxy) handleToolsCall(frame []byte, msg model.JSONRPCMessage) {
	var tc model.ToolCallParams
	if len(msg.Params) > 0 {
		tc, _ = model.ParseToolCallParams(msg.Params)
	}

	sc, ok := p.toolRoute[tc.Name]
	if !ok {
		ev := p.session.CreateEvent(frame, model.AgentToServer, "proxy", 0)
		p.logEvent(ev)
		p.sendAgentError(msg.ID, -32602, fmt.Sprintf("unknown tool: %s", tc.Name))
		return
	}

	ev := p.session.CreateEvent(frame, model.AgentToServer, sc.proc.ID, sc.proc.PID)
	p.logEvent(ev)

	// Track the pending request so we can attribute the response.
	idKey := string(msg.ID)
	p.mu.Lock()
	p.pending[idKey] = sc
	p.mu.Unlock()

	// Forward to the correct server.
	if err := sc.writer.WriteFrame(frame); err != nil {
		p.log.Printf("error forwarding to server %s: %v", sc.proc.ID, err)
	}
}

func (p *Proxy) handlePing(frame []byte, msg model.JSONRPCMessage) {
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
	p.agentWriter.WriteFrame(data)
}

func (p *Proxy) sendAgentError(id json.RawMessage, code int, message string) {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
	data, _ := json.Marshal(resp)
	p.agentWriter.WriteFrame(data)
}

// readServerFrames reads responses from a server and forwards them to the agent.
func (p *Proxy) readServerFrames(ctx context.Context, sc *serverConn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		frame, err := sc.reader.ReadFrame()
		if err != nil {
			if err != io.EOF {
				p.log.Printf("server %s read error: %v", sc.proc.ID, err)
			}
			return
		}

		ev := p.session.CreateEvent(frame, model.ServerToAgent, sc.proc.ID, sc.proc.PID)
		p.logEvent(ev)

		// Clean up pending tracking.
		var msg model.JSONRPCMessage
		if json.Unmarshal(frame, &msg) == nil && msg.IsResponse() {
			idKey := string(msg.ID)
			p.mu.Lock()
			delete(p.pending, idKey)
			p.mu.Unlock()
		}

		if err := p.agentWriter.WriteFrame(frame); err != nil {
			p.log.Printf("error writing to agent: %v", err)
			return
		}
	}
}

// copyStderr prefixes each line from the server's stderr and writes it
// to the proxy's stderr so the operator can see server-side logs.
func copyStderr(serverID string, r io.Reader) {
	fr := NewFrameReader(r)
	for {
		line, err := fr.ReadFrame()
		if err != nil {
			return
		}
		fmt.Fprintf(os.Stderr, "[%s:stderr] %s\n", serverID, line)
	}
}
