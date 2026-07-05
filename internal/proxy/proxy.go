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
	"github.com/yxshwanth/Interlock/internal/engine"
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

// pendingCall tracks an in-flight tools/call so the response can be
// attributed to the correct server and tool.
type pendingCall struct {
	sc       *serverConn
	toolName string
}

// Proxy is the multi-server MCP proxy. It launches all configured servers,
// initializes them, builds a tool routing table, and dispatches agent
// requests to the correct server.
type Proxy struct {
	cfg             *config.Config
	logger          *EventLogger
	engine          *engine.Engine
	log             *log.Logger
	servers         map[string]*serverConn
	toolRoute       map[string]*serverConn   // tool name -> server
	allTools        []json.RawMessage        // merged tool list
	session         *Session
	agentWriter     *FrameWriter
	pending         map[string]*pendingCall  // stringified request ID -> pending call info
	syncWait        map[string]chan []byte   // synchronous HTTP (or in-flight) response waiters
	mu              sync.Mutex
	onServersReady  func(childPIDs []int)    // called after all servers are launched
}

// New creates a Proxy from the given config.
// Pass nil for logger to disable JSONL logging.
// Pass nil for eng to disable enforcement (Week 1 passthrough mode).
func New(cfg *config.Config, logger *EventLogger, eng *engine.Engine) *Proxy {
	return &Proxy{
		cfg:       cfg,
		logger:    logger,
		engine:    eng,
		log:       log.New(os.Stderr, "[interlock] ", log.LstdFlags),
		servers:   make(map[string]*serverConn),
		toolRoute: make(map[string]*serverConn),
		pending:   make(map[string]*pendingCall),
		syncWait:  make(map[string]chan []byte),
	}
}

// OnServersReady registers a callback that fires after all child servers
// are launched and initialized but before the dispatch loop begins.
// The callback receives the list of child PIDs.
func (p *Proxy) OnServersReady(fn func(childPIDs []int)) {
	p.onServersReady = fn
}

// ChildPIDs returns the PIDs of all launched child server processes.
func (p *Proxy) ChildPIDs() []int {
	pids := make([]int, 0, len(p.servers))
	for _, sc := range p.servers {
		pids = append(pids, sc.proc.PID)
	}
	return pids
}

func (p *Proxy) logEvent(ev model.InterceptedEvent) {
	if p.engine != nil {
		p.engine.RedactEvent(&ev)
	}
	if p.logger != nil {
		p.logger.Log(ev)
	} else {
		logEventStderr(ev)
	}
}

// Run starts all servers and runs the STDIO agent transport loop.
func (p *Proxy) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p.session = NewSession()
	p.log.Printf("session %s started", p.session.ID)
	if p.engine == nil {
		p.log.Printf("[SECURITY] engine not configured — all calls forwarded without enforcement (FAIL-OPEN)")
	}
	p.agentWriter = NewFrameWriter(os.Stdout)

	if err := p.startServers(ctx); err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.readAgentFrames(ctx)
		cancel()
	}()

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

	os.Stdin.Close()
	p.stopServers()
	wg.Wait()
	return nil
}

// Start launches backend servers and background readers without binding agent I/O.
// Used by HTTP transport mode.
func (p *Proxy) Start(ctx context.Context) error {
	if p.session == nil {
		p.session = NewSession()
		p.log.Printf("session %s started", p.session.ID)
	}
	if p.engine == nil {
		p.log.Printf("[SECURITY] engine not configured — all calls forwarded without enforcement (FAIL-OPEN)")
	}
	return p.startServers(ctx)
}

// Session returns the active Interlock session (for HTTP session binding).
func (p *Proxy) Session() *Session {
	return p.session
}

// SetSession binds an Interlock session (HTTP MCP session reuse).
func (p *Proxy) SetSession(s *Session) {
	p.session = s
}

func (p *Proxy) startServers(ctx context.Context) error {
	for _, sc := range p.cfg.Servers {
		if err := p.startAndInit(ctx, sc); err != nil {
			return err
		}
	}

	p.log.Printf("all servers initialized, %d tools available", len(p.allTools))

	if p.onServersReady != nil {
		p.onServersReady(p.ChildPIDs())
	}

	for _, sc := range p.servers {
		go p.readServerFrames(ctx, sc)
		go copyStderr(sc.proc.ID, sc.proc.Stderr)
	}
	return nil
}

func (p *Proxy) stopServers() {
	for _, sc := range p.servers {
		sc.proc.Stop()
	}
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

		result, err := p.HandleAgentRequest(ctx, frame)
		if err != nil {
			p.log.Printf("dispatch error: %v", err)
			continue
		}
		if result.IsNotification {
			continue
		}
		if len(result.Response) > 0 {
			p.agentWriter.WriteFrame(result.Response)
		}
	}
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

		p.deliverServerFrame(sc, frame)
	}
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
