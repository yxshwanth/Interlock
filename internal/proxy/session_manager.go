package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

// PIDHooks notifies when child PIDs should be added/removed from eBPF watch.
type PIDHooks struct {
	OnWatch   func(pids []int)
	OnUnwatch func(pids []int)
}

// SessionRuntime is an isolated agent session with its own backend server pool.
type SessionRuntime struct {
	Session      *Session
	servers      map[string]*serverConn
	toolRoute    map[string]*serverConn
	allTools     []json.RawMessage
	shadowEvents []model.ShadowEvent
	pending      map[string]*pendingCall
	syncWait     map[string]chan []byte
	mu           sync.Mutex
	createdAt    time.Time
	lastActivity time.Time
	registered   []registeredPID
}

type registeredPID struct {
	pid         int
	startTimeNs uint64
	serverID    string
}

// SessionManager owns concurrent session runtimes and MCP session bindings.
type SessionManager struct {
	cfg         *config.Config
	log         *log.Logger
	proxy       *Proxy
	pidRegistry *PIDRegistry
	pidHooks    PIDHooks
	ctx         context.Context
	mu          sync.RWMutex
	runtimes    map[string]*SessionRuntime
	mcpSessions map[string]string
}

// NewSessionManager creates a session manager for p.
func NewSessionManager(p *Proxy, cfg *config.Config, log *log.Logger, reg *PIDRegistry) *SessionManager {
	return &SessionManager{
		cfg:         cfg,
		log:         log,
		proxy:       p,
		pidRegistry: reg,
		runtimes:    make(map[string]*SessionRuntime),
		mcpSessions: make(map[string]string),
	}
}

// SetPIDHooks registers eBPF PID watch/unwatch callbacks.
func (sm *SessionManager) SetPIDHooks(hooks PIDHooks) {
	sm.pidHooks = hooks
}

// Create spawns backend servers for a new Interlock session.
func (sm *SessionManager) Create(session *Session) (*SessionRuntime, error) {
	ctx := sm.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	sm.mu.Lock()
	if sm.cfg.Sessions.MaxConcurrent > 0 && len(sm.runtimes) >= sm.cfg.Sessions.MaxConcurrent {
		sm.mu.Unlock()
		return nil, fmt.Errorf("max concurrent sessions (%d) reached", sm.cfg.Sessions.MaxConcurrent)
	}
	sm.mu.Unlock()

	rt := &SessionRuntime{
		Session:      session,
		servers:      make(map[string]*serverConn),
		toolRoute:    make(map[string]*serverConn),
		pending:      make(map[string]*pendingCall),
		syncWait:     make(map[string]chan []byte),
		createdAt:    time.Now(),
		lastActivity: time.Now(),
	}

	for _, srvCfg := range sm.cfg.Servers {
		if err := sm.startAndInit(ctx, rt, srvCfg); err != nil {
			sm.stopRuntime(rt)
			return nil, err
		}
	}

	sm.emitToolShadowing(rt)

	sm.mu.Lock()
	sm.runtimes[session.ID] = rt
	sm.mu.Unlock()

	sm.log.Printf("session %s ready (%d tools, %d servers)", session.ID, len(rt.allTools), len(rt.servers))
	sm.watchRuntimePIDs(rt)
	return rt, nil
}

// CreateMCP binds a new MCP session ID to a fresh Interlock session runtime.
func (sm *SessionManager) CreateMCP(mcpSessionID string) (*SessionRuntime, error) {
	session := NewSession()
	rt, err := sm.Create(session)
	if err != nil {
		return nil, err
	}
	sm.mu.Lock()
	sm.mcpSessions[mcpSessionID] = session.ID
	sm.mu.Unlock()
	return rt, nil
}

// Get returns a session runtime by Interlock session ID.
func (sm *SessionManager) Get(sessionID string) (*SessionRuntime, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	rt, ok := sm.runtimes[sessionID]
	return rt, ok
}

// GetByMCP returns a runtime for an MCP session header value.
func (sm *SessionManager) GetByMCP(mcpSessionID string) (*SessionRuntime, bool) {
	sm.mu.RLock()
	interlockID, ok := sm.mcpSessions[mcpSessionID]
	sm.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return sm.Get(interlockID)
}

// Touch updates last-activity for idle expiry.
func (sm *SessionManager) Touch(sessionID string) {
	sm.mu.RLock()
	rt, ok := sm.runtimes[sessionID]
	sm.mu.RUnlock()
	if ok {
		rt.mu.Lock()
		rt.lastActivity = time.Now()
		rt.mu.Unlock()
	}
}

// Cleanup tears down a session and its server pool.
func (sm *SessionManager) Cleanup(sessionID string) {
	sm.mu.Lock()
	rt, ok := sm.runtimes[sessionID]
	if ok {
		delete(sm.runtimes, sessionID)
	}
	for mcpID, sid := range sm.mcpSessions {
		if sid == sessionID {
			delete(sm.mcpSessions, mcpID)
		}
	}
	sm.mu.Unlock()
	if !ok {
		return
	}
	sm.unwatchRuntimePIDs(rt)
	sm.stopRuntime(rt)
	sm.log.Printf("session %s cleaned up", sessionID)
}

// StartIdleSweeper evicts sessions past idle_timeout and binds manager lifetime.
func (sm *SessionManager) StartIdleSweeper(ctx context.Context) {
	sm.ctx = ctx
	timeout := sm.cfg.Sessions.IdleTimeoutDuration()
	if timeout <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sm.expireIdle(timeout)
			}
		}
	}()
}

func (sm *SessionManager) expireIdle(maxAge time.Duration) {
	now := time.Now()
	var expired []string

	sm.mu.RLock()
	for id, rt := range sm.runtimes {
		rt.mu.Lock()
		idle := now.Sub(rt.lastActivity)
		rt.mu.Unlock()
		if idle > maxAge {
			expired = append(expired, id)
		}
	}
	sm.mu.RUnlock()

	for _, id := range expired {
		sm.log.Printf("session %s expired (idle > %s)", id, maxAge)
		sm.Cleanup(id)
	}
}

func (sm *SessionManager) startAndInit(ctx context.Context, rt *SessionRuntime, cfg config.ServerConfig) error {
	sm.log.Printf("starting server %q for session %s: %s %v", cfg.ID, rt.Session.ID, cfg.Command, cfg.Args)

	proc, err := StartServer(ctx, cfg)
	if err != nil {
		return fmt.Errorf("starting server %s: %w", cfg.ID, err)
	}

	sc := &serverConn{
		proc:   proc,
		reader: NewFrameReader(proc.Stdout),
		writer: NewFrameWriter(proc.Stdin),
		cfg:    cfg,
		rt:     rt,
	}
	rt.servers[cfg.ID] = sc
	sm.log.Printf("server %q started for session %s (pid=%d)", cfg.ID, rt.Session.ID, proc.PID)

	startNs, err := ProcessStartTimeNs(proc.PID)
	if err != nil {
		startNs = uint64(time.Now().UnixNano())
	}
	rt.registered = append(rt.registered, registeredPID{
		pid:         proc.PID,
		startTimeNs: startNs,
		serverID:    cfg.ID,
	})
	sm.pidRegistry.Register(proc.PID, startNs, rt.Session.ID, cfg.ID)

	initReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      fmt.Sprintf("interlock-init-%s-%s", rt.Session.ID, cfg.ID),
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "interlock",
				"version": "0.2.0",
			},
		},
	}
	if err := sm.proxy.sendJSON(sc.writer, initReq); err != nil {
		return fmt.Errorf("server %s: initialize send: %w", cfg.ID, err)
	}
	if _, err := sc.reader.ReadFrame(); err != nil {
		return fmt.Errorf("server %s: initialize response: %w", cfg.ID, err)
	}

	notif := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	if err := sm.proxy.sendJSON(sc.writer, notif); err != nil {
		return fmt.Errorf("server %s: initialized notification: %w", cfg.ID, err)
	}

	listReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      fmt.Sprintf("interlock-tools-%s-%s", rt.Session.ID, cfg.ID),
		"method":  "tools/list",
		"params":  map[string]any{},
	}
	if err := sm.proxy.sendJSON(sc.writer, listReq); err != nil {
		return fmt.Errorf("server %s: tools/list send: %w", cfg.ID, err)
	}
	toolsFrame, err := sc.reader.ReadFrame()
	if err != nil {
		return fmt.Errorf("server %s: tools/list response: %w", cfg.ID, err)
	}

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
		if rt.registerTool(td.Name, rt.Session.ID, sc, raw) {
			sm.log.Printf("  registered tool %q from server %q (session %s)", td.Name, cfg.ID, rt.Session.ID)
		} else {
			owner := rt.toolRoute[td.Name].cfg.ID
			sm.log.Printf("[SECURITY] tool shadowing detected: server %q attempted to register tool %q, already owned by server %q — registration refused, route unchanged",
				cfg.ID, td.Name, owner)
		}
	}

	go sm.proxy.readServerFrames(ctx, rt, sc)
	go copyStderr(cfg.ID, sc.proc.Stderr)
	return nil
}

// registerTool implements first-owner-wins tool routing. On conflict it records
// a ShadowEvent and leaves the existing route / aggregated tools list unchanged.
// Returns true if the tool was newly registered.
func (rt *SessionRuntime) registerTool(name, sessionID string, sc *serverConn, raw json.RawMessage) bool {
	if existing, conflict := rt.toolRoute[name]; conflict {
		rt.shadowEvents = append(rt.shadowEvents, model.ShadowEvent{
			ToolName:       name,
			OwnerServerID:  existing.cfg.ID,
			ShadowServerID: sc.cfg.ID,
			SessionID:      sessionID,
		})
		return false
	}
	rt.toolRoute[name] = sc
	sc.tools = append(sc.tools, raw)
	rt.allTools = append(rt.allTools, raw)
	return true
}

func (sm *SessionManager) emitToolShadowing(rt *SessionRuntime) {
	if len(rt.shadowEvents) == 0 || sm.proxy == nil || sm.proxy.engine == nil {
		return
	}
	for _, ev := range rt.shadowEvents {
		sm.proxy.engine.RecordToolShadowing(ev)
	}
}

func (sm *SessionManager) watchRuntimePIDs(rt *SessionRuntime) {
	if sm.pidHooks.OnWatch == nil || len(rt.registered) == 0 {
		return
	}
	pids := make([]int, len(rt.registered))
	for i, r := range rt.registered {
		pids[i] = r.pid
	}
	sm.pidHooks.OnWatch(pids)
}

func (sm *SessionManager) unwatchRuntimePIDs(rt *SessionRuntime) {
	for _, r := range rt.registered {
		sm.pidRegistry.Unregister(r.pid, r.startTimeNs)
	}
	if sm.pidHooks.OnUnwatch == nil || len(rt.registered) == 0 {
		return
	}
	pids := make([]int, len(rt.registered))
	for i, r := range rt.registered {
		pids[i] = r.pid
	}
	sm.pidHooks.OnUnwatch(pids)
}

func (sm *SessionManager) stopRuntime(rt *SessionRuntime) {
	for _, sc := range rt.servers {
		sc.proc.Stop()
	}
}

func (rt *SessionRuntime) allToolsAsAny() []any {
	out := make([]any, len(rt.allTools))
	for i, raw := range rt.allTools {
		var v any
		json.Unmarshal(raw, &v)
		out[i] = v
	}
	return out
}

func (rt *SessionRuntime) touch() {
	rt.mu.Lock()
	rt.lastActivity = time.Now()
	rt.mu.Unlock()
}
