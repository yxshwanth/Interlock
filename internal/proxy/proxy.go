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
	tools  []json.RawMessage
	rt     *SessionRuntime
}

// pendingCall tracks an in-flight tools/call so the response can be
// attributed to the correct server and tool.
type pendingCall struct {
	sc       *serverConn
	toolName string
}

// Proxy is the multi-server MCP proxy with per-session backend pools.
type Proxy struct {
	cfg         *config.Config
	logger      *EventLogger
	engine      *engine.Engine
	log         *log.Logger
	sessions    *SessionManager
	pidRegistry *PIDRegistry
	agentWriter *FrameWriter
	stdioRT     *SessionRuntime
	mu          sync.Mutex
}

// New creates a Proxy from the given config.
func New(cfg *config.Config, logger *EventLogger, eng *engine.Engine) *Proxy {
	log := log.New(os.Stderr, "[interlock] ", log.LstdFlags)
	p := &Proxy{
		cfg:         cfg,
		logger:      logger,
		engine:      eng,
		log:         log,
		pidRegistry: NewPIDRegistry(),
	}
	p.sessions = NewSessionManager(p, cfg, log, p.pidRegistry)
	return p
}

// Sessions returns the session manager.
func (p *Proxy) Sessions() *SessionManager {
	return p.sessions
}

// PIDRegistry returns the PID→session registry.
func (p *Proxy) PIDRegistry() *PIDRegistry {
	return p.pidRegistry
}

// SetPIDHooks registers eBPF watch/unwatch callbacks on the session manager.
func (p *Proxy) SetPIDHooks(hooks PIDHooks) {
	p.sessions.SetPIDHooks(hooks)
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

// Run starts a single STDIO session and runs the agent transport loop.
func (p *Proxy) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if p.engine == nil {
		p.log.Printf("[SECURITY] engine not configured — all calls forwarded without enforcement (FAIL-OPEN)")
	}

	rt, err := p.StartStdioSession(ctx)
	if err != nil {
		return err
	}
	p.stdioRT = rt
	p.log.Printf("session %s started (stdio)", rt.Session.ID)

	p.agentWriter = NewFrameWriter(os.Stdout)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.readAgentFrames(ctx, rt)
		cancel()
	}()

	serverDone := make(chan string, len(rt.servers))
	for _, sc := range rt.servers {
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
	p.sessions.Cleanup(rt.Session.ID)
	wg.Wait()
	return nil
}

// StartHTTP prepares multi-session HTTP mode (idle sweeper, no global servers).
func (p *Proxy) StartHTTP(ctx context.Context) error {
	if p.engine == nil {
		p.log.Printf("[SECURITY] engine not configured — all calls forwarded without enforcement (FAIL-OPEN)")
	}
	p.sessions.StartIdleSweeper(ctx)
	return nil
}

// StartStdioSession creates the single STDIO session runtime.
func (p *Proxy) StartStdioSession(ctx context.Context) (*SessionRuntime, error) {
	p.sessions.StartIdleSweeper(ctx)
	return p.sessions.Create(NewSession())
}

func (p *Proxy) sendJSON(fw *FrameWriter, msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return fw.WriteFrame(data)
}

func (p *Proxy) readAgentFrames(ctx context.Context, rt *SessionRuntime) {
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

		result, err := p.HandleAgentRequest(ctx, rt, frame)
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

func (p *Proxy) readServerFrames(ctx context.Context, rt *SessionRuntime, sc *serverConn) {
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

		p.deliverServerFrame(rt, sc, frame)
	}
}

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
