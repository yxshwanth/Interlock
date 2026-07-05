package mcphttp

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
	"github.com/yxshwanth/Interlock/internal/proxy"
)

// Server serves Streamable HTTP MCP (2025-11-25) for the proxy.
type Server struct {
	proxy   *proxy.Proxy
	cfg     *config.Config
	log     *log.Logger
	sessions *SessionStore
}

// NewServer creates an HTTP MCP front-end for p.
func NewServer(p *proxy.Proxy, cfg *config.Config, logger *log.Logger) *Server {
	return &Server{
		proxy:    p,
		cfg:      cfg,
		log:      logger,
		sessions: NewSessionStore(),
	}
}

// Handler returns the HTTP handler for MCP POST requests (for tests and embedding).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	endpoint := s.cfg.Transport.Endpoint
	mux.HandleFunc(endpoint, s.handleMCP)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != endpoint {
			http.NotFound(w, r)
		}
	})
	return mux
}

// ListenAndServe starts the HTTP MCP endpoint until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Transport.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	s.log.Printf("HTTP MCP listening on http://%s%s", s.cfg.Transport.Listen, s.cfg.Transport.Endpoint)
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	host := strings.Split(s.cfg.Transport.Listen, ":")[0]
	if err := ValidateOrigin(r, []string{host, "localhost", "127.0.0.1"}); err != nil {
		WriteJSONRPCError(w, http.StatusForbidden, -32600, err.Error())
		return
	}

	if err := ValidateAccept(r); err != nil {
		WriteJSONRPCError(w, http.StatusBadRequest, -32600, err.Error())
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		WriteJSONRPCError(w, http.StatusBadRequest, -32700, "read body failed")
		return
	}

	meta := ParseRequestMeta(r)
	if err := ValidateProtocolVersion(meta.ProtocolVersion, s.cfg.Transport.ProtocolVersion); err != nil {
		WriteJSONRPCError(w, http.StatusBadRequest, -32600, err.Error())
		return
	}
	if err := ValidateHeaderBodyMatch(meta, body); err != nil {
		WriteJSONRPCError(w, http.StatusBadRequest, -32600, err.Error())
		return
	}
	if err := RequireSession(meta, body); err != nil {
		WriteJSONRPCError(w, http.StatusBadRequest, -32600, err.Error())
		return
	}

	var msg model.JSONRPCMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		WriteJSONRPCError(w, http.StatusBadRequest, -32700, "parse error")
		return
	}

	// Bind session
	if msg.Method == "initialize" {
		mcpID, sess := s.sessions.Create()
		s.proxy.SetSession(sess)
		w.Header().Set(HeaderSessionID, mcpID)
	} else if meta.SessionID != "" {
		sess, ok := s.sessions.Get(meta.SessionID)
		if !ok {
			WriteJSONRPCError(w, http.StatusBadRequest, -32600, "unknown session")
			return
		}
		s.proxy.SetSession(sess)
	}

	reqCtx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	result, err := s.proxy.HandleAgentRequest(reqCtx, body)
	if err != nil {
		s.log.Printf("HTTP dispatch error: %v", err)
		WriteJSONRPCError(w, http.StatusInternalServerError, -32603, err.Error())
		return
	}

	if result.IsNotification {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if err := WriteResponse(w, result.Response, result.UseSSE, result.Blocked); err != nil {
		s.log.Printf("HTTP write error: %v", err)
	}
}
