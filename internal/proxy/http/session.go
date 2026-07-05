package mcphttp

import (
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/yxshwanth/Interlock/internal/proxy"
)

// SessionStore maps MCP Mcp-Session-Id values to Interlock proxy sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*proxy.Session
}

// NewSessionStore creates an empty session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]*proxy.Session)}
}

// Create allocates a new MCP session ID and Interlock session.
func (s *SessionStore) Create() (mcpSessionID string, sess *proxy.Session) {
	b := make([]byte, 16)
	rand.Read(b)
	mcpSessionID = hex.EncodeToString(b)
	sess = proxy.NewSession()
	s.mu.Lock()
	s.sessions[mcpSessionID] = sess
	s.mu.Unlock()
	return mcpSessionID, sess
}

// Get returns the Interlock session for an MCP session ID.
func (s *SessionStore) Get(mcpSessionID string) (*proxy.Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[mcpSessionID]
	return sess, ok
}

// Bind associates an existing Interlock session with an MCP session ID.
func (s *SessionStore) Bind(mcpSessionID string, sess *proxy.Session) {
	s.mu.Lock()
	s.sessions[mcpSessionID] = sess
	s.mu.Unlock()
}
