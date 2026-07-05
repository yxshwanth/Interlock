package engine

import (
	"sync"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

// SessionStore is a thread-safe in-memory store for per-session trifecta state.
// Map structure is protected internally; SessionState fields must only be mutated
// while holding Engine.mu (via Ingest* methods), not via returned pointers alone.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*model.SessionState
}

// NewSessionStore returns an empty session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*model.SessionState),
	}
}

// Get returns the session state for the given ID, or nil if not found.
func (s *SessionStore) Get(sessionID string) *model.SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[sessionID]
}

// GetOrCreate returns the existing session or creates a fresh one with
// Status=Monitoring, zero legs, and the current timestamp.
func (s *SessionStore) GetOrCreate(sessionID string) *model.SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()

	if st, ok := s.sessions[sessionID]; ok {
		return st
	}

	now := time.Now().UnixNano()
	st := &model.SessionState{
		SessionID:    sessionID,
		Status:       model.Monitoring,
		CreatedAt:    now,
		LastActivity: now,
	}
	s.sessions[sessionID] = st
	return st
}

// Upsert stores (or overwrites) the session state by its SessionID.
func (s *SessionStore) Upsert(st *model.SessionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[st.SessionID] = st
}

// Delete removes a session from the store.
func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// All returns a snapshot of every session in the store.
func (s *SessionStore) All() []*model.SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*model.SessionState, 0, len(s.sessions))
	for _, st := range s.sessions {
		out = append(out, st)
	}
	return out
}
