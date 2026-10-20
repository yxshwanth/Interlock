// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"log"
	"sync"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

// maxSessions bounds the store (review #9): sessions are never deleted, and
// every HTTP initialize, pod UID and bridge pod_uid creates one.
const maxSessions = 10000

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

	if len(s.sessions) >= maxSessions {
		s.evictOne()
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

// evictOne drops the least recently active session, preferring one with no
// taint so a flood of empty sessions cannot push out the one that holds a
// secret. Caller holds s.mu. LastActivity is written under Engine.mu, which
// every engine caller of GetOrCreate holds.
// ponytail: O(n) scan per create at the cap; a heap if session churn at 10k matters.
func (s *SessionStore) evictOne() {
	betterVictim := func(a, b *model.SessionState) bool {
		if (len(a.Tainted) == 0) != (len(b.Tainted) == 0) {
			return len(a.Tainted) == 0
		}
		return a.LastActivity < b.LastActivity
	}
	var victimID string
	var victim *model.SessionState
	for id, st := range s.sessions {
		if victim == nil || betterVictim(st, victim) {
			victimID, victim = id, st
		}
	}
	delete(s.sessions, victimID)
	log.Printf("[engine] [SECURITY] session cap %d reached: evicted session=%s (tainted values=%d)",
		maxSessions, victimID, len(victim.Tainted))
}

// Upsert stores (or overwrites) the session state by its SessionID.
func (s *SessionStore) Upsert(st *model.SessionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[st.SessionID] = st
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
