package proxy

import (
	"sync"
	"syscall"
)

// ProcessKey uniquely identifies a process instance (PID + start time).
type ProcessKey struct {
	PID         int
	StartTimeNs uint64
}

// PIDEntry maps a live process to its owning session and server.
type PIDEntry struct {
	Key       ProcessKey
	SessionID string
	ServerID  string
}

// PIDRegistry tracks which session owns each monitored child process.
type PIDRegistry struct {
	mu      sync.RWMutex
	entries map[ProcessKey]PIDEntry
	byPID   map[int][]ProcessKey // multiple keys possible briefly during reuse
}

// NewPIDRegistry creates an empty PID registry.
func NewPIDRegistry() *PIDRegistry {
	return &PIDRegistry{
		entries: make(map[ProcessKey]PIDEntry),
		byPID:   make(map[int][]ProcessKey),
	}
}

// Register records that pid (with startTimeNs) belongs to sessionID/serverID.
func (r *PIDRegistry) Register(pid int, startTimeNs uint64, sessionID, serverID string) {
	key := ProcessKey{PID: pid, StartTimeNs: startTimeNs}
	entry := PIDEntry{Key: key, SessionID: sessionID, ServerID: serverID}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries[key] = entry
	r.byPID[pid] = append(r.byPID[pid], key)
}

// Unregister removes a process key from the registry.
func (r *PIDRegistry) Unregister(pid int, startTimeNs uint64) {
	key := ProcessKey{PID: pid, StartTimeNs: startTimeNs}

	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.entries, key)
	keys := r.byPID[pid]
	filtered := keys[:0]
	for _, k := range keys {
		if k != key {
			filtered = append(filtered, k)
		}
	}
	if len(filtered) == 0 {
		delete(r.byPID, pid)
	} else {
		r.byPID[pid] = filtered
	}
}

// Lookup resolves pid to session and server. Prefers live processes when
// multiple keys exist (PID reuse safety).
func (r *PIDRegistry) Lookup(pid int) (sessionID, serverID string, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := r.byPID[pid]
	if len(keys) == 0 {
		return "", "", false
	}

	var fallback *PIDEntry
	for _, key := range keys {
		entry, exists := r.entries[key]
		if !exists {
			continue
		}
		if processAlive(pid) {
			return entry.SessionID, entry.ServerID, true
		}
		if fallback == nil {
			e := entry
			fallback = &e
		}
	}
	if fallback != nil {
		return fallback.SessionID, fallback.ServerID, true
	}
	return "", "", false
}

// AllPIDs returns every registered PID (for diagnostics/tests).
func (r *PIDRegistry) AllPIDs() []int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]int, 0, len(r.byPID))
	for pid := range r.byPID {
		out = append(out, pid)
	}
	return out
}

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil
}
