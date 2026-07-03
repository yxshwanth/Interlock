package engine

import (
	"sync"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

func TestSessionStore_GetEmpty(t *testing.T) {
	s := NewSessionStore()
	if got := s.Get("nonexistent"); got != nil {
		t.Fatalf("expected nil for unknown session, got %+v", got)
	}
}

func TestSessionStore_GetOrCreate_New(t *testing.T) {
	s := NewSessionStore()
	st := s.GetOrCreate("sess-1")

	if st.SessionID != "sess-1" {
		t.Fatalf("expected session ID 'sess-1', got %q", st.SessionID)
	}
	if st.Status != model.Monitoring {
		t.Fatalf("expected status Monitoring, got %q", st.Status)
	}
	if st.Legs.SensitiveSourceTouched.Lit {
		t.Fatal("sensitive_source_touched should not be lit on a new session")
	}
	if st.Legs.UntrustedContentPresent.Lit {
		t.Fatal("untrusted_content_present should not be lit on a new session")
	}
	if st.Legs.ExternalSinkInvoked.Lit {
		t.Fatal("external_sink_invoked should not be lit on a new session")
	}
	if st.CreatedAt == 0 {
		t.Fatal("expected CreatedAt to be set")
	}
	if st.LastActivity == 0 {
		t.Fatal("expected LastActivity to be set")
	}
	if len(st.Tainted) != 0 {
		t.Fatalf("expected no tainted values, got %d", len(st.Tainted))
	}
	if len(st.Timeline) != 0 {
		t.Fatalf("expected empty timeline, got %d", len(st.Timeline))
	}
}

func TestSessionStore_GetOrCreate_Idempotent(t *testing.T) {
	s := NewSessionStore()
	st1 := s.GetOrCreate("sess-1")
	st1.Status = model.Tripped

	st2 := s.GetOrCreate("sess-1")
	if st2.Status != model.Tripped {
		t.Fatal("second GetOrCreate should return the same state, not a fresh one")
	}
	if st1 != st2 {
		t.Fatal("expected the same pointer from both calls")
	}
}

func TestSessionStore_Upsert(t *testing.T) {
	s := NewSessionStore()
	st := &model.SessionState{
		SessionID: "sess-u",
		Status:    model.Tripped,
	}
	s.Upsert(st)

	got := s.Get("sess-u")
	if got == nil {
		t.Fatal("expected to find session after Upsert")
	}
	if got.Status != model.Tripped {
		t.Fatalf("expected Tripped, got %q", got.Status)
	}
}

func TestSessionStore_Upsert_Overwrites(t *testing.T) {
	s := NewSessionStore()
	s.GetOrCreate("sess-o")

	replacement := &model.SessionState{
		SessionID: "sess-o",
		Status:    model.Terminated,
	}
	s.Upsert(replacement)

	got := s.Get("sess-o")
	if got.Status != model.Terminated {
		t.Fatalf("expected Terminated after overwrite, got %q", got.Status)
	}
}

func TestSessionStore_All(t *testing.T) {
	s := NewSessionStore()
	s.GetOrCreate("a")
	s.GetOrCreate("b")
	s.GetOrCreate("c")

	all := s.All()
	if len(all) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(all))
	}

	ids := map[string]bool{}
	for _, st := range all {
		ids[st.SessionID] = true
	}
	for _, id := range []string{"a", "b", "c"} {
		if !ids[id] {
			t.Errorf("missing session %q in All()", id)
		}
	}
}

func TestSessionStore_ConcurrentAccess(t *testing.T) {
	s := NewSessionStore()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			st := s.GetOrCreate(id)
			st.Legs.SensitiveSourceTouched.Lit = true
			s.Upsert(st)
			_ = s.Get(id)
			_ = s.All()
		}("sess-concurrent")
	}
	wg.Wait()

	st := s.Get("sess-concurrent")
	if st == nil {
		t.Fatal("expected session to exist after concurrent access")
	}
}
