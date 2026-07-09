package engine

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

type countingSink struct {
	mu      sync.Mutex
	records []model.EvidenceRecord
	delay   time.Duration
}

func (s *countingSink) Emit(rec model.EvidenceRecord) error {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	return nil
}

func (s *countingSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

func TestAsyncEvidenceSink_DrainOnClose(t *testing.T) {
	inner := &countingSink{}
	async := NewAsyncEvidenceSink(inner, "block", 8, nil)

	for i := 0; i < 5; i++ {
		if err := async.Emit(model.EvidenceRecord{SessionID: "s", Confidence: float64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := async.Close(); err != nil {
		t.Fatal(err)
	}
	if got := inner.Count(); got != 5 {
		t.Fatalf("after Close: got %d records, want 5", got)
	}
}

func TestAsyncEvidenceSink_DropOverflow(t *testing.T) {
	inner := &countingSink{delay: 50 * time.Millisecond}
	var dropped atomic.Uint64
	async := NewAsyncEvidenceSink(inner, "drop", 2, AtomicEvidenceDrops{N: &dropped})

	// Fill queue + keep worker busy; further emits should drop.
	for i := 0; i < 20; i++ {
		_ = async.Emit(model.EvidenceRecord{SessionID: "s"})
	}
	if err := async.Close(); err != nil {
		t.Fatal(err)
	}
	if dropped.Load() == 0 {
		t.Fatal("expected some dropped evidence under drop backpressure")
	}
	if inner.Count() == 0 {
		t.Fatal("expected at least some records persisted")
	}
}

func TestAsyncEvidenceSink_EmitReturnsBeforeSlowInner(t *testing.T) {
	inner := &countingSink{delay: 100 * time.Millisecond}
	async := NewAsyncEvidenceSink(inner, "block", 4, nil)
	defer async.Close()

	start := time.Now()
	if err := async.Emit(model.EvidenceRecord{SessionID: "fast"}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed > 50*time.Millisecond {
		t.Fatalf("Emit blocked for %v; want enqueue-only return", elapsed)
	}
}

func TestAsyncEvidenceSink_ConcurrentEmit(t *testing.T) {
	inner := &countingSink{}
	async := NewAsyncEvidenceSink(inner, "block", 64, nil)

	var wg sync.WaitGroup
	const n = 50
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_ = async.Emit(model.EvidenceRecord{SessionID: "c", Confidence: float64(i)})
		}(i)
	}
	wg.Wait()
	if err := async.Close(); err != nil {
		t.Fatal(err)
	}
	if got := inner.Count(); got != n {
		t.Fatalf("got %d records, want %d", got, n)
	}
}
