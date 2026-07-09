package engine

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"

	"github.com/yxshwanth/Interlock/internal/model"
)

// EvidenceDropCounter is incremented when drop-mode evidence enqueue fails.
type EvidenceDropCounter interface {
	Add(delta uint64)
}

// AtomicEvidenceDrops adapts sync/atomic.Uint64 to EvidenceDropCounter.
type AtomicEvidenceDrops struct {
	N *atomic.Uint64
}

// Add increments the counter.
func (a AtomicEvidenceDrops) Add(delta uint64) {
	if a.N != nil {
		a.N.Add(delta)
	}
}

// AsyncEvidenceSink decorates an EvidenceSink with a background worker so
// Emit returns after enqueue — verdict/action are not blocked on disk I/O.
//
// backpressure "block": Emit waits if the queue is full (no silent loss).
// backpressure "drop": Emit drops on overflow and increments drops.
// Close drains the queue before closing the inner sink.
type AsyncEvidenceSink struct {
	inner        EvidenceSink
	backpressure string
	queue        chan model.EvidenceRecord
	drops        EvidenceDropCounter
	log          *log.Logger
	done         chan struct{}

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// NewAsyncEvidenceSink wraps inner with an async emit queue.
// queueSize defaults to 256 when <= 0. backpressure defaults to "block".
func NewAsyncEvidenceSink(inner EvidenceSink, backpressure string, queueSize int, drops EvidenceDropCounter) *AsyncEvidenceSink {
	if backpressure == "" {
		backpressure = "block"
	}
	if queueSize <= 0 {
		queueSize = 256
	}
	s := &AsyncEvidenceSink{
		inner:        inner,
		backpressure: backpressure,
		queue:        make(chan model.EvidenceRecord, queueSize),
		drops:        drops,
		log:          log.New(os.Stderr, "[evidence] ", log.LstdFlags),
		done:         make(chan struct{}),
	}
	s.wg.Add(1)
	go s.writeLoop()
	return s
}

func (s *AsyncEvidenceSink) writeLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.done:
			s.drainQueue()
			return
		case rec := <-s.queue:
			s.emitInner(rec)
		}
	}
}

func (s *AsyncEvidenceSink) drainQueue() {
	for {
		select {
		case rec := <-s.queue:
			s.emitInner(rec)
		default:
			return
		}
	}
}

func (s *AsyncEvidenceSink) emitInner(rec model.EvidenceRecord) {
	if s.inner == nil {
		return
	}
	if err := s.inner.Emit(rec); err != nil {
		s.log.Printf("[SECURITY] evidence sink write failed — enforcement continues but forensic record is incomplete: %v", err)
	}
}

// Emit enqueues rec for background persistence. The record is copied by value
// (slices from buildEvidence are not mutated after return).
func (s *AsyncEvidenceSink) Emit(rec model.EvidenceRecord) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		if s.inner != nil {
			return s.inner.Emit(rec)
		}
		return nil
	}

	if s.backpressure == "drop" {
		select {
		case s.queue <- rec:
		default:
			if s.drops != nil {
				s.drops.Add(1)
			}
		}
		s.mu.Unlock()
		return nil
	}

	s.mu.Unlock()
	select {
	case s.queue <- rec:
		return nil
	case <-s.done:
		if s.inner != nil {
			return s.inner.Emit(rec)
		}
		return nil
	}
}

// Close stops the worker after draining the queue, then closes the inner sink.
func (s *AsyncEvidenceSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.done)
	s.mu.Unlock()

	s.wg.Wait()
	s.drainQueue() // catch any race enqueue after drain started

	if c, ok := s.inner.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// String describes the sink for debugging.
func (s *AsyncEvidenceSink) String() string {
	return fmt.Sprintf("AsyncEvidenceSink(backpressure=%s)", s.backpressure)
}
