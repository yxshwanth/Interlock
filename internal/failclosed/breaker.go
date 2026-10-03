package failclosed

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
)

// TransitionFunc is invoked when the breaker engages or clears fail-closed.
// tripped=true means ENGAGED; false means CLEARED. reason describes why.
type TransitionFunc func(tripped bool, reason string)

// Clock abstracts time for unit tests.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type state int

const (
	stateHealthy state = iota
	stateTripped
	stateRecovering
)

// Breaker implements fail-closed policy: hysteresis on ringbuf drop rate,
// consecutive sink failures, panic count, min-trip floor, recovery window,
// and exponential backoff on flap.
type Breaker struct {
	cfg          config.FailClosedConfig
	log          *log.Logger
	clock        Clock
	OnTransition TransitionFunc

	mu sync.Mutex

	st           state
	reason       string
	trippedAt    time.Time
	recoveringAt time.Time
	lastCleared  time.Time
	effectiveMin time.Duration
	flapCount    int

	// Rate samples (routine ringbuf: connect/openat)
	lastDropCount uint64
	lastDropAt    time.Time
	dropRate      float64
	rateBad       bool

	// Rate samples (critical ringbuf: write/sendto/lsm_deny)
	lastCriticalDropCount uint64
	lastCriticalDropAt    time.Time
	criticalDropRate      float64
	criticalRateBad       bool

	// Sink
	sinkFailures int
	sinkBad      bool

	// Panic
	panicCount int
	panicBad   bool
}

// New creates a Breaker from config. Returns nil if fail_closed is disabled.
func New(cfg config.FailClosedConfig, logger *log.Logger) *Breaker {
	if !cfg.Enabled {
		return nil
	}
	if logger == nil {
		logger = log.Default()
	}
	b := &Breaker{
		cfg:          cfg,
		log:          logger,
		clock:        realClock{},
		st:           stateHealthy,
		effectiveMin: cfg.MinTripDurationOrDefault(),
	}
	return b
}

// SetClock replaces the wall clock (tests only).
func (b *Breaker) SetClock(c Clock) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.clock = c
}

// Tripped reports whether fail-closed is currently engaged.
func (b *Breaker) Tripped() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.st == stateTripped || b.st == stateRecovering
}

// Reason returns the current engagement reason (empty when healthy).
func (b *Breaker) Reason() string {
	if b == nil {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reason
}

// RecordDropCount feeds a cumulative routine (connect/openat) drop_count sample.
func (b *Breaker) RecordDropCount(n uint64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock.Now()
	if !b.lastDropAt.IsZero() {
		elapsed := now.Sub(b.lastDropAt).Seconds()
		if elapsed > 0 {
			var delta float64
			if n >= b.lastDropCount {
				delta = float64(n - b.lastDropCount)
			}
			b.dropRate = delta / elapsed
		}
	}
	b.lastDropCount = n
	b.lastDropAt = now

	hi := b.cfg.RingbufDropRateThresholdOrDefault()
	lo := b.cfg.RingbufRecoveryRateThresholdOrDefault()
	if b.dropRate > hi {
		b.rateBad = true
	} else if b.dropRate <= lo {
		b.rateBad = false
	}
	// else: hysteresis band — keep previous rateBad

	b.evalLocked(now)
}

// RecordCriticalDropCount feeds a cumulative critical_drop_count sample
// (write/sendto/lsm_deny). Uses the same high/low watermarks as routine drops.
func (b *Breaker) RecordCriticalDropCount(n uint64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock.Now()
	if !b.lastCriticalDropAt.IsZero() {
		elapsed := now.Sub(b.lastCriticalDropAt).Seconds()
		if elapsed > 0 {
			var delta float64
			if n >= b.lastCriticalDropCount {
				delta = float64(n - b.lastCriticalDropCount)
			}
			b.criticalDropRate = delta / elapsed
		}
	}
	b.lastCriticalDropCount = n
	b.lastCriticalDropAt = now

	hi := b.cfg.RingbufDropRateThresholdOrDefault()
	lo := b.cfg.RingbufRecoveryRateThresholdOrDefault()
	if b.criticalDropRate > hi {
		b.criticalRateBad = true
	} else if b.criticalDropRate <= lo {
		b.criticalRateBad = false
	}

	b.evalLocked(now)
}

// RecordSinkFailure notes a consecutive evidence write failure.
func (b *Breaker) RecordSinkFailure() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sinkFailures++
	if b.sinkFailures >= b.cfg.SinkFailureThresholdOrDefault() {
		b.sinkBad = true
	}
	b.evalLocked(b.clock.Now())
}

// RecordSinkSuccess resets the consecutive sink-failure counter.
func (b *Breaker) RecordSinkSuccess() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sinkFailures = 0
	b.sinkBad = false
	b.evalLocked(b.clock.Now())
}

// RecordPanic notes an engine/sensor panic.
func (b *Breaker) RecordPanic() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.panicCount++
	if b.panicCount >= b.cfg.PanicThresholdOrDefault() {
		b.panicBad = true
	}
	b.evalLocked(b.clock.Now())
}

// WatchRingbufDrops polls routine and optional critical drop counts on every
// interval until ctx is cancelled. criticalDropCount may be nil.
func (b *Breaker) WatchRingbufDrops(ctx context.Context, dropCount, criticalDropCount func() (uint64, error), every time.Duration) {
	if b == nil || every <= 0 {
		return
	}
	if dropCount == nil && criticalDropCount == nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	poll := func() {
		if dropCount != nil {
			if n, err := dropCount(); err == nil {
				b.RecordDropCount(n)
			}
		}
		if criticalDropCount != nil {
			if n, err := criticalDropCount(); err == nil {
				b.RecordCriticalDropCount(n)
			}
		}
	}
	poll()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			poll()
		}
	}
}

func (b *Breaker) anyBad() bool {
	return b.rateBad || b.criticalRateBad || b.sinkBad || b.panicBad
}

func (b *Breaker) currentReason() string {
	var parts []string
	if b.rateBad {
		parts = append(parts, fmt.Sprintf("ringbuf_drop_rate=%.1f/s", b.dropRate))
	}
	if b.criticalRateBad {
		parts = append(parts, fmt.Sprintf("critical_ringbuf_drop_rate=%.1f/s", b.criticalDropRate))
	}
	if b.sinkBad {
		parts = append(parts, fmt.Sprintf("sink_failures=%d", b.sinkFailures))
	}
	if b.panicBad {
		parts = append(parts, fmt.Sprintf("panics=%d", b.panicCount))
	}
	if len(parts) == 0 {
		return "unknown"
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += "," + parts[i]
	}
	return out
}

func (b *Breaker) evalLocked(now time.Time) {
	switch b.st {
	case stateHealthy:
		// Reset flap backoff if healthy long enough.
		rw := b.cfg.RecoveryWindowOrDefault()
		if !b.lastCleared.IsZero() && now.Sub(b.lastCleared) >= 5*rw {
			b.flapCount = 0
			b.effectiveMin = b.cfg.MinTripDurationOrDefault()
		}
		if b.anyBad() {
			b.engageLocked(now, b.currentReason())
		}

	case stateTripped:
		if b.anyBad() {
			// Stay tripped; refresh reason.
			b.reason = b.currentReason()
			return
		}
		if now.Sub(b.trippedAt) < b.effectiveMin {
			return
		}
		b.st = stateRecovering
		b.recoveringAt = now
		b.log.Printf("fail-closed recovering: waiting %s of sustained health", b.cfg.RecoveryWindowOrDefault())

	case stateRecovering:
		if b.anyBad() {
			b.reason = b.currentReason()
			b.st = stateTripped
			b.trippedAt = now
			b.log.Printf("[SECURITY] FAIL-CLOSED re-tripped during recovery: %s", b.reason)
			return
		}
		if now.Sub(b.recoveringAt) >= b.cfg.RecoveryWindowOrDefault() {
			b.clearLocked(now)
		}
	}
}

func (b *Breaker) engageLocked(now time.Time, reason string) {
	// Backoff if re-tripping soon after a clear.
	rw := b.cfg.RecoveryWindowOrDefault()
	if !b.lastCleared.IsZero() && now.Sub(b.lastCleared) < 5*rw {
		b.flapCount++
		mult := b.cfg.BackoffMultiplierOrDefault()
		floor := b.cfg.MinTripDurationOrDefault()
		for i := 0; i < b.flapCount; i++ {
			floor = time.Duration(float64(floor) * mult)
		}
		max := b.cfg.MaxTripDurationOrDefault()
		if floor > max {
			floor = max
		}
		b.effectiveMin = floor
	} else {
		b.effectiveMin = b.cfg.MinTripDurationOrDefault()
	}

	b.st = stateTripped
	b.reason = reason
	b.trippedAt = now
	b.log.Printf("[SECURITY] FAIL-CLOSED ENGAGED: %s (min_trip=%s)", reason, b.effectiveMin)
	cb := b.OnTransition
	if cb != nil {
		b.mu.Unlock()
		func() {
			defer b.mu.Lock()
			cb(true, reason)
		}()
	}
}

func (b *Breaker) clearLocked(now time.Time) {
	reason := b.reason
	b.st = stateHealthy
	b.reason = ""
	b.lastCleared = now
	b.panicCount = 0
	b.panicBad = false
	b.sinkFailures = 0
	b.sinkBad = false
	b.log.Printf("[SECURITY] FAIL-CLOSED CLEARED (was: %s)", reason)
	cb := b.OnTransition
	if cb != nil {
		b.mu.Unlock()
		func() {
			defer b.mu.Lock()
			cb(false, reason)
		}()
	}
}
