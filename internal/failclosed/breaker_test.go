package failclosed

import (
	"log"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
)

type fakeClock struct {
	t atomic.Int64
}

func (c *fakeClock) Now() time.Time {
	return time.Unix(0, c.t.Load())
}

func (c *fakeClock) advance(d time.Duration) {
	c.t.Add(int64(d))
}

func testCfg() config.FailClosedConfig {
	return config.FailClosedConfig{
		Enabled:                      true,
		RingbufDropRateThreshold:     50,
		RingbufRecoveryRateThreshold: 10,
		SinkFailureThreshold:         3,
		PanicThreshold:               1,
		MinTripDuration:              "30s",
		RecoveryWindow:               "30s",
		BackoffMultiplier:            2.0,
		MaxTripDuration:              "10m",
	}
}

func newTestBreaker(t *testing.T) (*Breaker, *fakeClock) {
	t.Helper()
	clk := &fakeClock{}
	clk.t.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	b := New(testCfg(), log.New(os.Stderr, "[test] ", 0))
	b.SetClock(clk)
	return b, clk
}

func TestBreaker_NilWhenDisabled(t *testing.T) {
	if New(config.FailClosedConfig{Enabled: false}, nil) != nil {
		t.Fatal("expected nil breaker when disabled")
	}
}

func TestBreaker_HysteresisBand(t *testing.T) {
	b, clk := newTestBreaker(t)

	b.RecordDropCount(0)
	clk.advance(time.Second)
	b.RecordDropCount(60) // 60/s > 50 → rateBad
	if !b.Tripped() {
		t.Fatal("expected trip at 60/s")
	}

	// 30/s is in the band (10 < x ≤ 50): must keep rateBad true (Schmitt).
	clk.advance(time.Second)
	b.RecordDropCount(60 + 30)
	b.mu.Lock()
	stillBad := b.rateBad
	b.mu.Unlock()
	if !stillBad {
		t.Fatal("hysteresis: rate in band should keep rateBad")
	}

	// 5/s ≤ lo → clear rateBad
	clk.advance(time.Second)
	b.RecordDropCount(60 + 30 + 5)
	b.mu.Lock()
	stillBad = b.rateBad
	b.mu.Unlock()
	if stillBad {
		t.Fatal("hysteresis: rate ≤ lo should clear rateBad")
	}
}

func TestBreaker_MinTripFloorAndRecovery(t *testing.T) {
	b, clk := newTestBreaker(t)
	var transitions []bool
	b.OnTransition = func(tripped bool, reason string) {
		transitions = append(transitions, tripped)
	}

	b.RecordPanic()
	if !b.Tripped() || len(transitions) != 1 || !transitions[0] {
		t.Fatalf("expected engage, transitions=%v tripped=%v", transitions, b.Tripped())
	}

	// Signal clears immediately but min trip floor holds.
	b.panicBad = false
	b.panicCount = 0
	clk.advance(10 * time.Second)
	b.RecordSinkSuccess() // eval
	if !b.Tripped() {
		t.Fatal("should stay tripped during min_trip_duration")
	}

	clk.advance(25 * time.Second) // total 35s > 30s min
	b.RecordSinkSuccess()
	if b.st != stateRecovering && !b.Tripped() {
		// Still tripped while recovering
	}
	if !b.Tripped() {
		t.Fatal("should be recovering (still Tripped()==true)")
	}

	clk.advance(30 * time.Second)
	b.RecordSinkSuccess()
	if b.Tripped() {
		t.Fatal("expected clear after recovery window")
	}
	if len(transitions) < 2 || transitions[len(transitions)-1] {
		t.Fatalf("expected clear transition, got %v", transitions)
	}
}

func TestBreaker_SinkFailureThreshold(t *testing.T) {
	b, _ := newTestBreaker(t)
	b.RecordSinkFailure()
	b.RecordSinkFailure()
	if b.Tripped() {
		t.Fatal("should not trip before threshold")
	}
	b.RecordSinkFailure()
	if !b.Tripped() {
		t.Fatal("expected trip at 3 consecutive sink failures")
	}
}

func TestBreaker_FlapBackoff(t *testing.T) {
	b, clk := newTestBreaker(t)

	// Trip via panic, clear, re-trip quickly → backoff multiplies floor.
	b.RecordPanic()
	clk.advance(30 * time.Second)
	// clear signals
	b.mu.Lock()
	b.panicBad = false
	b.panicCount = 0
	b.mu.Unlock()
	b.RecordSinkSuccess()
	clk.advance(30 * time.Second) // recovery window
	b.RecordSinkSuccess()
	if b.Tripped() {
		t.Fatal("expected clear")
	}

	// Re-trip within 5×recovery (150s) — lastCleared is now.
	b.RecordPanic()
	b.mu.Lock()
	floor := b.effectiveMin
	b.mu.Unlock()
	if floor < 60*time.Second {
		t.Fatalf("expected backoff floor ≥ 60s, got %s", floor)
	}
}

func TestBreaker_CriticalDropRateTrips(t *testing.T) {
	b, clk := newTestBreaker(t)

	b.RecordCriticalDropCount(0)
	clk.advance(time.Second)
	b.RecordCriticalDropCount(60) // 60/s > 50
	if !b.Tripped() {
		t.Fatal("expected trip on critical ringbuf drop rate")
	}
	reason := b.Reason()
	if !strings.Contains(reason, "critical_ringbuf_drop_rate") {
		t.Fatalf("expected critical_ringbuf_drop_rate in reason, got %q", reason)
	}
}

func TestBreaker_FlapLoopDoesNotOscillate(t *testing.T) {
	b, clk := newTestBreaker(t)
	var engages, clears int
	b.OnTransition = func(tripped bool, reason string) {
		if tripped {
			engages++
		} else {
			clears++
		}
	}

	// Rapid alternating high/low drop samples every second for 2 minutes.
	count := uint64(0)
	b.RecordDropCount(0)
	for i := 0; i < 120; i++ {
		clk.advance(time.Second)
		if i%2 == 0 {
			count += 100 // 100/s → trip
		} else {
			count += 1 // 1/s → healthy signal
		}
		b.RecordDropCount(count)
	}

	if engages == 0 {
		t.Fatal("expected at least one engage")
	}
	// With min_trip 30s and recovery 30s, clears must be rare — not every second.
	if clears > engages {
		t.Fatalf("clears (%d) > engages (%d) — flap loop", clears, engages)
	}
	if engages+clears > 10 {
		t.Fatalf("too many transitions (%d engages, %d clears) — flap not damped", engages, clears)
	}
}
