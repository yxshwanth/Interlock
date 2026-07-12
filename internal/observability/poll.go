package observability

import (
	"context"
	"time"

	"github.com/yxshwanth/Interlock/internal/proxy"
)

// DropCountFunc returns the current eBPF ringbuf drop count.
type DropCountFunc func() (uint64, error)

// FilterCountFunc returns watched PID and cgroup counts.
type FilterCountFunc func() (pids, cgroups int, err error)

// PollRuntime syncs RuntimeStats, eBPF drops, and filter sizes into Prometheus gauges/counters.
// Stops when ctx is cancelled.
func PollRuntime(ctx context.Context, m *Metrics, stats *proxy.RuntimeStats, dropCount DropCountFunc, filters FilterCountFunc, every time.Duration) {
	if m == nil || every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	syncOnce := func() {
		if stats != nil {
			m.SyncDrops(stats.DroppedEvidence.Load(), stats.DroppedEvents.Load())
		}
		if dropCount != nil {
			if n, err := dropCount(); err == nil {
				m.SetEBPFRingbufDrops(n)
			}
		}
		if filters != nil {
			if p, c, err := filters(); err == nil {
				m.SetWatchedFilters(p, c)
			}
		}
	}
	syncOnce()
	for {
		select {
		case <-ctx.Done():
			syncOnce()
			return
		case <-t.C:
			syncOnce()
		}
	}
}
