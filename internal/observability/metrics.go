package observability

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/yxshwanth/Interlock/internal/model"
)

var (
	up = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "interlock_up",
		Help: "1 while the Interlock process is serving observability endpoints",
	})

	detectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "interlock_detections_total",
		Help: "Evidence records persisted after a trifecta trip",
	}, []string{"verdict", "variant", "action"})

	evidenceDroppedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "interlock_evidence_dropped_total",
		Help: "Evidence records dropped due to async backpressure",
	})

	eventsDroppedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "interlock_events_dropped_total",
		Help: "Event log records dropped due to async backpressure",
	})

	ebpfRingbufDrops = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "interlock_ebpf_ringbuf_drops_total",
		Help: "Kernel eBPF ring buffer reserve failures (current total from drop_count map)",
	})

	watchedPIDs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "interlock_watched_pids",
		Help: "Number of PIDs in the eBPF pid_filter map",
	})

	watchedCgroups = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "interlock_watched_cgroups",
		Help: "Number of cgroup IDs in the eBPF cgroup_filter map",
	})

	alertDeliveriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "interlock_alert_deliveries_total",
		Help: "Outbound alert/SIEM delivery attempts",
	}, []string{"kind", "result"})
)

// Metrics records detection and drop counters for Prometheus.
type Metrics struct {
	lastEvidenceDropped atomic.Uint64
	lastEventsDropped   atomic.Uint64
}

// NewMetrics returns a Metrics helper (singleton Prometheus series).
func NewMetrics() *Metrics {
	return &Metrics{}
}

// RecordDetection increments interlock_detections_total after a successful evidence persist.
func (m *Metrics) RecordDetection(rec model.EvidenceRecord) {
	verdict := string(rec.Verdict)
	if verdict == "" {
		verdict = "unknown"
	}
	variant := string(rec.Variant)
	if variant == "" {
		variant = "unknown"
	}
	action := string(rec.Action)
	if action == "" {
		action = "unknown"
	}
	detectionsTotal.WithLabelValues(verdict, variant, action).Inc()
}

// OnEvidenceEmitted implements engine.EvidenceEmitObserver.
func (m *Metrics) OnEvidenceEmitted(rec model.EvidenceRecord) {
	m.RecordDetection(rec)
}

// SyncDrops advances drop counters from RuntimeStats atomics (monotonic).
func (m *Metrics) SyncDrops(evidenceDropped, eventsDropped uint64) {
	if prev := m.lastEvidenceDropped.Load(); evidenceDropped > prev {
		evidenceDroppedTotal.Add(float64(evidenceDropped - prev))
		m.lastEvidenceDropped.Store(evidenceDropped)
	}
	if prev := m.lastEventsDropped.Load(); eventsDropped > prev {
		eventsDroppedTotal.Add(float64(eventsDropped - prev))
		m.lastEventsDropped.Store(eventsDropped)
	}
}

// SetEBPFRingbufDrops sets the live kernel drop_count gauge.
func (m *Metrics) SetEBPFRingbufDrops(n uint64) {
	ebpfRingbufDrops.Set(float64(n))
}

// SetWatchedFilters sets PID/cgroup filter map size gauges.
func (m *Metrics) SetWatchedFilters(pids, cgroups int) {
	watchedPIDs.Set(float64(pids))
	watchedCgroups.Set(float64(cgroups))
}

// SetUp marks the process as up (1) or down (0).
func SetUp(v float64) {
	up.Set(v)
}

// RecordAlertDelivery increments interlock_alert_deliveries_total{kind,result}.
func (m *Metrics) RecordAlertDelivery(kind, result string) {
	if kind == "" {
		kind = "unknown"
	}
	if result == "" {
		result = "unknown"
	}
	alertDeliveriesTotal.WithLabelValues(kind, result).Inc()
}
