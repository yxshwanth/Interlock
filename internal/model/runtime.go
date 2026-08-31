package model

import "sync/atomic"

// RuntimeStats holds operational counters surfaced at shutdown.
type RuntimeStats struct {
	DroppedEvents            atomic.Uint64
	DroppedEvidence          atomic.Uint64
	EBPFRingbufDrops         atomic.Uint64
	EBPFCriticalRingbufDrops atomic.Uint64
}

// DeliveryRecorder records webhook/SIEM delivery outcomes (ok|error|skipped).
type DeliveryRecorder interface {
	RecordAlertDelivery(kind, result string)
}
