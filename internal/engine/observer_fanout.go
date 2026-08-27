package engine

import "github.com/yxshwanth/Interlock/internal/model"

// MultiEmitObserver fans OnEvidenceEmitted to all non-nil observers.
type MultiEmitObserver []EvidenceEmitObserver

// OnEvidenceEmitted calls each observer in order.
func (m MultiEmitObserver) OnEvidenceEmitted(rec model.EvidenceRecord) {
	for _, o := range m {
		if o != nil {
			o.OnEvidenceEmitted(rec)
		}
	}
}
