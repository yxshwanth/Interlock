package engine

import (
	"sync/atomic"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

type countObs struct {
	n atomic.Int32
}

func (c *countObs) OnEvidenceEmitted(rec model.EvidenceRecord) {
	c.n.Add(1)
}

func TestMultiEmitObserver(t *testing.T) {
	a, b := &countObs{}, &countObs{}
	var nilObs EvidenceEmitObserver
	m := MultiEmitObserver{a, nilObs, b}
	m.OnEvidenceEmitted(model.EvidenceRecord{SessionID: "s"})
	if a.n.Load() != 1 || b.n.Load() != 1 {
		t.Fatalf("a=%d b=%d", a.n.Load(), b.n.Load())
	}
}
