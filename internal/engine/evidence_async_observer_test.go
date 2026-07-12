package engine

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

type countingObserver struct {
	n atomic.Int32
}

func (c *countingObserver) OnEvidenceEmitted(rec model.EvidenceRecord) {
	c.n.Add(1)
}

func TestAsyncEvidenceSink_EmitObserver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	inner, err := NewJSONLEvidenceSink(path)
	if err != nil {
		t.Fatal(err)
	}
	async := NewAsyncEvidenceSink(inner, "block", 8, nil)
	obs := &countingObserver{}
	async.SetEmitObserver(obs)
	defer async.Close()

	if err := async.Emit(model.EvidenceRecord{
		SessionID: "s1",
		Verdict:   model.VerdictExfil,
		Variant:   model.VariantB,
		Action:    model.ActionContained,
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if obs.n.Load() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := obs.n.Load(); got != 1 {
		t.Fatalf("observer called %d times, want 1", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
