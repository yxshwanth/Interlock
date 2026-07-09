package engine

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

func TestSQLiteEvidenceSink_RestartSurvival(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.db")

	sink, err := NewSQLiteEvidenceSink(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(sampleEvidence("sess-a")); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	sink2, err := NewSQLiteEvidenceSink(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer sink2.Close()

	n, err := sink2.Count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 record after restart, got %d", n)
	}
}

func TestSQLiteEvidenceSink_Retention(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.db")

	sink, err := NewSQLiteEvidenceSink(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	for i := 0; i < 5; i++ {
		rec := sampleEvidence("sess")
		rec.TripTS = int64(i + 1)
		if err := sink.Emit(rec); err != nil {
			t.Fatal(err)
		}
	}

	n, err := sink.Count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("expected 3 records after retention, got %d", n)
	}
}

func TestSQLiteEvidenceSink_ConcurrentRetention(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.db")
	const maxRecords = 8
	const writers = 6
	const emitsPerWriter = 5

	sink, err := NewSQLiteEvidenceSink(path, maxRecords)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	start := make(chan struct{})
	var done sync.WaitGroup
	done.Add(writers)
	errCh := make(chan error, 1)

	for w := 0; w < writers; w++ {
		go func(w int) {
			defer done.Done()
			<-start
			for i := 0; i < emitsPerWriter; i++ {
				rec := sampleEvidence("sess")
				rec.SessionID = fmt.Sprintf("sess-%d", w)
				rec.TripTS = int64(w*100 + i)
				if err := sink.Emit(rec); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
			}
		}(w)
	}

	close(start)
	done.Wait()

	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}

	n, err := sink.Count()
	if err != nil {
		t.Fatal(err)
	}
	if n != maxRecords {
		t.Fatalf("expected %d records after concurrent retention, got %d", maxRecords, n)
	}

	// Restart survival after concurrent writes + eviction.
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	sink2, err := NewSQLiteEvidenceSink(path, maxRecords)
	if err != nil {
		t.Fatal(err)
	}
	defer sink2.Close()
	n, err = sink2.Count()
	if err != nil {
		t.Fatal(err)
	}
	if n != maxRecords {
		t.Fatalf("expected %d records after restart, got %d", maxRecords, n)
	}
}

func TestEvidenceStore_CrossSessionQuery_KnownGap(t *testing.T) {
	t.Skip("known v0.2 gap: SQLite stores records but no query API or viewer DB integration yet")
}

func sampleEvidence(sessionID string) model.EvidenceRecord {
	return model.EvidenceRecord{
		SessionID:  sessionID,
		TripTS:     1,
		Verdict:    model.VerdictExfil,
		Action:     model.ActionPrevented,
		Variant:    model.VariantA,
		Confidence: 0.95,
	}
}

func TestNewEvidenceSink_DefaultJSONL(t *testing.T) {
	cfg := &config.Config{
		Evidence: config.EvidenceConfig{
			Backend:    "jsonl",
			Path:       filepath.Join(t.TempDir(), "evidence.jsonl"),
			MaxRecords: 1000,
		},
	}
	sink, err := NewEvidenceSink(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	async, ok := sink.(*AsyncEvidenceSink)
	if !ok {
		t.Fatalf("expected AsyncEvidenceSink, got %T", sink)
	}
	defer async.Close()
	if _, ok := async.inner.(*JSONLEvidenceSink); !ok {
		t.Fatalf("expected inner JSONLEvidenceSink, got %T", async.inner)
	}
}

func TestNewEvidenceSink_SQLite(t *testing.T) {
	cfg := &config.Config{
		Evidence: config.EvidenceConfig{
			Backend:    "sqlite",
			Path:       filepath.Join(t.TempDir(), "evidence.db"),
			MaxRecords: 100,
		},
	}
	sink, err := NewEvidenceSink(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	async, ok := sink.(*AsyncEvidenceSink)
	if !ok {
		t.Fatalf("expected AsyncEvidenceSink, got %T", sink)
	}
	defer async.Close()
	if _, ok := async.inner.(*SQLiteEvidenceSink); !ok {
		t.Fatalf("expected inner SQLiteEvidenceSink, got %T", async.inner)
	}
}
