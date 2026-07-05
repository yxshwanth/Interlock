package engine

import (
	"path/filepath"
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
	if js, ok := sink.(*JSONLEvidenceSink); ok {
		defer js.Close()
	} else {
		t.Fatalf("expected JSONLEvidenceSink, got %T", sink)
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
	if ss, ok := sink.(*SQLiteEvidenceSink); ok {
		defer ss.Close()
	} else {
		t.Fatalf("expected SQLiteEvidenceSink, got %T", sink)
	}
}
