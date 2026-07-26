package engine

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
	_ "modernc.org/sqlite"
)

func readJSONLRecords(t *testing.T, path string) []model.EvidenceRecord {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []model.EvidenceRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var rec model.EvidenceRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestJSONLEvidenceSink_ChainLinksRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	sink, err := NewJSONLEvidenceSink(path)
	if err != nil {
		t.Fatal(err)
	}

	const n = 5
	for i := 0; i < n; i++ {
		rec := testEvidenceRecord()
		rec.SessionID = "sess"
		rec.TripTS = int64(i + 1)
		if err := sink.Emit(rec); err != nil {
			t.Fatal(err)
		}
	}
	sink.Close()

	records := readJSONLRecords(t, path)
	if len(records) != n {
		t.Fatalf("want %d records, got %d", n, len(records))
	}
	if err := VerifyChain(records); err != nil {
		t.Fatal(err)
	}
	if records[0].PrevHash != "" || records[0].ChainSeq != 0 {
		t.Fatalf("genesis: seq=%d prev=%q", records[0].ChainSeq, records[0].PrevHash)
	}
	for i := 1; i < n; i++ {
		if records[i].PrevHash != records[i-1].Hash {
			t.Fatalf("record %d prev_hash != previous hash", i)
		}
		if records[i].ChainSeq != uint64(i) {
			t.Fatalf("record %d chain_seq=%d", i, records[i].ChainSeq)
		}
		if len(records[i].Hash) != 64 {
			t.Fatalf("record %d hash len=%d", i, len(records[i].Hash))
		}
	}

	// Standalone evidence.json also carries chain fields.
	data, err := os.ReadFile(filepath.Join(dir, "evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	var last model.EvidenceRecord
	if err := json.Unmarshal(data, &last); err != nil {
		t.Fatal(err)
	}
	if last.Hash != records[n-1].Hash || last.ChainSeq != uint64(n-1) {
		t.Fatalf("standalone chain mismatch: %+v", last)
	}
}

func TestJSONLEvidenceSink_ChainSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")

	sink, err := NewJSONLEvidenceSink(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := testEvidenceRecord()
	rec.SessionID = "before-restart"
	if err := sink.Emit(rec); err != nil {
		t.Fatal(err)
	}
	sink.Close()

	before := readJSONLRecords(t, path)
	if len(before) != 1 {
		t.Fatalf("want 1, got %d", len(before))
	}

	sink2, err := NewJSONLEvidenceSink(path)
	if err != nil {
		t.Fatal(err)
	}
	rec2 := testEvidenceRecord()
	rec2.SessionID = "after-restart"
	rec2.TripTS = 99
	if err := sink2.Emit(rec2); err != nil {
		t.Fatal(err)
	}
	sink2.Close()

	all := readJSONLRecords(t, path)
	if len(all) != 2 {
		t.Fatalf("want 2, got %d", len(all))
	}
	if all[1].PrevHash != before[0].Hash {
		t.Fatalf("restart continuity broken: prev=%q want %q", all[1].PrevHash, before[0].Hash)
	}
	if all[1].ChainSeq != 1 {
		t.Fatalf("chain_seq after restart: %d", all[1].ChainSeq)
	}
	if err := VerifyChain(all); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteEvidenceSink_ChainLinksAndRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.db")

	sink, err := NewSQLiteEvidenceSink(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		rec := sampleEvidence("sess")
		rec.TripTS = int64(i + 1)
		if err := sink.Emit(rec); err != nil {
			t.Fatal(err)
		}
	}
	sink.Close()

	recs, err := loadSQLiteRecords(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChain(recs); err != nil {
		t.Fatal(err)
	}

	sink2, err := NewSQLiteEvidenceSink(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	rec := sampleEvidence("after")
	rec.TripTS = 100
	if err := sink2.Emit(rec); err != nil {
		t.Fatal(err)
	}
	sink2.Close()

	recs, err = loadSQLiteRecords(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 4 {
		t.Fatalf("want 4, got %d", len(recs))
	}
	if err := VerifyChain(recs); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteEvidenceSink_SchemaMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE evidence (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			trip_ts INTEGER NOT NULL,
			session_id TEXT NOT NULL,
			record_json TEXT NOT NULL
		);
	`)
	if err != nil {
		t.Fatal(err)
	}
	legacy := sampleEvidence("legacy")
	raw, _ := json.Marshal(legacy)
	_, err = db.Exec(`INSERT INTO evidence (trip_ts, session_id, record_json) VALUES (?, ?, ?)`,
		legacy.TripTS, legacy.SessionID, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	sink, err := NewSQLiteEvidenceSink(path, 0)
	if err != nil {
		t.Fatalf("open migrated: %v", err)
	}
	rec := sampleEvidence("new")
	rec.TripTS = 2
	if err := sink.Emit(rec); err != nil {
		t.Fatal(err)
	}
	sink.Close()

	db2, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	cols, err := sqliteTableColumns(db2, "evidence")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"chain_seq", "prev_hash", "hash"} {
		if !cols[want] {
			t.Fatalf("missing column %s after migration", want)
		}
	}
}

func loadSQLiteRecords(path string) ([]model.EvidenceRecord, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT record_json FROM evidence ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.EvidenceRecord
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var rec model.EvidenceRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func TestVerifyChain_TamperDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	sink, err := NewJSONLEvidenceSink(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		rec := testEvidenceRecord()
		rec.TripTS = int64(i + 1)
		if err := sink.Emit(rec); err != nil {
			t.Fatal(err)
		}
	}
	sink.Close()

	clean := readJSONLRecords(t, path)
	if err := VerifyChain(clean); err != nil {
		t.Fatalf("clean chain: %v", err)
	}

	t.Run("edit_middle", func(t *testing.T) {
		mut := append([]model.EvidenceRecord(nil), clean...)
		mut[1].SessionID = "tampered"
		// Keep stored Hash — recompute would differ
		err := VerifyChain(mut)
		b, ok := err.(*ChainBreak)
		if !ok {
			t.Fatalf("want ChainBreak, got %v", err)
		}
		if b.Index != 1 || b.Reason != "hash mismatch" {
			t.Fatalf("got %+v", b)
		}
	})

	t.Run("delete_middle", func(t *testing.T) {
		mut := []model.EvidenceRecord{clean[0], clean[2], clean[3]}
		err := VerifyChain(mut)
		b, ok := err.(*ChainBreak)
		if !ok {
			t.Fatalf("want ChainBreak, got %v", err)
		}
		if b.Reason != "chain link broken" && !strings.Contains(b.Reason, "seq mismatch") {
			t.Fatalf("unexpected reason: %+v", b)
		}
	})

	t.Run("truncate_tail", func(t *testing.T) {
		// Truncated tail: remaining prefix still verifies.
		prefix := clean[:3]
		if err := VerifyChain(prefix); err != nil {
			t.Fatalf("truncated tail should still verify: %v", err)
		}
	})
}

func TestHashEvidenceRecord_Deterministic(t *testing.T) {
	rec := testEvidenceRecord()
	rec.ChainSeq = 0
	rec.PrevHash = ""
	h1, err := HashEvidenceRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashEvidenceRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("hash not stable: %q vs %q", h1, h2)
	}
	// Hash field itself must not affect the digest.
	rec.Hash = "deadbeef"
	h3, err := HashEvidenceRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if h3 != h1 {
		t.Fatal("Hash field leaked into digest")
	}
}
