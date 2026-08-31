package engine

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/yxshwanth/Interlock/internal/model"
	_ "modernc.org/sqlite"
)

// SQLiteEvidenceSink persists EvidenceRecords in SQLite with optional retention.
// Each Emit seals the record into an append-only hash chain. Pre-upgrade rows
// without chain columns are not retroactively chained — VerifyChain on a
// mixed DB may fail until operators rotate or accept a fresh chain tip.
type SQLiteEvidenceSink struct {
	db         *sql.DB
	dir        string
	maxRecords int
	mu         sync.Mutex
	lastHash   string
	nextSeq    uint64
}

// NewSQLiteEvidenceSink opens (or creates) the SQLite database at path.
func NewSQLiteEvidenceSink(path string, maxRecords int) (*SQLiteEvidenceSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return nil, fmt.Errorf("creating evidence dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite evidence %s: %w", path, err)
	}
	if err := initEvidenceSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	lastHash, nextSeq, err := loadSQLiteChainTip(db)
	if err != nil {
		db.Close()
		return nil, err
	}

	return &SQLiteEvidenceSink{
		db:         db,
		dir:        filepath.Dir(path),
		maxRecords: maxRecords,
		lastHash:   lastHash,
		nextSeq:    nextSeq,
	}, nil
}

func initEvidenceSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS evidence (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			trip_ts INTEGER NOT NULL,
			session_id TEXT NOT NULL,
			record_json TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_evidence_trip_ts ON evidence(trip_ts);
	`)
	if err != nil {
		return fmt.Errorf("init evidence schema: %w", err)
	}
	if err := migrateEvidenceChainColumns(db); err != nil {
		return fmt.Errorf("migrate evidence chain columns: %w", err)
	}
	if err := migrateEvidenceQueryColumns(db); err != nil {
		return fmt.Errorf("migrate evidence query columns: %w", err)
	}
	if err := backfillEvidenceQueryColumns(db); err != nil {
		return fmt.Errorf("backfill evidence query columns: %w", err)
	}
	return nil
}

func migrateEvidenceChainColumns(db *sql.DB) error {
	cols, err := sqliteTableColumns(db, "evidence")
	if err != nil {
		return fmt.Errorf("list evidence columns: %w", err)
	}
	add := func(name, decl string) error {
		if cols[name] {
			return nil
		}
		_, err := db.Exec(fmt.Sprintf(`ALTER TABLE evidence ADD COLUMN %s %s`, name, decl))
		if err != nil {
			return fmt.Errorf("adding evidence.%s: %w", name, err)
		}
		cols[name] = true
		return nil
	}
	if err := add("chain_seq", "INTEGER"); err != nil {
		return fmt.Errorf("migrate chain_seq: %w", err)
	}
	if err := add("prev_hash", "TEXT"); err != nil {
		return fmt.Errorf("migrate prev_hash: %w", err)
	}
	if err := add("hash", "TEXT"); err != nil {
		return fmt.Errorf("migrate hash: %w", err)
	}
	return nil
}

func migrateEvidenceQueryColumns(db *sql.DB) error {
	cols, err := sqliteTableColumns(db, "evidence")
	if err != nil {
		return fmt.Errorf("list evidence columns: %w", err)
	}
	add := func(name, decl string) error {
		if cols[name] {
			return nil
		}
		_, err := db.Exec(fmt.Sprintf(`ALTER TABLE evidence ADD COLUMN %s %s`, name, decl))
		if err != nil {
			return fmt.Errorf("adding evidence.%s: %w", name, err)
		}
		cols[name] = true
		return nil
	}
	if err := add("verdict", "TEXT"); err != nil {
		return fmt.Errorf("migrate verdict: %w", err)
	}
	if err := add("pod_name", "TEXT"); err != nil {
		return fmt.Errorf("migrate pod_name: %w", err)
	}
	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_evidence_session_id ON evidence(session_id);
		CREATE INDEX IF NOT EXISTS idx_evidence_verdict ON evidence(verdict);
		CREATE INDEX IF NOT EXISTS idx_evidence_pod_name ON evidence(pod_name);
	`)
	if err != nil {
		return fmt.Errorf("creating evidence query indexes: %w", err)
	}
	return nil
}

// backfillEvidenceQueryColumns fills verdict/pod_name from record_json for legacy rows.
func backfillEvidenceQueryColumns(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT id, record_json FROM evidence
		WHERE verdict IS NULL OR (pod_name IS NULL AND record_json LIKE '%"pod_context"%')
	`)
	if err != nil {
		return fmt.Errorf("select evidence for query backfill: %w", err)
	}
	defer rows.Close()

	type row struct {
		id  int64
		raw string
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.raw); err != nil {
			return err
		}
		pending = append(pending, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range pending {
		var rec model.EvidenceRecord
		if err := json.Unmarshal([]byte(r.raw), &rec); err != nil {
			continue
		}
		podName := ""
		if rec.Pod != nil {
			podName = rec.Pod.PodName
		}
		_, err := db.Exec(`UPDATE evidence SET verdict = ?, pod_name = ? WHERE id = ?`,
			string(rec.Verdict), podName, r.id)
		if err != nil {
			return fmt.Errorf("backfill evidence id=%d: %w", r.id, err)
		}
	}
	return nil
}

func sqliteTableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return nil, fmt.Errorf("pragma table_info(%s): %w", table, err)
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

func loadSQLiteChainTip(db *sql.DB) (lastHash string, nextSeq uint64, err error) {
	var hash sql.NullString
	var seq sql.NullInt64
	err = db.QueryRowContext(context.Background(),
		`SELECT hash, chain_seq FROM evidence WHERE hash IS NOT NULL AND hash != '' ORDER BY id DESC LIMIT 1`).
		Scan(&hash, &seq)
	if err == sql.ErrNoRows {
		// Fall back: count rows and try record_json tip for pre-upgrade DBs
		// that already have sealed JSON but empty dedicated columns.
		var count int
		if qerr := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM evidence`).Scan(&count); qerr != nil {
			return "", 0, fmt.Errorf("count evidence for chain tip: %w", qerr)
		}
		if count == 0 {
			return "", 0, nil
		}
		var raw string
		qerr := db.QueryRowContext(context.Background(),
			`SELECT record_json FROM evidence ORDER BY id DESC LIMIT 1`).Scan(&raw)
		if qerr != nil {
			return "", 0, fmt.Errorf("load evidence chain tip json: %w", qerr)
		}
		var rec model.EvidenceRecord
		if uerr := json.Unmarshal([]byte(raw), &rec); uerr != nil {
			// Unchained legacy row — start a fresh chain after existing rows.
			return "", uint64(count), nil
		}
		if rec.Hash == "" {
			return "", uint64(count), nil
		}
		return rec.Hash, uint64(count), nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("load evidence chain tip: %w", err)
	}
	if !hash.Valid || hash.String == "" {
		return "", 0, nil
	}
	return hash.String, uint64(seq.Int64) + 1, nil
}

// Emit seals rec into the hash chain, inserts it, and prunes to maxRecords when configured.
func (s *SQLiteEvidenceSink) Emit(rec model.EvidenceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := SealEvidenceRecord(&rec, s.nextSeq, s.lastHash); err != nil {
		return err
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshaling evidence: %w", err)
	}

	podName := ""
	if rec.Pod != nil {
		podName = rec.Pod.PodName
	}

	_, err = s.db.ExecContext(context.Background(),
		`INSERT INTO evidence (trip_ts, session_id, record_json, chain_seq, prev_hash, hash, verdict, pod_name)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.TripTS, rec.SessionID, string(data), rec.ChainSeq, rec.PrevHash, rec.Hash,
		string(rec.Verdict), podName)
	if err != nil {
		return fmt.Errorf("insert evidence: %w", err)
	}

	s.lastHash = rec.Hash
	s.nextSeq++

	if s.maxRecords > 0 {
		if err := s.pruneLocked(); err != nil {
			return err
		}
	}

	return writeStandaloneEvidence(s.dir, rec)
}

func (s *SQLiteEvidenceSink) pruneLocked() error {
	var count int
	if err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM evidence`).Scan(&count); err != nil {
		return fmt.Errorf("count evidence: %w", err)
	}
	overflow := count - s.maxRecords
	if overflow <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(context.Background(), `
		DELETE FROM evidence WHERE id IN (
			SELECT id FROM evidence ORDER BY trip_ts ASC LIMIT ?
		)`, overflow)
	if err != nil {
		return fmt.Errorf("prune evidence: %w", err)
	}
	return nil
}

// Count returns the number of stored evidence records.
func (s *SQLiteEvidenceSink) Count() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM evidence`).Scan(&n)
	return n, err
}

// EvidenceQuery filters stored evidence records. Empty fields match any value.
type EvidenceQuery struct {
	SessionID string
	Verdict   string // exact match; empty = any
	PodName   string
	Limit     int // default 100, max 1000
}

// Query returns matching evidence records ordered by trip_ts descending.
func (s *SQLiteEvidenceSink) Query(ctx context.Context, q EvidenceQuery) ([]model.EvidenceRecord, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("sqlite evidence sink closed")
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var clauses []string
	var args []any
	if q.SessionID != "" {
		clauses = append(clauses, "session_id = ?")
		args = append(args, q.SessionID)
	}
	if q.Verdict != "" {
		clauses = append(clauses, "verdict = ?")
		args = append(args, q.Verdict)
	}
	if q.PodName != "" {
		clauses = append(clauses, "pod_name = ?")
		args = append(args, q.PodName)
	}
	sqlStr := `SELECT record_json FROM evidence`
	if len(clauses) > 0 {
		sqlStr += " WHERE " + strings.Join(clauses, " AND ")
	}
	sqlStr += " ORDER BY trip_ts DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, fmt.Errorf("query evidence: %w", err)
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
			return nil, fmt.Errorf("unmarshal evidence: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// Close closes the database.
func (s *SQLiteEvidenceSink) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
