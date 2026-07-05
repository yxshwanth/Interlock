package engine

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/yxshwanth/Interlock/internal/model"
	_ "modernc.org/sqlite"
)

// SQLiteEvidenceSink persists EvidenceRecords in SQLite with optional retention.
type SQLiteEvidenceSink struct {
	db         *sql.DB
	dir        string
	maxRecords int
	mu         sync.Mutex
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

	return &SQLiteEvidenceSink{
		db:         db,
		dir:        filepath.Dir(path),
		maxRecords: maxRecords,
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
	return nil
}

// Emit inserts a record and prunes to maxRecords when configured.
func (s *SQLiteEvidenceSink) Emit(rec model.EvidenceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshaling evidence: %w", err)
	}

	_, err = s.db.ExecContext(context.Background(),
		`INSERT INTO evidence (trip_ts, session_id, record_json) VALUES (?, ?, ?)`,
		rec.TripTS, rec.SessionID, string(data))
	if err != nil {
		return fmt.Errorf("insert evidence: %w", err)
	}

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

// Close closes the database.
func (s *SQLiteEvidenceSink) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
