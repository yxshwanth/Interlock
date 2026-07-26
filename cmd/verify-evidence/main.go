package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/model"
	_ "modernc.org/sqlite"
)

func main() {
	backend := flag.String("backend", "jsonl", "evidence backend: jsonl | sqlite")
	path := flag.String("path", "evidence.jsonl", "path to evidence.jsonl or evidence.db")
	flag.Parse()

	records, err := loadRecords(*backend, *path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-evidence: load: %v\n", err)
		os.Exit(2)
	}

	if len(records) == 0 {
		fmt.Printf("ok: empty evidence store (%s)\n", *path)
		return
	}

	if err := engine.VerifyChain(records); err != nil {
		if b, ok := err.(*engine.ChainBreak); ok {
			fmt.Fprintf(os.Stderr, "FAIL: record %d: %s\n", b.Index, b.Reason)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "verify-evidence: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("ok: %d record(s) — chain intact (%s)\n", len(records), *path)
}

func loadRecords(backend, path string) ([]model.EvidenceRecord, error) {
	switch backend {
	case "jsonl", "":
		return loadJSONL(path)
	case "sqlite":
		return loadSQLite(path)
	default:
		return nil, fmt.Errorf("backend must be jsonl or sqlite, got %q", backend)
	}
}

func loadJSONL(path string) ([]model.EvidenceRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []model.EvidenceRecord
	line := 0
	for scanner.Scan() {
		line++
		b := scanner.Bytes()
		if len(b) == 0 {
			continue
		}
		var rec model.EvidenceRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, rec)
	}
	return out, scanner.Err()
}

func loadSQLite(path string) ([]model.EvidenceRecord, error) {
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
	i := 0
	for rows.Next() {
		i++
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var rec model.EvidenceRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return nil, fmt.Errorf("row %d: %w", i, err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
