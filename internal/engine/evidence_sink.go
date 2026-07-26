package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/yxshwanth/Interlock/internal/model"
)

// JSONLEvidenceSink appends EvidenceRecords as JSONL and writes the latest
// record as a standalone JSON file for the evidence viewer.
// Each Emit seals the record into an append-only hash chain (ChainSeq /
// PrevHash / Hash). On open, an existing file is scanned once to seed the
// chain tip so the chain survives process restart.
type JSONLEvidenceSink struct {
	file     *os.File
	enc      *json.Encoder
	dir      string // directory containing the JSONL file
	mu       sync.Mutex
	lastHash string
	nextSeq  uint64
}

// NewJSONLEvidenceSink opens (or creates) the JSONL file at path.
// If path already exists, the last valid record seeds the hash chain tip.
func NewJSONLEvidenceSink(path string) (*JSONLEvidenceSink, error) {
	lastHash, nextSeq, err := scanJSONLChainTip(path)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening evidence file %s: %w", path, err)
	}

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)

	return &JSONLEvidenceSink{
		file:     f,
		enc:      enc,
		dir:      filepath.Dir(path),
		lastHash: lastHash,
		nextSeq:  nextSeq,
	}, nil
}

// scanJSONLChainTip reads an existing JSONL evidence file and returns the
// last record's Hash and the next ChainSeq. Missing/empty files return ("", 0).
func scanJSONLChainTip(path string) (lastHash string, nextSeq uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, nil
		}
		return "", 0, fmt.Errorf("scanning evidence chain tip %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Evidence records can be large (timelines); match proxy frame budget.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var n uint64
	var tip string
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec model.EvidenceRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return "", 0, fmt.Errorf("scanning evidence chain tip %s line %d: %w", path, n+1, err)
		}
		tip = rec.Hash
		n++
	}
	if err := scanner.Err(); err != nil {
		return "", 0, fmt.Errorf("scanning evidence chain tip %s: %w", path, err)
	}
	return tip, n, nil
}

// Emit seals rec into the hash chain, appends it to the JSONL file, and
// writes a standalone evidence.json for the viewer.
func (s *JSONLEvidenceSink) Emit(rec model.EvidenceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := SealEvidenceRecord(&rec, s.nextSeq, s.lastHash); err != nil {
		return err
	}

	if err := s.enc.Encode(rec); err != nil {
		return fmt.Errorf("writing evidence JSONL: %w", err)
	}

	s.lastHash = rec.Hash
	s.nextSeq++

	return writeStandaloneEvidence(s.dir, rec)
}

// Close flushes and closes the JSONL file.
func (s *JSONLEvidenceSink) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}
