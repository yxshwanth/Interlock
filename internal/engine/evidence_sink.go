package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/yxshwanth/Interlock/internal/model"
)

// JSONLEvidenceSink appends EvidenceRecords as JSONL and writes the latest
// record as a standalone JSON file for the evidence viewer.
type JSONLEvidenceSink struct {
	file    *os.File
	enc     *json.Encoder
	dir     string // directory containing the JSONL file
	mu      sync.Mutex
}

// NewJSONLEvidenceSink opens (or creates) the JSONL file at path.
func NewJSONLEvidenceSink(path string) (*JSONLEvidenceSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening evidence file %s: %w", path, err)
	}

	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)

	return &JSONLEvidenceSink{
		file: f,
		enc:  enc,
		dir:  filepath.Dir(path),
	}, nil
}

// Emit appends a single EvidenceRecord to the JSONL file, writes a
// standalone evidence.json (overwriting any previous one) for the viewer,
// and generates a self-contained evidence_viewer.html with the data embedded.
func (s *JSONLEvidenceSink) Emit(rec model.EvidenceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.enc.Encode(rec); err != nil {
		return fmt.Errorf("writing evidence JSONL: %w", err)
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling evidence JSON: %w", err)
	}

	// Write standalone JSON for the viewer (last record wins).
	standalone := filepath.Join(s.dir, "evidence.json")
	if err := os.WriteFile(standalone, data, 0644); err != nil {
		return fmt.Errorf("writing evidence.json: %w", err)
	}

	return nil
}

// Close flushes and closes the JSONL file.
func (s *JSONLEvidenceSink) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}
