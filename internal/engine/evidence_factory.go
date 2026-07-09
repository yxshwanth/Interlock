package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

// NewEvidenceSink creates an evidence sink from config. pathOverride non-empty replaces cfg.Evidence.Path.
// The returned sink is wrapped in AsyncEvidenceSink so Emit does not block the engine on disk I/O.
func NewEvidenceSink(cfg *config.Config, pathOverride string) (EvidenceSink, error) {
	path := cfg.Evidence.Path
	if pathOverride != "" {
		path = pathOverride
	}
	var inner EvidenceSink
	var err error
	switch cfg.Evidence.Backend {
	case "sqlite":
		inner, err = NewSQLiteEvidenceSink(path, cfg.Evidence.MaxRecords)
	default:
		inner, err = NewJSONLEvidenceSink(path)
	}
	if err != nil {
		return nil, err
	}
	return NewAsyncEvidenceSink(inner, cfg.Evidence.Backpressure, cfg.Evidence.QueueSize, nil), nil
}

// NewEvidenceSinkWithStats is like NewEvidenceSink but records drop-mode overflows on drops.
func NewEvidenceSinkWithStats(cfg *config.Config, pathOverride string, drops EvidenceDropCounter) (EvidenceSink, error) {
	path := cfg.Evidence.Path
	if pathOverride != "" {
		path = pathOverride
	}
	var inner EvidenceSink
	var err error
	switch cfg.Evidence.Backend {
	case "sqlite":
		inner, err = NewSQLiteEvidenceSink(path, cfg.Evidence.MaxRecords)
	default:
		inner, err = NewJSONLEvidenceSink(path)
	}
	if err != nil {
		return nil, err
	}
	return NewAsyncEvidenceSink(inner, cfg.Evidence.Backpressure, cfg.Evidence.QueueSize, drops), nil
}

// writeStandaloneEvidence writes the latest record for the HTML viewer.
func writeStandaloneEvidence(dir string, rec model.EvidenceRecord) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling evidence JSON: %w", err)
	}
	standalone := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(standalone, data, 0644); err != nil {
		return fmt.Errorf("writing evidence.json: %w", err)
	}
	return nil
}
