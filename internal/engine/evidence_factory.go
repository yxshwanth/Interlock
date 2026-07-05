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
func NewEvidenceSink(cfg *config.Config, pathOverride string) (EvidenceSink, error) {
	path := cfg.Evidence.Path
	if pathOverride != "" {
		path = pathOverride
	}
	switch cfg.Evidence.Backend {
	case "sqlite":
		return NewSQLiteEvidenceSink(path, cfg.Evidence.MaxRecords)
	default:
		return NewJSONLEvidenceSink(path)
	}
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
