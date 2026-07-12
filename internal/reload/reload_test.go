package reload_test

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/observability"
	"github.com/yxshwanth/Interlock/internal/reload"
)

func TestDiffNonReloadable(t *testing.T) {
	old := &config.Config{Enforcement: "block"}
	newCfg := &config.Config{Enforcement: "monitor"}
	w := reload.DiffNonReloadable(old, newCfg)
	if len(w) == 0 {
		t.Fatal("expected enforcement warning")
	}
}

func TestApplyReloadable_Observers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	inner, err := engine.NewJSONLEvidenceSink(path)
	if err != nil {
		t.Fatal(err)
	}
	async := engine.NewAsyncEvidenceSink(inner, "block", 8, nil)
	defer async.Close()

	metrics := observability.NewMetrics()
	rt := &reload.Runtime{
		Logger:  log.New(os.Stderr, "", 0),
		Metrics: metrics,
		Async:   async,
		Cfg: &config.Config{
			Enforcement: "block",
		},
	}

	newCfg := &config.Config{
		Enforcement: "block",
		Alerting: config.AlertingConfig{
			Webhook: config.WebhookConfig{
				// disabled (empty url)
			},
		},
		SIEM: config.SIEMConfig{
			Format: "ocsf",
			Path:   filepath.Join(dir, "ocsf.jsonl"),
		},
	}
	summary := rt.ApplyReloadable(newCfg)
	if summary == "" {
		t.Fatal("expected summary")
	}
	if rt.CurrentCfg() != newCfg {
		t.Fatal("cfg not updated")
	}
	if rt.SIEM == nil {
		t.Fatal("expected SIEM exporter after reload")
	}
}
