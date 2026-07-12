package reload

import (
	"log"
	"sync"

	"github.com/yxshwanth/Interlock/internal/alerting"
	"github.com/yxshwanth/Interlock/internal/config"
	interlockebpf "github.com/yxshwanth/Interlock/internal/ebpf"
	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/observability"
	"github.com/yxshwanth/Interlock/internal/siem"
)

// Runtime holds live references updated on SIGHUP.
type Runtime struct {
	mu       sync.Mutex
	Logger   *log.Logger
	Metrics  *observability.Metrics
	Async    *engine.AsyncEvidenceSink
	Sensor   *interlockebpf.Sensor
	Webhook  *alerting.WebhookNotifier
	SIEM     *siem.Exporter
	Cfg      *config.Config
}

// CurrentCfg returns the last applied config.
func (r *Runtime) CurrentCfg() *config.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Cfg
}

// ApplyReloadable updates allowlist, sensitive_paths, alerting, and siem from newCfg.
// Returns a human-readable summary of what changed. Does not mutate enforcement/transport/etc.
func (r *Runtime) ApplyReloadable(newCfg *config.Config) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var parts []string
	if r.Sensor != nil {
		r.Sensor.UpdateAllowlist(newCfg.EgressAllowlist)
		r.Sensor.UpdateSensitivePaths(newCfg.SensitivePaths)
		_ = r.Sensor.SetPayloadCaptureBytes(newCfg.EBPF.PayloadCaptureBytesOrDefault())
		parts = append(parts, "allowlist", "sensitive_paths", "payload_capture_bytes")
	}

	oldWh, oldSIEM := r.Webhook, r.SIEM
	wh := alerting.NewWebhookNotifier(newCfg.Alerting.Webhook, r.Metrics)
	exp, err := siem.NewExporter(newCfg.SIEM, r.Metrics)
	if err != nil {
		if r.Logger != nil {
			r.Logger.Printf("[SECURITY] SIEM reload failed — keeping previous exporter: %v", err)
		}
		exp = oldSIEM
	} else {
		parts = append(parts, "siem")
	}
	r.Webhook = wh
	if err == nil {
		r.SIEM = exp
	}
	parts = append(parts, "alerting")

	if r.Async != nil {
		r.Async.SetEmitObserver(engine.MultiEmitObserver{r.Metrics, r.Webhook, r.SIEM})
	}

	// Close previous notifiers after swap so in-flight deliveries finish on old instances.
	if oldWh != nil && oldWh != r.Webhook {
		oldWh.Close()
	}
	if err == nil && oldSIEM != nil && oldSIEM != r.SIEM {
		oldSIEM.Close()
	}

	r.Cfg = newCfg
	if len(parts) == 0 {
		return "observers"
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += "," + parts[i]
	}
	return out
}

// CloseNotifiers drains webhook/SIEM on shutdown.
func (r *Runtime) CloseNotifiers() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Webhook != nil {
		r.Webhook.Close()
	}
	if r.SIEM != nil {
		r.SIEM.Close()
	}
}

// DiffNonReloadable returns warnings for fields that require a process restart.
func DiffNonReloadable(old, new *config.Config) []string {
	if old == nil || new == nil {
		return nil
	}
	var w []string
	if old.Enforcement != new.Enforcement {
		w = append(w, "enforcement (restart required)")
	}
	if old.Transport != new.Transport {
		w = append(w, "transport (restart required)")
	}
	if old.Observability.Listen != new.Observability.Listen ||
		old.Observability.MetricsPath != new.Observability.MetricsPath ||
		old.Observability.HealthPath != new.Observability.HealthPath {
		w = append(w, "observability.listen (restart required)")
	}
	if old.Evidence.Backend != new.Evidence.Backend || old.Evidence.Path != new.Evidence.Path {
		w = append(w, "evidence backend/path (restart required)")
	}
	if len(old.Servers) != len(new.Servers) {
		w = append(w, "servers (restart required)")
	}
	return w
}
