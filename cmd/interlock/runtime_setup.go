package main

import (
	"fmt"
	"log"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/model"
	"github.com/yxshwanth/Interlock/internal/observability"
	"github.com/yxshwanth/Interlock/internal/proxy"
	"github.com/yxshwanth/Interlock/internal/reload"
)

// runtimeCore holds components shared by proxy and sensor orchestration.
type runtimeCore struct {
	stats        *model.RuntimeStats
	evLogger     *proxy.EventLogger
	store        *engine.SessionStore
	evidenceSink engine.EvidenceSink
	eng          *engine.Engine
	metrics      *observability.Metrics
	rt           *reload.Runtime
}

func setupRuntimeCore(logger *log.Logger, cfg *config.Config, logPath, evidencePath string, tagger *engine.Tagger) (*runtimeCore, error) {
	stats := &model.RuntimeStats{}
	evLogger, err := proxy.NewEventLogger(logPath, cfg.Logging, stats)
	if err != nil {
		return nil, fmt.Errorf("logger: %w", err)
	}

	store := engine.NewSessionStore()
	var evidenceSink engine.EvidenceSink
	if evidencePath != "" {
		evidenceSink, err = engine.NewEvidenceSinkWithStats(cfg, evidencePath, &stats.DroppedEvidence)
		if err != nil {
			evLogger.Close()
			return nil, fmt.Errorf("evidence sink: %w", err)
		}
	}

	eng := engine.NewEngine(store, tagger, cfg.Enforcement, evidenceSink)
	eng.Configure(cfg)
	if evLogger != nil {
		eng.SetSecurityAuditSink(evLogger)
	}

	metrics := observability.NewMetrics()
	rt := &reload.Runtime{Logger: logger, Metrics: metrics, Cfg: cfg, Engine: eng}
	if async, ok := evidenceSink.(*engine.AsyncEvidenceSink); ok {
		rt.Async = async
	}

	return &runtimeCore{
		stats:        stats,
		evLogger:     evLogger,
		store:        store,
		evidenceSink: evidenceSink,
		eng:          eng,
		metrics:      metrics,
		rt:           rt,
	}, nil
}

func (c *runtimeCore) close() {
	if c.evLogger != nil {
		c.evLogger.Close()
	}
	if c.evidenceSink != nil {
		if closer, ok := c.evidenceSink.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
}

func attachObservability(logger *log.Logger, cfg *config.Config, core *runtimeCore) (func(), error) {
	if _, _, err := attachEmitObservers(logger, cfg, core.rt); err != nil {
		return nil, err
	}
	cleanup := func() { core.rt.CloseNotifiers() }
	return cleanup, nil
}
