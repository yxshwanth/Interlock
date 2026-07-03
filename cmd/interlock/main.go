package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/proxy"
)

func main() {
	cfgPath := flag.String("config", "interlock.yaml", "path to Interlock config file")
	logPath := flag.String("log", "events.jsonl", "path to JSONL event log (empty to disable)")
	evidencePath := flag.String("evidence", "evidence.jsonl", "path to JSONL evidence log")
	flag.Parse()

	logger := log.New(os.Stderr, "[interlock] ", log.LstdFlags)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	logger.Printf("loaded config: %d server(s), enforcement=%s", len(cfg.Servers), cfg.Enforcement)

	evLogger, err := proxy.NewEventLogger(*logPath)
	if err != nil {
		logger.Fatalf("logger: %v", err)
	}
	defer evLogger.Close()

	store := engine.NewSessionStore()
	tagger := engine.NewTagger(cfg)

	var evidenceSink *engine.JSONLEvidenceSink
	if *evidencePath != "" {
		evidenceSink, err = engine.NewJSONLEvidenceSink(*evidencePath)
		if err != nil {
			logger.Fatalf("evidence sink: %v", err)
		}
		defer evidenceSink.Close()
	}

	eng := engine.NewEngine(store, tagger, cfg.Enforcement, evidenceSink)

	p := proxy.New(cfg, evLogger, eng)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := p.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Fatalf("proxy: %v", err)
	}
}
