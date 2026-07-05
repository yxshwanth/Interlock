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
	interlockebpf "github.com/yxshwanth/Interlock/internal/ebpf"
	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/model"
	"github.com/yxshwanth/Interlock/internal/proxy"
	mcphttp "github.com/yxshwanth/Interlock/internal/proxy/http"
)

func main() {
	cfgPath := flag.String("config", "interlock.yaml", "path to Interlock config file")
	logPath := flag.String("log", "events.jsonl", "path to JSONL event log (empty to disable)")
	evidencePath := flag.String("evidence", "evidence.jsonl", "path to JSONL evidence log")
	enableEBPF := flag.Bool("ebpf", false, "enable eBPF connect() sensor (requires root)")
	flag.Parse()

	logger := log.New(os.Stderr, "[interlock] ", log.LstdFlags)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	logger.Printf("loaded config: %d server(s), enforcement=%s, transport=%s",
		len(cfg.Servers), cfg.Enforcement, cfg.Transport.Mode)

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

	// If eBPF is requested, set up the sensor to start after servers launch.
	var sensor *interlockebpf.Sensor
	if *enableEBPF {
		handler := func(ev model.SyscallEvent) model.Decision {
			return eng.IngestSyscall(ev)
		}
		s, sErr := interlockebpf.NewSensor(cfg.EgressAllowlist, handler)
		if sErr != nil {
			logger.Printf("WARNING: eBPF sensor failed to initialize: %v", sErr)
			logger.Printf("  (this is expected if not running as root)")
		} else {
			sensor = s
			defer sensor.Stop()

			p.OnServersReady(func(childPIDs []int) {
				selfPID := os.Getpid()
				allPIDs := append([]int{selfPID}, childPIDs...)
				if addErr := sensor.AddPIDs(allPIDs...); addErr != nil {
					logger.Printf("WARNING: failed to add PIDs to sensor: %v", addErr)
				}
				sensor.Start()
				logger.Printf("eBPF sensor started, watching %d PIDs", len(allPIDs))
			})
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var runErr error
	if cfg.Transport.Mode == "http" {
		if err := p.Start(ctx); err != nil {
			logger.Fatalf("proxy start: %v", err)
		}
		httpSrv := mcphttp.NewServer(p, cfg, logger)
		runErr = httpSrv.ListenAndServe(ctx)
	} else {
		runErr = p.Run(ctx)
	}

	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		logger.Fatalf("proxy: %v", runErr)
	}
}
