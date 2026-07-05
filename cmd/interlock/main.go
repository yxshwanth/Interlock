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
	evidencePath := flag.String("evidence", "evidence.jsonl", "path to evidence store (empty to disable)")
	enableEBPF := flag.Bool("ebpf", false, "enable eBPF connect() sensor (requires root)")
	flag.Parse()

	logger := log.New(os.Stderr, "[interlock] ", log.LstdFlags)
	stats := &proxy.RuntimeStats{}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	logger.Printf("loaded config: %d server(s), enforcement=%s, transport=%s, evidence=%s",
		len(cfg.Servers), cfg.Enforcement, cfg.Transport.Mode, cfg.Evidence.Backend)

	evLogger, err := proxy.NewEventLogger(*logPath, cfg.Logging, stats)
	if err != nil {
		logger.Fatalf("logger: %v", err)
	}
	defer evLogger.Close()

	store := engine.NewSessionStore()
	tagger := engine.NewTagger(cfg)

	var evidenceSink engine.EvidenceSink
	if *evidencePath != "" {
		evidenceSink, err = engine.NewEvidenceSink(cfg, *evidencePath)
		if err != nil {
			logger.Fatalf("evidence sink: %v", err)
		}
		if c, ok := evidenceSink.(interface{ Close() error }); ok {
			defer c.Close()
		}
	}

	eng := engine.NewEngine(store, tagger, cfg.Enforcement, evidenceSink)
	if evLogger != nil {
		eng.SetSecurityAuditSink(evLogger)
	}

	p := proxy.New(cfg, evLogger, eng)

	var sensor *interlockebpf.Sensor
	var sensorStarted bool
	if *enableEBPF {
		handler := func(ev model.SyscallEvent) model.Decision {
			if ev.SessionID == "" {
				sid, _, ok := p.PIDRegistry().Lookup(ev.PID)
				if ok {
					ev.SessionID = sid
				}
			}
			return eng.IngestSyscall(ev)
		}
		s, sErr := interlockebpf.NewSensor(cfg.EgressAllowlist, handler)
		if sErr != nil {
			logger.Printf("WARNING: eBPF sensor failed to initialize: %v", sErr)
			logger.Printf("  (this is expected if not running as root)")
		} else {
			sensor = s
			defer func() {
				if drops, err := sensor.DropCount(); err == nil {
					stats.EBPFRingbufDrops.Store(drops)
				}
				sensor.Stop()
				logRuntimeStats(logger, stats)
			}()

			selfPID := os.Getpid()
			if addErr := sensor.AddPIDs(selfPID); addErr != nil {
				logger.Printf("WARNING: failed to add self PID to sensor: %v", addErr)
			}

			p.SetPIDHooks(proxy.PIDHooks{
				OnWatch: func(pids []int) {
					if len(pids) == 0 {
						return
					}
					if addErr := sensor.AddPIDs(pids...); addErr != nil {
						logger.Printf("WARNING: failed to add PIDs to sensor: %v", addErr)
					}
					if !sensorStarted {
						sensor.Start()
						sensorStarted = true
						logger.Printf("eBPF sensor started (self pid=%d)", selfPID)
					}
				},
				OnUnwatch: func(pids []int) {
					if len(pids) == 0 {
						return
					}
					if remErr := sensor.RemovePIDs(pids...); remErr != nil {
						logger.Printf("WARNING: failed to remove PIDs from sensor: %v", remErr)
					}
				},
			})
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	defer logRuntimeStats(logger, stats)

	var runErr error
	if cfg.Transport.Mode == "http" {
		if err := p.StartHTTP(ctx); err != nil {
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

func logRuntimeStats(logger *log.Logger, stats *proxy.RuntimeStats) {
	if stats == nil {
		return
	}
	dropped := stats.DroppedEvents.Load()
	ebpfDrops := stats.EBPFRingbufDrops.Load()
	if dropped > 0 || ebpfDrops > 0 {
		logger.Printf("runtime stats: dropped_events=%d ebpf_ringbuf_drops=%d", dropped, ebpfDrops)
		if dropped > 0 {
			logger.Printf("[SECURITY] event log backpressure dropped %d events", dropped)
		}
		if ebpfDrops > 0 {
			logger.Printf("[SECURITY] eBPF ring buffer dropped %d connect events in kernel", ebpfDrops)
		}
	}
}
