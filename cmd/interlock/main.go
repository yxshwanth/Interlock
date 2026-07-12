package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yxshwanth/Interlock/internal/alerting"
	"github.com/yxshwanth/Interlock/internal/bridge"
	"github.com/yxshwanth/Interlock/internal/config"
	interlockebpf "github.com/yxshwanth/Interlock/internal/ebpf"
	"github.com/yxshwanth/Interlock/internal/engine"
	"github.com/yxshwanth/Interlock/internal/k8s"
	"github.com/yxshwanth/Interlock/internal/model"
	"github.com/yxshwanth/Interlock/internal/observability"
	"github.com/yxshwanth/Interlock/internal/proxy"
	mcphttp "github.com/yxshwanth/Interlock/internal/proxy/http"
	"github.com/yxshwanth/Interlock/internal/reload"
	"github.com/yxshwanth/Interlock/internal/siem"
)

// version is set at link time by release builds:
//
//	-ldflags="-X main.version=v0.3.0"
var version = "dev"

func main() {
	cfgPath := flag.String("config", "interlock.yaml", "path to Interlock config file")
	logPath := flag.String("log", "events.jsonl", "path to JSONL event log (empty to disable)")
	evidencePath := flag.String("evidence", "evidence.jsonl", "path to evidence store (empty to disable)")
	enableEBPF := flag.Bool("ebpf", false, "enable eBPF connect() sensor (requires root)")
	mode := flag.String("mode", "proxy", "run mode: proxy (default) or sensor (DaemonSet, no MCP proxy)")
	kubeconfig := flag.String("kubeconfig", "", "kubeconfig path for sensor mode (default: in-cluster)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	logger := log.New(os.Stderr, "[interlock] ", log.LstdFlags)
	logger.Printf("interlock %s", version)

	switch strings.ToLower(*mode) {
	case "sensor":
		if err := runSensorMode(logger, *cfgPath, *logPath, *evidencePath, *enableEBPF, *kubeconfig); err != nil {
			logger.Fatalf("sensor: %v", err)
		}
	case "proxy", "":
		if err := runProxyMode(logger, *cfgPath, *logPath, *evidencePath, *enableEBPF); err != nil {
			logger.Fatalf("proxy: %v", err)
		}
	default:
		logger.Fatalf("unknown --mode %q (want proxy or sensor)", *mode)
	}
}

func runSensorMode(logger *log.Logger, cfgPath, logPath, evidencePath string, enableEBPF bool, kubeconfig string) error {
	if !enableEBPF {
		return fmt.Errorf("--mode=sensor requires --ebpf")
	}

	cfg, err := config.LoadSensor(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	logger.Printf("sensor mode: enforcement=%s evidence=%s allowlist=%d sensitive_paths=%d",
		cfg.Enforcement, cfg.Evidence.Backend, len(cfg.EgressAllowlist), len(cfg.SensitivePaths))

	stats := &proxy.RuntimeStats{}
	evLogger, err := proxy.NewEventLogger(logPath, cfg.Logging, stats)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer evLogger.Close()

	store := engine.NewSessionStore()
	var evidenceSink engine.EvidenceSink
	if evidencePath != "" {
		evidenceSink, err = engine.NewEvidenceSinkWithStats(cfg, evidencePath, engine.AtomicEvidenceDrops{N: &stats.DroppedEvidence})
		if err != nil {
			return fmt.Errorf("evidence sink: %w", err)
		}
		if c, ok := evidenceSink.(interface{ Close() error }); ok {
			defer c.Close()
		}
	}

	eng := engine.NewEngine(store, nil, cfg.Enforcement, evidenceSink)
	eng.Configure(cfg)
	if evLogger != nil {
		eng.SetSecurityAuditSink(evLogger)
	}

	metrics := observability.NewMetrics()
	rt := &reload.Runtime{Logger: logger, Metrics: metrics, Cfg: cfg}
	if async, ok := evidenceSink.(*engine.AsyncEvidenceSink); ok {
		rt.Async = async
	}
	if _, _, obsErr := attachEmitObservers(logger, cfg, rt); obsErr != nil {
		return obsErr
	}
	defer rt.CloseNotifiers()

	attr := k8s.NewPodAttribution()

	handler := func(ev model.SyscallEvent) model.Decision {
		if ev.CgroupID != 0 {
			if a, ok := attr.LookupByCgroup(ev.CgroupID); ok {
				ev.SessionID = a.SessionID
				pod := a.Pod
				ev.Pod = &pod
			}
		}
		if ev.SessionID == "" {
			if a, ok := attr.Lookup(ev.PID); ok {
				ev.SessionID = a.SessionID
				pod := a.Pod
				ev.Pod = &pod
			}
		}
		if ev.Syscall == "openat" && ev.Path != "" && ev.SessionID != "" {
			pids := attr.NodePIDsForCgroup(ev.CgroupID)
			if len(pids) == 0 {
				// Fall back to looking up by BPF pid if somehow in node ns.
				pids = []int{ev.PID}
			}
			if contents, rErr := k8s.ReadContainerFile(pids, ev.Path); rErr == nil {
				ev.FileContents = contents
			} else {
				logger.Printf("WARNING: sensor seed read %s via /proc/*/root: %v", ev.Path, rErr)
			}
		}
		return eng.IngestSyscallSensor(ev)
	}

	sensor, err := interlockebpf.NewSensor(cfg.EgressAllowlist, cfg.SensitivePaths, handler)
	if err != nil {
		return fmt.Errorf("eBPF sensor: %w", err)
	}
	if err := sensor.SetPayloadCaptureBytes(cfg.EBPF.PayloadCaptureBytesOrDefault()); err != nil {
		sensor.Stop()
		return fmt.Errorf("eBPF payload_capture_bytes: %w", err)
	}
	sensor.SetKillResolver(func(cgroupID uint64, bpfPID int) []int {
		if pids := attr.NodePIDsForCgroup(cgroupID); len(pids) > 0 {
			return pids
		}
		return []int{bpfPID}
	})
	defer func() {
		if drops, dropErr := sensor.DropCount(); dropErr == nil {
			stats.EBPFRingbufDrops.Store(drops)
		}
		sensor.Stop()
		logRuntimeStats(logger, stats)
	}()

	sensor.Start()
	logger.Printf("eBPF sensor started (sensor-only mode)")
	rt.Sensor = sensor

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go watchSIGHUP(ctx, logger, cfgPath, true, rt)

	if cfg.TaintBridge.Enabled {
		sock := cfg.TaintBridge.SocketPathOrDefault()
		bridgeSrv := bridge.NewServer(sock, func(msg bridge.RegisterTaintMsg) error {
			sid := k8s.SessionIDForPod(msg.PodUID)
			eng.RegisterRemoteTaint(sid, bridge.ToTaintedValue(msg))
			return nil
		}, logger.Printf)
		if err := bridgeSrv.Listen(); err != nil {
			return fmt.Errorf("taint bridge: %w", err)
		}
		defer bridgeSrv.Close()
		go bridgeSrv.Serve()
		logger.Printf("taint bridge enabled (listen %s)", sock)
	}

	obsSrv, err := observability.Start(cfg.Observability.Listen, cfg.Observability.MetricsPath, cfg.Observability.HealthPath, func() bool {
		return true // sensor already started above
	})
	if err != nil {
		return fmt.Errorf("observability: %w", err)
	}
	if obsSrv != nil {
		defer obsSrv.Close()
		logger.Printf("observability listening on %s (metrics=%s health=%s)",
			cfg.Observability.Listen, cfg.Observability.MetricsPath, cfg.Observability.HealthPath)
		go observability.PollRuntime(ctx, metrics, stats, sensor.DropCount, sensor.FilterCounts, 5*time.Second)
	}

	hooks := k8s.PIDHooks{
		OnWatch: func(pids []int) {
			if len(pids) == 0 {
				return
			}
			if addErr := sensor.AddPIDs(pids...); addErr != nil {
				logger.Printf("WARNING: failed to add PIDs to sensor: %v", addErr)
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
		OnWatchCgroups: func(ids []uint64) {
			if len(ids) == 0 {
				return
			}
			if addErr := sensor.AddCgroupIDs(ids...); addErr != nil {
				logger.Printf("WARNING: failed to add cgroups to sensor: %v", addErr)
			}
		},
		OnUnwatchCgroups: func(ids []uint64) {
			if len(ids) == 0 {
				return
			}
			if remErr := sensor.RemoveCgroupIDs(ids...); remErr != nil {
				logger.Printf("WARNING: failed to remove cgroups from sensor: %v", remErr)
			}
		},
	}

	watcher, err := k8s.NewNodeWatcher(k8s.WatcherConfig{
		Kubeconfig: kubeconfig,
	}, attr, hooks)
	if err != nil {
		return fmt.Errorf("node watcher: %w", err)
	}

	runErr := watcher.Run(ctx)
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	return nil
}

func runProxyMode(logger *log.Logger, cfgPath, logPath, evidencePath string, enableEBPF bool) error {
	stats := &proxy.RuntimeStats{}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	logger.Printf("loaded config: %d server(s), enforcement=%s, transport=%s, evidence=%s",
		len(cfg.Servers), cfg.Enforcement, cfg.Transport.Mode, cfg.Evidence.Backend)

	evLogger, err := proxy.NewEventLogger(logPath, cfg.Logging, stats)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer evLogger.Close()

	store := engine.NewSessionStore()
	tagger := engine.NewTagger(cfg)

	var evidenceSink engine.EvidenceSink
	if evidencePath != "" {
		evidenceSink, err = engine.NewEvidenceSinkWithStats(cfg, evidencePath, engine.AtomicEvidenceDrops{N: &stats.DroppedEvidence})
		if err != nil {
			return fmt.Errorf("evidence sink: %w", err)
		}
		if c, ok := evidenceSink.(interface{ Close() error }); ok {
			defer c.Close()
		}
	}

	eng := engine.NewEngine(store, tagger, cfg.Enforcement, evidenceSink)
	eng.Configure(cfg)
	if evLogger != nil {
		eng.SetSecurityAuditSink(evLogger)
	}

	var bridgeClient *bridge.Client
	if cfg.TaintBridge.Enabled {
		podUID := strings.TrimSpace(os.Getenv("POD_UID"))
		if podUID == "" {
			logger.Printf("WARNING: taint_bridge.enabled but POD_UID unset — bridge forwards disabled")
		} else {
			bridgeClient = bridge.NewClient(cfg.TaintBridge.SocketPathOrDefault())
			defer bridgeClient.Close()
			eng.SetTaintForwarder(func(tvs []model.TaintedValue) {
				for _, tv := range tvs {
					if err := bridgeClient.Register(podUID, tv); err != nil {
						logger.Printf("WARNING: taint bridge forward: %v", err)
					}
				}
			})
			logger.Printf("taint bridge enabled (dial %s, pod_uid=%s)",
				cfg.TaintBridge.SocketPathOrDefault(), podUID)
		}
	}

	metrics := observability.NewMetrics()
	rt := &reload.Runtime{Logger: logger, Metrics: metrics, Cfg: cfg}
	if async, ok := evidenceSink.(*engine.AsyncEvidenceSink); ok {
		rt.Async = async
	}
	if _, _, obsAttachErr := attachEmitObservers(logger, cfg, rt); obsAttachErr != nil {
		return obsAttachErr
	}
	defer rt.CloseNotifiers()

	p := proxy.New(cfg, evLogger, eng)

	var sensor *interlockebpf.Sensor
	var sensorStarted bool
	if enableEBPF {
		handler := func(ev model.SyscallEvent) model.Decision {
			if ev.SessionID == "" {
				sid, _, ok := p.PIDRegistry().Lookup(ev.PID)
				if ok {
					ev.SessionID = sid
				}
			}
			return eng.IngestSyscall(ev)
		}
		s, sErr := interlockebpf.NewSensor(cfg.EgressAllowlist, cfg.SensitivePaths, handler)
		if sErr != nil {
			logger.Printf("WARNING: eBPF sensor failed to initialize: %v", sErr)
			logger.Printf("  (this is expected if not running as root)")
		} else {
			sensor = s
			rt.Sensor = sensor
			if capErr := sensor.SetPayloadCaptureBytes(cfg.EBPF.PayloadCaptureBytesOrDefault()); capErr != nil {
				logger.Printf("WARNING: eBPF payload_capture_bytes: %v", capErr)
			}
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
	go watchSIGHUP(ctx, logger, cfgPath, false, rt)

	obsSrv, obsErr := observability.Start(cfg.Observability.Listen, cfg.Observability.MetricsPath, cfg.Observability.HealthPath, func() bool {
		return true
	})
	if obsErr != nil {
		return fmt.Errorf("observability: %w", obsErr)
	}
	if obsSrv != nil {
		defer obsSrv.Close()
		logger.Printf("observability listening on %s", cfg.Observability.Listen)
		var dropFn observability.DropCountFunc
		var filterFn observability.FilterCountFunc
		if sensor != nil {
			dropFn = sensor.DropCount
			filterFn = sensor.FilterCounts
		}
		go observability.PollRuntime(ctx, metrics, stats, dropFn, filterFn, 5*time.Second)
	}

	defer logRuntimeStats(logger, stats)

	var runErr error
	if cfg.Transport.Mode == "http" {
		if err := p.StartHTTP(ctx); err != nil {
			return fmt.Errorf("proxy start: %w", err)
		}
		httpSrv := mcphttp.NewServer(p, cfg, logger)
		runErr = httpSrv.ListenAndServe(ctx)
	} else {
		runErr = p.Run(ctx)
	}

	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	return nil
}

func logRuntimeStats(logger *log.Logger, stats *proxy.RuntimeStats) {
	if stats == nil {
		return
	}
	dropped := stats.DroppedEvents.Load()
	droppedEvidence := stats.DroppedEvidence.Load()
	ebpfDrops := stats.EBPFRingbufDrops.Load()
	if dropped > 0 || droppedEvidence > 0 || ebpfDrops > 0 {
		logger.Printf("runtime stats: dropped_events=%d dropped_evidence=%d ebpf_ringbuf_drops=%d",
			dropped, droppedEvidence, ebpfDrops)
		if dropped > 0 {
			logger.Printf("[SECURITY] event log backpressure dropped %d events", dropped)
		}
		if droppedEvidence > 0 {
			logger.Printf("[SECURITY] evidence emit backpressure dropped %d records", droppedEvidence)
		}
		if ebpfDrops > 0 {
			logger.Printf("[SECURITY] eBPF ring buffer dropped %d connect events in kernel", ebpfDrops)
		}
	}
}

func attachEmitObservers(logger *log.Logger, cfg *config.Config, rt *reload.Runtime) (*alerting.WebhookNotifier, *siem.Exporter, error) {
	webhook := alerting.NewWebhookNotifier(cfg.Alerting.Webhook, rt.Metrics)
	siemExp, err := siem.NewExporter(cfg.SIEM, rt.Metrics)
	if err != nil {
		return nil, nil, fmt.Errorf("siem: %w", err)
	}
	if webhook != nil {
		logger.Printf("alerting webhook enabled format=%s min_verdict=%s", cfg.Alerting.Webhook.Format, cfg.Alerting.Webhook.MinVerdict)
	}
	if siemExp != nil {
		logger.Printf("SIEM OCSF export enabled path=%q url_set=%v", cfg.SIEM.Path, cfg.SIEM.URL != "")
	}
	rt.Webhook = webhook
	rt.SIEM = siemExp
	if rt.Async != nil {
		rt.Async.SetEmitObserver(engine.MultiEmitObserver{rt.Metrics, webhook, siemExp})
	}
	return webhook, siemExp, nil
}

func watchSIGHUP(ctx context.Context, logger *log.Logger, cfgPath string, sensorMode bool, rt *reload.Runtime) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			var newCfg *config.Config
			var err error
			if sensorMode {
				newCfg, err = config.LoadSensor(cfgPath)
			} else {
				newCfg, err = config.Load(cfgPath)
			}
			if err != nil {
				logger.Printf("[SECURITY] config reload failed — keeping previous config: %v", err)
				continue
			}
			old := rt.CurrentCfg()
			for _, w := range reload.DiffNonReloadable(old, newCfg) {
				logger.Printf("config reload note: %s", w)
			}
			summary := rt.ApplyReloadable(newCfg)
			logger.Printf("config reloaded via SIGHUP (%s)", summary)
		}
	}
}
