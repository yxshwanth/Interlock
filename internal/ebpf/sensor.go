package ebpf

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/yxshwanth/Interlock/internal/model"
)

// SyscallHandler is called for each non-allowlisted connect() event.
// It receives the SyscallEvent and returns a Decision. If the decision
// says Action=ActionContained, the sensor will SIGKILL the process.
type SyscallHandler func(ev model.SyscallEvent) model.Decision

// Sensor manages the eBPF connect() probe lifecycle: loads the probe,
// maintains the PID filter, reads events, checks the egress allowlist,
// calls the handler (engine), and enforces kill-on-detect.
type Sensor struct {
	loader    *Loader
	allowlist map[string]bool
	handler   SyscallHandler
	log       *log.Logger
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// NewSensor creates a Sensor. allowedIPs are the egress allowlist entries
// (IPs only, no CIDR in v0.1). handler is called for each non-allowlisted
// event and should return the engine's Decision.
func NewSensor(allowedIPs []string, handler SyscallHandler) (*Sensor, error) {
	loader, err := NewLoader()
	if err != nil {
		return nil, fmt.Errorf("sensor: %w", err)
	}

	allow := make(map[string]bool, len(allowedIPs))
	for _, ip := range allowedIPs {
		allow[ip] = true
	}

	return &Sensor{
		loader:    loader,
		allowlist: allow,
		handler:   handler,
		log:       log.New(os.Stderr, "[sensor] ", log.LstdFlags),
		stopCh:    make(chan struct{}),
	}, nil
}

// AddPIDs adds the given PIDs to the BPF filter map so their connect()
// calls generate events.
func (s *Sensor) AddPIDs(pids ...int) error {
	for _, pid := range pids {
		if err := s.loader.AddPID(pid); err != nil {
			return err
		}
		s.log.Printf("watching PID %d", pid)
	}
	return nil
}

// Start begins the event-reading goroutine. Call Stop() to shut down.
func (s *Sensor) Start() {
	s.wg.Add(1)
	go s.readLoop()
}

func (s *Sensor) readLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		raw, err := s.loader.ReadEvent()
		if err != nil {
			if err == ringbuf.ErrClosed || s.stopping() || errors.Is(err, os.ErrClosed) {
				return
			}
			s.log.Printf("read event error: %v", err)
			continue
		}

		destIP := raw.DestIPString()
		if s.allowlist[destIP] || s.allowlist[destIPNormalized(destIP)] {
			continue
		}

		ev := model.SyscallEvent{
			TSMono:      int64(raw.TSNs),
			PID:         int(raw.PID),
			TID:         int(raw.TID),
			Comm:        raw.CommString(),
			Syscall:     "connect",
			DestIP:      destIP,
			DestPort:    int(raw.DestPort),
			Allowlisted: false,
		}

		s.log.Printf("connect detected: pid=%d comm=%s dest=%s:%d",
			ev.PID, ev.Comm, ev.DestIP, ev.DestPort)

		if s.handler != nil {
			decision := s.handler(ev)
			if decision.Action == model.ActionContained {
				s.log.Printf("KILL-ON-DETECT: sending SIGKILL to pid %d (%s)", ev.PID, ev.Comm)
				KillProcess(ev.PID)
			}
		}
	}
}

func (s *Sensor) stopping() bool {
	select {
	case <-s.stopCh:
		return true
	default:
		return false
	}
}

// KillProcess sends SIGKILL to the process group of the given PID.
// This is immediate and non-graceful — appropriate for a caught attacker.
func KillProcess(pid int) {
	// Kill the entire process group (negative PID).
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	// Also kill the individual process in case Setpgid wasn't used.
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

// Stop shuts down the sensor: closes the ring buffer reader (unblocks
// ReadEvent), waits for the goroutine, then closes BPF resources.
func (s *Sensor) Stop() {
	close(s.stopCh)
	s.loader.reader.Close()
	s.wg.Wait()
	s.loader.Close()
	s.log.Println("sensor stopped")
}

func destIPNormalized(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	return parsed.String()
}
