package ebpf

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/yxshwanth/Interlock/internal/model"
)

// DeferredKillWindow is how long after a connect/sendto SUSPICIOUS trip we wait
// for a write payload before SIGKILL.
const DeferredKillWindow = 100 * time.Millisecond

// SuspiciousConnectTTL is how long a non-allowlisted connect stays eligible
// for write-payload correlation.
const SuspiciousConnectTTL = 5 * time.Second

// SyscallHandler is called for each relevant syscall event.
type SyscallHandler func(ev model.SyscallEvent) model.Decision

// KillResolver maps a BPF event (init-ns PID + cgroup) to PIDs killable in
// the sensor's PID namespace (needed when hostPID ≠ BPF init namespace, e.g. kind).
type KillResolver func(cgroupID uint64, bpfPID int) []int

type pendingConnect struct {
	destIP   string
	destPort int
	at       time.Time
}

type pendingKill struct {
	pid int
	at  time.Time
}

// Sensor manages the eBPF probe lifecycle.
type Sensor struct {
	loader         *Loader
	handler        SyscallHandler
	killResolver   KillResolver
	log            *log.Logger
	stopCh         chan struct{}
	wg             sync.WaitGroup

	cfgMu          sync.RWMutex
	allowlist      map[string]bool
	sensitivePaths []string

	mu              sync.Mutex
	suspiciousByPID map[int]pendingConnect
	deferredKills   map[int]pendingKill
}

// NewSensor creates a Sensor. allowedIPs are the egress allowlist.
// sensitivePaths are pathname prefixes for openat trips (empty = ignore openat).
func NewSensor(allowedIPs []string, sensitivePaths []string, handler SyscallHandler) (*Sensor, error) {
	loader, err := NewLoader()
	if err != nil {
		return nil, fmt.Errorf("sensor: %w", err)
	}

	allow := make(map[string]bool, len(allowedIPs))
	for _, ip := range allowedIPs {
		allow[ip] = true
	}

	return &Sensor{
		loader:          loader,
		allowlist:       allow,
		sensitivePaths:  append([]string(nil), sensitivePaths...),
		handler:         handler,
		log:             log.New(os.Stderr, "[sensor] ", log.LstdFlags),
		stopCh:          make(chan struct{}),
		suspiciousByPID: make(map[int]pendingConnect),
		deferredKills:   make(map[int]pendingKill),
	}, nil
}

// SetKillResolver sets optional PID translation for SIGKILL targets.
func (s *Sensor) SetKillResolver(r KillResolver) {
	s.killResolver = r
}

// SetPayloadCaptureBytes updates the kernel write/sendto capture window.
func (s *Sensor) SetPayloadCaptureBytes(n int) error {
	if s == nil || s.loader == nil {
		return fmt.Errorf("sensor: loader not ready")
	}
	return s.loader.SetPayloadCaptureBytes(n)
}

// UpdateAllowlist replaces the egress allowlist (SIGHUP hot-reload).
func (s *Sensor) UpdateAllowlist(allowedIPs []string) {
	allow := make(map[string]bool, len(allowedIPs))
	for _, ip := range allowedIPs {
		allow[ip] = true
	}
	s.cfgMu.Lock()
	s.allowlist = allow
	s.cfgMu.Unlock()
	s.log.Printf("allowlist updated: %d entries", len(allow))
}

// UpdateSensitivePaths replaces openat sensitive path prefixes (SIGHUP hot-reload).
func (s *Sensor) UpdateSensitivePaths(paths []string) {
	cp := append([]string(nil), paths...)
	s.cfgMu.Lock()
	s.sensitivePaths = cp
	s.cfgMu.Unlock()
	s.log.Printf("sensitive_paths updated: %d prefixes", len(cp))
}

func (s *Sensor) isAllowlisted(destIP string) bool {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.allowlist[destIP] || s.allowlist[destIPNormalized(destIP)]
}

func (s *Sensor) matchesSensitivePath(path string) bool {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	if len(s.sensitivePaths) == 0 || path == "" {
		return false
	}
	return pathMatchesSensitive(path, s.sensitivePaths)
}

// AddPIDs adds the given PIDs to the BPF filter map.
func (s *Sensor) AddPIDs(pids ...int) error {
	for _, pid := range pids {
		if err := s.loader.AddPID(pid); err != nil {
			return err
		}
		s.log.Printf("watching PID %d", pid)
	}
	return nil
}

// RemovePIDs removes PIDs from the BPF filter map.
func (s *Sensor) RemovePIDs(pids ...int) error {
	for _, pid := range pids {
		if err := s.loader.RemovePID(pid); err != nil {
			return err
		}
		s.log.Printf("stopped watching PID %d", pid)
		s.mu.Lock()
		delete(s.suspiciousByPID, pid)
		delete(s.deferredKills, pid)
		s.mu.Unlock()
	}
	return nil
}

// AddCgroupIDs watches tasks by cgroup v2 ID (cross-PID-namespace safe).
func (s *Sensor) AddCgroupIDs(ids ...uint64) error {
	for _, id := range ids {
		if id == 0 {
			continue
		}
		if err := s.loader.AddCgroupID(id); err != nil {
			return err
		}
		s.log.Printf("watching cgroup id=%d", id)
	}
	return nil
}

// RemoveCgroupIDs stops watching cgroups.
func (s *Sensor) RemoveCgroupIDs(ids ...uint64) error {
	for _, id := range ids {
		if id == 0 {
			continue
		}
		if err := s.loader.RemoveCgroupID(id); err != nil {
			return err
		}
		s.log.Printf("stopped watching cgroup id=%d", id)
	}
	return nil
}

func (s *Sensor) containPIDs(cgroupID uint64, bpfPID int, reason string) {
	targets := []int{bpfPID}
	if s.killResolver != nil {
		if resolved := s.killResolver(cgroupID, bpfPID); len(resolved) > 0 {
			targets = resolved
		}
	}
	for _, pid := range targets {
		s.log.Printf("KILL-ON-DETECT: SIGKILL pid %d (%s)", pid, reason)
		s.cancelDeferredKill(pid)
		KillProcess(pid)
	}
}

func (s *Sensor) scheduleContain(cgroupID uint64, bpfPID int, comm string) {
	targets := []int{bpfPID}
	if s.killResolver != nil {
		if resolved := s.killResolver(cgroupID, bpfPID); len(resolved) > 0 {
			targets = resolved
		}
	}
	for _, pid := range targets {
		s.scheduleKill(pid, comm)
	}
}

// Start begins the event-reading goroutine. Call Stop() to shut down.
func (s *Sensor) Start() {
	s.wg.Add(2)
	go s.readLoop()
	go s.killLoop()
}

func (s *Sensor) killLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.flushDeferredKills()
		}
	}
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

		if raw.Connect != nil {
			s.handleConnect(raw.Connect)
		}
		if raw.Write != nil {
			s.handleWrite(raw.Write)
		}
		if raw.Sendto != nil {
			s.handleSendto(raw.Sendto)
		}
		if raw.Openat != nil {
			s.handleOpenat(raw.Openat)
		}
	}
}

func (s *Sensor) handleConnect(raw *ConnectEvent) {
	destIP := raw.DestIPString()
	s.log.Printf("connect observed: pid=%d cgroup=%d comm=%s dest=%s:%d",
		int(raw.PID), raw.CgroupID, raw.CommString(), destIP, int(raw.DestPort))
	if s.isAllowlisted(destIP) {
		s.log.Printf("connect allowlisted, ignoring: dest=%s", destIP)
		return
	}

	pid := int(raw.PID)
	s.mu.Lock()
	s.suspiciousByPID[pid] = pendingConnect{
		destIP:   destIP,
		destPort: int(raw.DestPort),
		at:       time.Now(),
	}
	s.mu.Unlock()

	ev := model.SyscallEvent{
		TSMono:      int64(raw.TSNs),
		PID:         pid,
		TID:         int(raw.TID),
		Comm:        raw.CommString(),
		Syscall:     "connect",
		DestIP:      destIP,
		DestPort:    int(raw.DestPort),
		Allowlisted: false,
		CgroupID:    raw.CgroupID,
	}

	s.log.Printf("connect detected: pid=%d comm=%s dest=%s:%d",
		ev.PID, ev.Comm, ev.DestIP, ev.DestPort)

	if s.handler == nil {
		return
	}
	decision := s.handler(ev)
	if decision.Action == model.ActionContained {
		s.scheduleContain(raw.CgroupID, pid, raw.CommString())
	}
}

func (s *Sensor) handleWrite(raw *WriteEvent) {
	pid := int(raw.PID)
	s.mu.Lock()
	pc, ok := s.suspiciousByPID[pid]
	if ok && time.Since(pc.at) > SuspiciousConnectTTL {
		delete(s.suspiciousByPID, pid)
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		return
	}

	ev := model.SyscallEvent{
		TSMono:         int64(raw.TSNs),
		PID:            pid,
		TID:            int(raw.TID),
		Comm:           raw.CommString(),
		Syscall:        "write",
		DestIP:         pc.destIP,
		DestPort:       pc.destPort,
		Allowlisted:    false,
		PayloadExcerpt: string(raw.Payload),
		CgroupID:       raw.CgroupID,
	}

	s.log.Printf("write payload captured: pid=%d fd=%d len=%d (correlated to %s:%d)",
		ev.PID, raw.FD, raw.Len, pc.destIP, pc.destPort)

	if s.handler == nil {
		return
	}
	decision := s.handler(ev)
	if decision.Action == model.ActionContained {
		s.containPIDs(raw.CgroupID, pid, "after write")
	}
}

func (s *Sensor) handleSendto(raw *SendtoEvent) {
	destIP := raw.DestIPString()
	if s.isAllowlisted(destIP) {
		return
	}

	pid := int(raw.PID)
	port := int(raw.DestPort)

	// Arm write correlation for the same PID (TCP-style follow-up writes).
	s.mu.Lock()
	s.suspiciousByPID[pid] = pendingConnect{
		destIP:   destIP,
		destPort: port,
		at:       time.Now(),
	}
	s.mu.Unlock()

	syscallName := "sendto"
	if port == 53 {
		syscallName = "dns"
	}

	ev := model.SyscallEvent{
		TSMono:         int64(raw.TSNs),
		PID:            pid,
		TID:            int(raw.TID),
		Comm:           raw.CommString(),
		Syscall:        syscallName,
		DestIP:         destIP,
		DestPort:       port,
		Allowlisted:    false,
		PayloadExcerpt: string(raw.Payload),
		CgroupID:       raw.CgroupID,
	}

	s.log.Printf("%s detected: pid=%d dest=%s:%d len=%d",
		syscallName, ev.PID, ev.DestIP, ev.DestPort, raw.Len)

	if s.handler == nil {
		return
	}
	decision := s.handler(ev)
	if decision.Action != model.ActionContained {
		return
	}
	if decision.Verdict == model.VerdictExfil {
		s.containPIDs(raw.CgroupID, pid, "after "+syscallName+" EXFIL")
		return
	}
	// Only EXFIL hard-contains; SUSPICIOUS is detected_only (no deferred kill).
}

func (s *Sensor) handleOpenat(raw *OpenatEvent) {
	if !s.matchesSensitivePath(raw.Path) {
		return
	}

	ev := model.SyscallEvent{
		TSMono:      int64(raw.TSNs),
		PID:         int(raw.PID),
		TID:         int(raw.TID),
		Comm:        raw.CommString(),
		Syscall:     "openat",
		Path:        raw.Path,
		Allowlisted: false,
		CgroupID:    raw.CgroupID,
	}

	s.log.Printf("openat sensitive path: pid=%d path=%s", ev.PID, ev.Path)

	if s.handler == nil {
		return
	}
	decision := s.handler(ev)
	if decision.Action == model.ActionContained {
		s.containPIDs(raw.CgroupID, int(raw.PID), "after openat")
	}
}

func pathMatchesSensitive(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (s *Sensor) scheduleKill(pid int, comm string) {
	s.mu.Lock()
	s.deferredKills[pid] = pendingKill{pid: pid, at: time.Now()}
	s.mu.Unlock()
	s.log.Printf("KILL deferred %s: pid %d (%s) — waiting for write payload", DeferredKillWindow, pid, comm)
}

func (s *Sensor) cancelDeferredKill(pid int) {
	s.mu.Lock()
	delete(s.deferredKills, pid)
	s.mu.Unlock()
}

func (s *Sensor) flushDeferredKills() {
	now := time.Now()
	var due []int
	s.mu.Lock()
	for pid, pk := range s.deferredKills {
		if now.Sub(pk.at) >= DeferredKillWindow {
			due = append(due, pid)
			delete(s.deferredKills, pid)
		}
	}
	s.mu.Unlock()
	for _, pid := range due {
		s.log.Printf("KILL-ON-DETECT: sending SIGKILL to pid %d (deferred window elapsed)", pid)
		KillProcess(pid)
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
func KillProcess(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

// Stop shuts down the sensor.
func (s *Sensor) Stop() {
	close(s.stopCh)
	s.loader.reader.Close()
	s.wg.Wait()
	s.loader.Close()
	s.log.Println("sensor stopped")
}

// DropCount returns kernel-side ring buffer reserve failures.
func (s *Sensor) DropCount() (uint64, error) {
	return s.loader.DropCount()
}

// FilterCounts returns watched PID and cgroup filter map sizes.
func (s *Sensor) FilterCounts() (pids, cgroups int, err error) {
	return s.loader.FilterCounts()
}

func destIPNormalized(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	return parsed.String()
}
