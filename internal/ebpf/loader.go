package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	eventTypeConnect      uint32 = 1
	eventTypeWrite        uint32 = 2
	eventTypeSendto       uint32 = 3
	eventTypeOpenat       uint32 = 4
	eventTypeLSMDeny      uint32 = 5
	eventTypeWritev       uint32 = 6
	eventTypeSendmsg      uint32 = 7
	afInet                       = 2
	afInet6                      = 10
	payloadMax                   = 1024
	pathMax                      = 128
	defaultPayloadCapture        = 1024
	minPayloadCapture            = 64
	connectHeaderLen             = 72 // type…comm with family+16B dest
	writeHeaderLen               = 56
	sendtoHeaderLen              = 72
)

// ConnectEvent is the Go-side representation of a BPF connect event.
type ConnectEvent struct {
	TSNs     uint64
	PID      uint32
	TID      uint32
	Family   uint8
	DestAddr [16]byte
	DestPort uint16
	CgroupID uint64
	Comm     [16]byte
}

// WriteEvent is the Go-side representation of a BPF write/writev payload excerpt
// (also unnamed sendmsg — correlate like write).
type WriteEvent struct {
	TSNs     uint64
	PID      uint32
	TID      uint32
	FD       uint32
	Len      uint32
	CgroupID uint64
	Comm     [16]byte
	Payload  []byte
	Syscall  string // "write" | "writev" | "sendmsg"
}

// SendtoEvent is a self-contained sendto/named-sendmsg (dest + payload excerpt).
type SendtoEvent struct {
	TSNs     uint64
	PID      uint32
	TID      uint32
	Family   uint8
	DestAddr [16]byte
	DestPort uint16
	Len      uint32
	CgroupID uint64
	Comm     [16]byte
	Payload  []byte
	Syscall  string // "sendto" | "sendmsg" (dns override applied in sensor)
}

// OpenatEvent is a pathname open from a monitored PID.
type OpenatEvent struct {
	TSNs     uint64
	PID      uint32
	TID      uint32
	PathLen  uint32
	CgroupID uint64
	Comm     [16]byte
	Path     string
}

// LSMDenyEvent records a connect() the kernel denied for a quarantined
// PID/cgroup (v0.3 Phase 2, Slice 1 — ebpf.lsm_enforce).
type LSMDenyEvent struct {
	TSNs     uint64
	PID      uint32
	TID      uint32
	CgroupID uint64
	Comm     [16]byte
}

// DestIPString returns the destination IP (IPv4 or IPv6).
func (e *ConnectEvent) DestIPString() string {
	return destIPString(e.Family, e.DestAddr)
}

func (e *SendtoEvent) DestIPString() string {
	return destIPString(e.Family, e.DestAddr)
}

func destIPString(family uint8, addr [16]byte) string {
	switch family {
	case afInet:
		ip := net.IP(addr[:4])
		return ip.String()
	case afInet6:
		ip := net.IP(addr[:])
		return ip.String()
	default:
		return ""
	}
}

// CommString returns the process comm as a trimmed string.
func (e *ConnectEvent) CommString() string { return nullTerm(e.Comm[:]) }
func (e *WriteEvent) CommString() string   { return nullTerm(e.Comm[:]) }
func (e *SendtoEvent) CommString() string  { return nullTerm(e.Comm[:]) }
func (e *OpenatEvent) CommString() string  { return nullTerm(e.Comm[:]) }
func (e *LSMDenyEvent) CommString() string { return nullTerm(e.Comm[:]) }

func nullTerm(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// RingEvent is a decoded ring-buffer record.
type RingEvent struct {
	Connect *ConnectEvent
	Write   *WriteEvent  // EVENT_WRITE or unnamed EVENT_SENDMSG
	Writev  *WriteEvent  // EVENT_WRITEV
	Sendto  *SendtoEvent // EVENT_SENDTO
	Sendmsg *SendtoEvent // named EVENT_SENDMSG
	Openat  *OpenatEvent
	LSMDeny *LSMDenyEvent
}

// Loader manages the lifecycle of the compiled BPF probes.
type Loader struct {
	objs           connectObjects
	connectLink    link.Link
	writeLink      link.Link
	writevLink     link.Link
	sendtoLink     link.Link
	sendmsgLink    link.Link
	openatLink     link.Link
	lsmLink        link.Link       // nil unless lsmEnforce requested it and attach succeeded
	reader         *ringbuf.Reader // routine: connect/openat
	criticalReader *ringbuf.Reader // critical: write/writev/sendto/sendmsg/lsm_deny
	log            *log.Logger
}

// NewLoader loads the BPF programs and attaches connect/write/writev/sendto/sendmsg/openat.
// When lsmEnforce is true, it additionally attempts to attach the opt-in
// LSM quarantine hook (requires CONFIG_BPF_LSM=y + "bpf" active in
// /sys/kernel/security/lsm). Attach failure there is never fatal — it logs a
// loud [SECURITY] warning and the loader continues tracepoint-only, matching
// the project's fail-open-with-warnings posture (see docs/architecture.md §12).
func NewLoader(lsmEnforce bool) (*Loader, error) {
	var objs connectObjects
	if err := loadConnectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	cleanup := func(links ...link.Link) {
		for _, ln := range links {
			if ln != nil {
				ln.Close()
			}
		}
		objs.Close()
	}

	tpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TracepointSyscallsSysEnterConnect, nil)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("attaching connect tracepoint: %w", err)
	}

	tpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TracepointSyscallsSysEnterWrite, nil)
	if err != nil {
		cleanup(tpConnect)
		return nil, fmt.Errorf("attaching write tracepoint: %w", err)
	}

	tpWritev, err := link.Tracepoint("syscalls", "sys_enter_writev", objs.TracepointSyscallsSysEnterWritev, nil)
	if err != nil {
		cleanup(tpWrite, tpConnect)
		return nil, fmt.Errorf("attaching writev tracepoint: %w", err)
	}

	tpSendto, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TracepointSyscallsSysEnterSendto, nil)
	if err != nil {
		cleanup(tpWritev, tpWrite, tpConnect)
		return nil, fmt.Errorf("attaching sendto tracepoint: %w", err)
	}

	tpSendmsg, err := link.Tracepoint("syscalls", "sys_enter_sendmsg", objs.TracepointSyscallsSysEnterSendmsg, nil)
	if err != nil {
		cleanup(tpSendto, tpWritev, tpWrite, tpConnect)
		return nil, fmt.Errorf("attaching sendmsg tracepoint: %w", err)
	}

	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		cleanup(tpSendmsg, tpSendto, tpWritev, tpWrite, tpConnect)
		return nil, fmt.Errorf("attaching openat tracepoint: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		cleanup(tpOpenat, tpSendmsg, tpSendto, tpWritev, tpWrite, tpConnect)
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	critRD, err := ringbuf.NewReader(objs.CriticalEvents)
	if err != nil {
		rd.Close()
		cleanup(tpOpenat, tpSendmsg, tpSendto, tpWritev, tpWrite, tpConnect)
		return nil, fmt.Errorf("creating critical ring buffer reader: %w", err)
	}

	l := &Loader{
		objs:           objs,
		connectLink:    tpConnect,
		writeLink:      tpWrite,
		writevLink:     tpWritev,
		sendtoLink:     tpSendto,
		sendmsgLink:    tpSendmsg,
		openatLink:     tpOpenat,
		reader:         rd,
		criticalReader: critRD,
		log:            log.New(os.Stderr, "[loader] ", log.LstdFlags),
	}
	if err := l.SetPayloadCaptureBytes(defaultPayloadCapture); err != nil {
		l.Close()
		return nil, fmt.Errorf("setting default payload capture: %w", err)
	}

	if lsmEnforce {
		lsmLink, lsmErr := link.AttachLSM(link.LSMOptions{Program: objs.LsmSocketConnect})
		if lsmErr != nil {
			l.log.Printf("[SECURITY] ebpf.lsm_enforce requested but LSM attach failed — "+
				"continuing without kernel-level quarantine (kill-on-detect still active): %v", lsmErr)
		} else {
			l.lsmLink = lsmLink
			l.log.Printf("LSM quarantine hook attached (lsm/socket_connect)")
		}
	}

	return l, nil
}

// LSMEnforced reports whether the LSM quarantine hook is attached and active.
func (l *Loader) LSMEnforced() bool {
	return l != nil && l.lsmLink != nil
}

// Quarantine denies future connect() calls from pid and cgroupID at the
// kernel level (best-effort — a zero value for either is skipped). No-op
// with a clear error if the LSM hook isn't attached (LSMEnforced() == false).
func (l *Loader) Quarantine(pid int, cgroupID uint64) error {
	if !l.LSMEnforced() {
		return fmt.Errorf("lsm quarantine: hook not attached (ebpf.lsm_enforce not active or attach failed)")
	}
	var val uint8 = 1
	var errs []error
	if pid > 0 {
		k := uint32(pid)
		if err := l.objs.LsmBlocklistPid.Put(k, val); err != nil {
			errs = append(errs, fmt.Errorf("quarantine pid %d: %w", pid, err))
		}
	}
	if cgroupID != 0 {
		if err := l.objs.LsmBlocklistCgroup.Put(cgroupID, val); err != nil {
			errs = append(errs, fmt.Errorf("quarantine cgroup %d: %w", cgroupID, err))
		}
	}
	return errors.Join(errs...)
}

// Unquarantine removes a prior kernel-level quarantine for pid and/or
// cgroupID. Called when a watched PID/cgroup is removed, so a recycled PID
// never inherits a stale quarantine entry.
func (l *Loader) Unquarantine(pid int, cgroupID uint64) error {
	if !l.LSMEnforced() {
		return nil
	}
	if pid > 0 {
		_ = l.objs.LsmBlocklistPid.Delete(uint32(pid))
	}
	if cgroupID != 0 {
		_ = l.objs.LsmBlocklistCgroup.Delete(cgroupID)
	}
	return nil
}

// ListWatched returns PIDs and cgroup IDs currently in the filter maps.
func (l *Loader) ListWatched() (pids []int, cgroups []uint64, err error) {
	if l.objs.PidFilter != nil {
		iter := l.objs.PidFilter.Iterate()
		var k uint32
		var v uint8
		for iter.Next(&k, &v) {
			pids = append(pids, int(k))
		}
		if e := iter.Err(); e != nil {
			return nil, nil, e
		}
	}
	if l.objs.CgroupFilter != nil {
		iter := l.objs.CgroupFilter.Iterate()
		var k uint64
		var v uint8
		for iter.Next(&k, &v) {
			cgroups = append(cgroups, k)
		}
		if e := iter.Err(); e != nil {
			return nil, nil, e
		}
	}
	return pids, cgroups, nil
}

// ListQuarantined returns PIDs and cgroup IDs currently in the LSM blocklists.
func (l *Loader) ListQuarantined() (pids []int, cgroups []uint64, err error) {
	if !l.LSMEnforced() {
		return nil, nil, fmt.Errorf("lsm quarantine: hook not attached")
	}
	if l.objs.LsmBlocklistPid != nil {
		iter := l.objs.LsmBlocklistPid.Iterate()
		var k uint32
		var v uint8
		for iter.Next(&k, &v) {
			pids = append(pids, int(k))
		}
		if e := iter.Err(); e != nil {
			return nil, nil, e
		}
	}
	if l.objs.LsmBlocklistCgroup != nil {
		iter := l.objs.LsmBlocklistCgroup.Iterate()
		var k uint64
		var v uint8
		for iter.Next(&k, &v) {
			cgroups = append(cgroups, k)
		}
		if e := iter.Err(); e != nil {
			return nil, nil, e
		}
	}
	return pids, cgroups, nil
}

// QuarantineAllWatched puts every watched PID/cgroup into the LSM blocklists.
func (l *Loader) QuarantineAllWatched() error {
	if !l.LSMEnforced() {
		return fmt.Errorf("lsm quarantine: hook not attached")
	}
	pids, cgroups, err := l.ListWatched()
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range pids {
		if err := l.Quarantine(p, 0); err != nil {
			errs = append(errs, err)
		}
	}
	for _, c := range cgroups {
		if err := l.Quarantine(0, c); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// UnquarantineWatched removes the given PIDs/cgroups from the LSM blocklists.
func (l *Loader) UnquarantineWatched(pids []int, cgroups []uint64) error {
	if !l.LSMEnforced() {
		return nil
	}
	for _, p := range pids {
		_ = l.Unquarantine(p, 0)
	}
	for _, c := range cgroups {
		_ = l.Unquarantine(0, c)
	}
	return nil
}

// ClampPayloadCaptureBytes clamps n into [minPayloadCapture, payloadMax].
func ClampPayloadCaptureBytes(n int) int {
	if n < minPayloadCapture {
		return minPayloadCapture
	}
	if n > payloadMax {
		return payloadMax
	}
	return n
}

// SetPayloadCaptureBytes updates the BPF payload_cap map (how many bytes of
// each write/sendto are copied). Cannot exceed the compiled PAYLOAD_MAX.
func (l *Loader) SetPayloadCaptureBytes(n int) error {
	if l.objs.PayloadCap == nil {
		return fmt.Errorf("payload_cap map not loaded")
	}
	n = ClampPayloadCaptureBytes(n)
	var key uint32
	val := uint32(n)
	return l.objs.PayloadCap.Put(key, val)
}

// UpdatePIDSet replaces the BPF PID filter map contents with the given PIDs.
func (l *Loader) UpdatePIDSet(pids []int) error {
	var key uint32
	var val uint8
	iter := l.objs.PidFilter.Iterate()
	var toDelete []uint32
	for iter.Next(&key, &val) {
		toDelete = append(toDelete, key)
	}
	for _, k := range toDelete {
		l.objs.PidFilter.Delete(k)
	}

	val = 1
	for _, pid := range pids {
		k := uint32(pid)
		if err := l.objs.PidFilter.Put(k, val); err != nil {
			return fmt.Errorf("inserting PID %d: %w", pid, err)
		}
	}
	return nil
}

// AddPID adds a single PID to the filter map.
func (l *Loader) AddPID(pid int) error {
	k := uint32(pid)
	var val uint8 = 1
	return l.objs.PidFilter.Put(k, val)
}

// RemovePID removes a PID from the filter map.
func (l *Loader) RemovePID(pid int) error {
	k := uint32(pid)
	return l.objs.PidFilter.Delete(k)
}

// AddCgroupID watches all tasks in a cgroup v2 (by inode / bpf cgroup id).
func (l *Loader) AddCgroupID(id uint64) error {
	if l.objs.CgroupFilter == nil {
		return fmt.Errorf("cgroup_filter map not loaded")
	}
	var val uint8 = 1
	return l.objs.CgroupFilter.Put(id, val)
}

// RemoveCgroupID stops watching a cgroup.
func (l *Loader) RemoveCgroupID(id uint64) error {
	if l.objs.CgroupFilter == nil {
		return nil
	}
	return l.objs.CgroupFilter.Delete(id)
}

// DropCount returns kernel-side routine ring buffer reserve failures
// (connect/openat → events map). Primary fail-closed trip signal.
func (l *Loader) DropCount() (uint64, error) {
	if l.objs.DropCount == nil {
		return 0, fmt.Errorf("drop_count map not loaded")
	}
	var key uint32
	var val uint64
	if err := l.objs.DropCount.Lookup(&key, &val); err != nil {
		return 0, err
	}
	return val, nil
}

// CriticalDropCount returns kernel-side critical ring buffer reserve failures
// (write/sendto/lsm_deny → critical_events map).
func (l *Loader) CriticalDropCount() (uint64, error) {
	if l.objs.CriticalDropCount == nil {
		return 0, fmt.Errorf("critical_drop_count map not loaded")
	}
	var key uint32
	var val uint64
	if err := l.objs.CriticalDropCount.Lookup(&key, &val); err != nil {
		return 0, err
	}
	return val, nil
}

// FilterCounts returns the number of entries in pid_filter and cgroup_filter maps.
func (l *Loader) FilterCounts() (pids, cgroups int, err error) {
	if l.objs.PidFilter != nil {
		iter := l.objs.PidFilter.Iterate()
		var k uint32
		var v uint8
		for iter.Next(&k, &v) {
			pids++
		}
		if e := iter.Err(); e != nil {
			return 0, 0, e
		}
	}
	if l.objs.CgroupFilter != nil {
		iter := l.objs.CgroupFilter.Iterate()
		var k uint64
		var v uint8
		for iter.Next(&k, &v) {
			cgroups++
		}
		if e := iter.Err(); e != nil {
			return 0, 0, e
		}
	}
	return pids, cgroups, nil
}

// ReadEvent returns the next decoded routine ring-buffer event (connect/openat).
func (l *Loader) ReadEvent() (*RingEvent, error) {
	if l.reader == nil {
		return nil, fmt.Errorf("routine ringbuf reader not loaded")
	}
	record, err := l.reader.Read()
	if err != nil {
		return nil, err
	}
	return decodeRingEvent(record.RawSample)
}

// ReadCriticalEvent returns the next decoded critical ring-buffer event
// (write/sendto/lsm_deny).
func (l *Loader) ReadCriticalEvent() (*RingEvent, error) {
	if l.criticalReader == nil {
		return nil, fmt.Errorf("critical ringbuf reader not loaded")
	}
	record, err := l.criticalReader.Read()
	if err != nil {
		return nil, err
	}
	return decodeRingEvent(record.RawSample)
}

func decodeRingEvent(raw []byte) (*RingEvent, error) {
	if len(raw) < 8 {
		return nil, fmt.Errorf("short record: %d bytes", len(raw))
	}
	typ := binary.LittleEndian.Uint32(raw[0:4])
	switch typ {
	case eventTypeConnect:
		return decodeConnect(raw)
	case eventTypeWrite:
		ev, err := decodeWritePayload(raw)
		if err != nil {
			return nil, err
		}
		ev.Syscall = "write"
		return &RingEvent{Write: ev}, nil
	case eventTypeWritev:
		ev, err := decodeWritePayload(raw)
		if err != nil {
			return nil, err
		}
		ev.Syscall = "writev"
		return &RingEvent{Writev: ev}, nil
	case eventTypeSendto:
		ev, err := decodeSendtoPayload(raw)
		if err != nil {
			return nil, err
		}
		ev.Syscall = "sendto"
		return &RingEvent{Sendto: ev}, nil
	case eventTypeSendmsg:
		// Named sendmsg reserves sendto_event (72+PAYLOAD_MAX); unnamed uses write_event (56+PAYLOAD_MAX).
		if len(raw) >= sendtoHeaderLen+payloadMax {
			ev, err := decodeSendtoPayload(raw)
			if err != nil {
				return nil, err
			}
			ev.Syscall = "sendmsg"
			return &RingEvent{Sendmsg: ev}, nil
		}
		ev, err := decodeWritePayload(raw)
		if err != nil {
			return nil, err
		}
		ev.Syscall = "sendmsg"
		return &RingEvent{Write: ev}, nil
	case eventTypeOpenat:
		return decodeOpenat(raw)
	case eventTypeLSMDeny:
		return decodeLSMDeny(raw)
	default:
		return nil, fmt.Errorf("unknown event type %d", typ)
	}
}

func decodeConnect(raw []byte) (*RingEvent, error) {
	if len(raw) < connectHeaderLen {
		return nil, fmt.Errorf("short connect record: %d bytes", len(raw))
	}
	ev := &ConnectEvent{
		TSNs:     binary.LittleEndian.Uint64(raw[8:16]),
		PID:      binary.LittleEndian.Uint32(raw[16:20]),
		TID:      binary.LittleEndian.Uint32(raw[20:24]),
		Family:   raw[24],
		DestPort: binary.LittleEndian.Uint16(raw[41:43]),
		CgroupID: binary.LittleEndian.Uint64(raw[48:56]),
	}
	copy(ev.DestAddr[:], raw[25:41])
	copy(ev.Comm[:], raw[56:72])
	return &RingEvent{Connect: ev}, nil
}

func decodeWritePayload(raw []byte) (*WriteEvent, error) {
	if len(raw) < writeHeaderLen {
		return nil, fmt.Errorf("short write record: %d bytes", len(raw))
	}
	n := binary.LittleEndian.Uint32(raw[4:8])
	if n > payloadMax {
		n = payloadMax
	}
	ev := &WriteEvent{
		Len:      n,
		TSNs:     binary.LittleEndian.Uint64(raw[8:16]),
		PID:      binary.LittleEndian.Uint32(raw[16:20]),
		TID:      binary.LittleEndian.Uint32(raw[20:24]),
		FD:       binary.LittleEndian.Uint32(raw[24:28]),
		CgroupID: binary.LittleEndian.Uint64(raw[32:40]),
	}
	copy(ev.Comm[:], raw[40:56])
	if int(n) > 0 && len(raw) >= writeHeaderLen+int(n) {
		ev.Payload = append([]byte(nil), raw[writeHeaderLen:writeHeaderLen+int(n)]...)
	}
	return ev, nil
}

func decodeSendtoPayload(raw []byte) (*SendtoEvent, error) {
	if len(raw) < sendtoHeaderLen {
		return nil, fmt.Errorf("short sendto record: %d bytes", len(raw))
	}
	n := binary.LittleEndian.Uint32(raw[4:8])
	if n > payloadMax {
		n = payloadMax
	}
	ev := &SendtoEvent{
		Len:      n,
		TSNs:     binary.LittleEndian.Uint64(raw[8:16]),
		PID:      binary.LittleEndian.Uint32(raw[16:20]),
		TID:      binary.LittleEndian.Uint32(raw[20:24]),
		Family:   raw[24],
		DestPort: binary.LittleEndian.Uint16(raw[41:43]),
		CgroupID: binary.LittleEndian.Uint64(raw[48:56]),
	}
	copy(ev.DestAddr[:], raw[25:41])
	copy(ev.Comm[:], raw[56:72])
	if int(n) > 0 && len(raw) >= sendtoHeaderLen+int(n) {
		ev.Payload = append([]byte(nil), raw[sendtoHeaderLen:sendtoHeaderLen+int(n)]...)
	}
	return ev, nil
}

func decodeOpenat(raw []byte) (*RingEvent, error) {
	// type+path_len(8)+ts(8)+pid+tid(8)+cgroup(8)+comm(16) = 48
	const header = 48
	if len(raw) < header {
		return nil, fmt.Errorf("short openat record: %d bytes", len(raw))
	}
	n := binary.LittleEndian.Uint32(raw[4:8])
	if n > pathMax {
		n = pathMax
	}
	ev := &OpenatEvent{
		PathLen:  n,
		TSNs:     binary.LittleEndian.Uint64(raw[8:16]),
		PID:      binary.LittleEndian.Uint32(raw[16:20]),
		TID:      binary.LittleEndian.Uint32(raw[20:24]),
		CgroupID: binary.LittleEndian.Uint64(raw[24:32]),
	}
	copy(ev.Comm[:], raw[32:48])
	if int(n) > 0 && len(raw) >= header+int(n) {
		p := raw[header : header+int(n)]
		ev.Path = nullTerm(p)
	}
	return &RingEvent{Openat: ev}, nil
}

func decodeLSMDeny(raw []byte) (*RingEvent, error) {
	const minLen = 48
	if len(raw) < minLen {
		return nil, fmt.Errorf("short lsm_deny record: %d bytes", len(raw))
	}
	ev := &LSMDenyEvent{
		TSNs:     binary.LittleEndian.Uint64(raw[8:16]),
		PID:      binary.LittleEndian.Uint32(raw[16:20]),
		TID:      binary.LittleEndian.Uint32(raw[20:24]),
		CgroupID: binary.LittleEndian.Uint64(raw[24:32]),
	}
	copy(ev.Comm[:], raw[32:48])
	return &RingEvent{LSMDeny: ev}, nil
}

// Close tears down the BPF resources in the correct order.
func (l *Loader) Close() error {
	if l.criticalReader != nil {
		l.criticalReader.Close()
	}
	if l.reader != nil {
		l.reader.Close()
	}
	if l.lsmLink != nil {
		l.lsmLink.Close()
	}
	if l.openatLink != nil {
		l.openatLink.Close()
	}
	if l.sendmsgLink != nil {
		l.sendmsgLink.Close()
	}
	if l.sendtoLink != nil {
		l.sendtoLink.Close()
	}
	if l.writevLink != nil {
		l.writevLink.Close()
	}
	if l.writeLink != nil {
		l.writeLink.Close()
	}
	if l.connectLink != nil {
		l.connectLink.Close()
	}
	l.objs.Close()
	return nil
}
