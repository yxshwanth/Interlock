package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	eventTypeConnect uint32 = 1
	eventTypeWrite   uint32 = 2
	eventTypeSendto  uint32 = 3
	eventTypeOpenat  uint32 = 4
	payloadMax              = 1024
	pathMax                 = 128
	defaultPayloadCapture   = 512
	minPayloadCapture       = 64
)

// ConnectEvent is the Go-side representation of a BPF connect event.
type ConnectEvent struct {
	TSNs     uint64
	PID      uint32
	TID      uint32
	DestIP   uint32
	DestPort uint16
	CgroupID uint64
	Comm     [16]byte
}

// WriteEvent is the Go-side representation of a BPF write payload excerpt.
type WriteEvent struct {
	TSNs     uint64
	PID      uint32
	TID      uint32
	FD       uint32
	Len      uint32
	CgroupID uint64
	Comm     [16]byte
	Payload  []byte
}

// SendtoEvent is a self-contained sendto (dest + payload excerpt).
type SendtoEvent struct {
	TSNs     uint64
	PID      uint32
	TID      uint32
	DestIP   uint32
	DestPort uint16
	Len      uint32
	CgroupID uint64
	Comm     [16]byte
	Payload  []byte
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

// DestIPString returns the destination IP as a dotted-quad string.
func (e *ConnectEvent) DestIPString() string {
	return destIPFromU32(e.DestIP)
}

func (e *SendtoEvent) DestIPString() string {
	return destIPFromU32(e.DestIP)
}

func destIPFromU32(v uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, v)
	return ip.String()
}

// CommString returns the process comm as a trimmed string.
func (e *ConnectEvent) CommString() string { return nullTerm(e.Comm[:]) }
func (e *WriteEvent) CommString() string   { return nullTerm(e.Comm[:]) }
func (e *SendtoEvent) CommString() string  { return nullTerm(e.Comm[:]) }
func (e *OpenatEvent) CommString() string  { return nullTerm(e.Comm[:]) }

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
	Write   *WriteEvent
	Sendto  *SendtoEvent
	Openat  *OpenatEvent
}

// Loader manages the lifecycle of the compiled BPF probes.
type Loader struct {
	objs        connectObjects
	connectLink link.Link
	writeLink   link.Link
	sendtoLink  link.Link
	openatLink  link.Link
	reader      *ringbuf.Reader
}

// NewLoader loads the BPF programs and attaches connect/write/sendto/openat.
func NewLoader() (*Loader, error) {
	var objs connectObjects
	if err := loadConnectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	tpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TracepointSyscallsSysEnterConnect, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching connect tracepoint: %w", err)
	}

	tpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TracepointSyscallsSysEnterWrite, nil)
	if err != nil {
		tpConnect.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching write tracepoint: %w", err)
	}

	tpSendto, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TracepointSyscallsSysEnterSendto, nil)
	if err != nil {
		tpWrite.Close()
		tpConnect.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching sendto tracepoint: %w", err)
	}

	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		tpSendto.Close()
		tpWrite.Close()
		tpConnect.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching openat tracepoint: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tpOpenat.Close()
		tpSendto.Close()
		tpWrite.Close()
		tpConnect.Close()
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	l := &Loader{
		objs:        objs,
		connectLink: tpConnect,
		writeLink:   tpWrite,
		sendtoLink:  tpSendto,
		openatLink:  tpOpenat,
		reader:      rd,
	}
	if err := l.SetPayloadCaptureBytes(defaultPayloadCapture); err != nil {
		l.Close()
		return nil, fmt.Errorf("setting default payload capture: %w", err)
	}
	return l, nil
}

// PayloadMax is the compiled-in capture ceiling (event struct size).
func PayloadMax() int { return payloadMax }

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

// PayloadCaptureBytes reads the current runtime capture cap from the BPF map.
func (l *Loader) PayloadCaptureBytes() (int, error) {
	if l.objs.PayloadCap == nil {
		return 0, fmt.Errorf("payload_cap map not loaded")
	}
	var key uint32
	var val uint32
	if err := l.objs.PayloadCap.Lookup(&key, &val); err != nil {
		return 0, err
	}
	return int(val), nil
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

// DropCount returns kernel-side ring buffer reserve failures.
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

// ReadEvent returns the next decoded ring-buffer event.
func (l *Loader) ReadEvent() (*RingEvent, error) {
	record, err := l.reader.Read()
	if err != nil {
		return nil, err
	}
	raw := record.RawSample
	if len(raw) < 8 {
		return nil, fmt.Errorf("short record: %d bytes", len(raw))
	}
	typ := binary.LittleEndian.Uint32(raw[0:4])
	switch typ {
	case eventTypeConnect:
		return decodeConnect(raw)
	case eventTypeWrite:
		return decodeWrite(raw)
	case eventTypeSendto:
		return decodeSendto(raw)
	case eventTypeOpenat:
		return decodeOpenat(raw)
	default:
		return nil, fmt.Errorf("unknown event type %d", typ)
	}
}

func decodeConnect(raw []byte) (*RingEvent, error) {
	// type+pad(8)+ts(8)+pid+tid(8)+ip(4)+port+pad(4)+cgroup(8)+comm(16) = 56
	const minLen = 56
	if len(raw) < minLen {
		return nil, fmt.Errorf("short connect record: %d bytes", len(raw))
	}
	ev := &ConnectEvent{
		TSNs:     binary.LittleEndian.Uint64(raw[8:16]),
		PID:      binary.LittleEndian.Uint32(raw[16:20]),
		TID:      binary.LittleEndian.Uint32(raw[20:24]),
		DestIP:   binary.LittleEndian.Uint32(raw[24:28]),
		DestPort: binary.LittleEndian.Uint16(raw[28:30]),
		CgroupID: binary.LittleEndian.Uint64(raw[32:40]),
	}
	copy(ev.Comm[:], raw[40:56])
	return &RingEvent{Connect: ev}, nil
}

func decodeWrite(raw []byte) (*RingEvent, error) {
	// type+len(8)+ts(8)+pid+tid(8)+fd+pad(8)+cgroup(8)+comm(16) = 56
	const header = 56
	if len(raw) < header {
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
	if int(n) > 0 && len(raw) >= header+int(n) {
		ev.Payload = append([]byte(nil), raw[header:header+int(n)]...)
	}
	return &RingEvent{Write: ev}, nil
}

func decodeSendto(raw []byte) (*RingEvent, error) {
	// type+len(8)+ts(8)+pid+tid(8)+ip(4)+port+pad(4)+cgroup(8)+comm(16) = 56
	const header = 56
	if len(raw) < header {
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
		DestIP:   binary.LittleEndian.Uint32(raw[24:28]),
		DestPort: binary.LittleEndian.Uint16(raw[28:30]),
		CgroupID: binary.LittleEndian.Uint64(raw[32:40]),
	}
	copy(ev.Comm[:], raw[40:56])
	if int(n) > 0 && len(raw) >= header+int(n) {
		ev.Payload = append([]byte(nil), raw[header:header+int(n)]...)
	}
	return &RingEvent{Sendto: ev}, nil
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

// Close tears down the BPF resources in the correct order.
func (l *Loader) Close() error {
	l.reader.Close()
	l.openatLink.Close()
	l.sendtoLink.Close()
	l.writeLink.Close()
	l.connectLink.Close()
	l.objs.Close()
	return nil
}
