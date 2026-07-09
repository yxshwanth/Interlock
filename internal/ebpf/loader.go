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
	payloadMax              = 256
	pathMax                 = 128
)

// ConnectEvent is the Go-side representation of a BPF connect event.
type ConnectEvent struct {
	TSNs     uint64
	PID      uint32
	TID      uint32
	DestIP   uint32
	DestPort uint16
	Comm     [16]byte
}

// WriteEvent is the Go-side representation of a BPF write payload excerpt.
type WriteEvent struct {
	TSNs    uint64
	PID     uint32
	TID     uint32
	FD      uint32
	Len     uint32
	Comm    [16]byte
	Payload []byte
}

// SendtoEvent is a self-contained sendto (dest + payload excerpt).
type SendtoEvent struct {
	TSNs     uint64
	PID      uint32
	TID      uint32
	DestIP   uint32
	DestPort uint16
	Len      uint32
	Comm     [16]byte
	Payload  []byte
}

// OpenatEvent is a pathname open from a monitored PID.
type OpenatEvent struct {
	TSNs    uint64
	PID     uint32
	TID     uint32
	PathLen uint32
	Comm    [16]byte
	Path    string
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

	return &Loader{
		objs:        objs,
		connectLink: tpConnect,
		writeLink:   tpWrite,
		sendtoLink:  tpSendto,
		openatLink:  tpOpenat,
		reader:      rd,
	}, nil
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
	const minLen = 46
	if len(raw) < minLen {
		return nil, fmt.Errorf("short connect record: %d bytes", len(raw))
	}
	ev := &ConnectEvent{
		TSNs:     binary.LittleEndian.Uint64(raw[8:16]),
		PID:      binary.LittleEndian.Uint32(raw[16:20]),
		TID:      binary.LittleEndian.Uint32(raw[20:24]),
		DestIP:   binary.LittleEndian.Uint32(raw[24:28]),
		DestPort: binary.LittleEndian.Uint16(raw[28:30]),
	}
	copy(ev.Comm[:], raw[30:46])
	return &RingEvent{Connect: ev}, nil
}

func decodeWrite(raw []byte) (*RingEvent, error) {
	const header = 44
	if len(raw) < header {
		return nil, fmt.Errorf("short write record: %d bytes", len(raw))
	}
	n := binary.LittleEndian.Uint32(raw[4:8])
	if n > payloadMax {
		n = payloadMax
	}
	ev := &WriteEvent{
		Len:  n,
		TSNs: binary.LittleEndian.Uint64(raw[8:16]),
		PID:  binary.LittleEndian.Uint32(raw[16:20]),
		TID:  binary.LittleEndian.Uint32(raw[20:24]),
		FD:   binary.LittleEndian.Uint32(raw[24:28]),
	}
	copy(ev.Comm[:], raw[28:44])
	if int(n) > 0 && len(raw) >= header+int(n) {
		ev.Payload = append([]byte(nil), raw[header:header+int(n)]...)
	}
	return &RingEvent{Write: ev}, nil
}

func decodeSendto(raw []byte) (*RingEvent, error) {
	// type(4)+len(4)+ts(8)+pid(4)+tid(4)+ip(4)+port(2)+pad(2)+comm(16)+payload(256) = 304
	const header = 48
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
	}
	copy(ev.Comm[:], raw[32:48])
	if int(n) > 0 && len(raw) >= header+int(n) {
		ev.Payload = append([]byte(nil), raw[header:header+int(n)]...)
	}
	return &RingEvent{Sendto: ev}, nil
}

func decodeOpenat(raw []byte) (*RingEvent, error) {
	// type(4)+path_len(4)+ts(8)+pid(4)+tid(4)+comm(16)+path(128) = 168
	const header = 40
	if len(raw) < header {
		return nil, fmt.Errorf("short openat record: %d bytes", len(raw))
	}
	n := binary.LittleEndian.Uint32(raw[4:8])
	if n > pathMax {
		n = pathMax
	}
	ev := &OpenatEvent{
		PathLen: n,
		TSNs:    binary.LittleEndian.Uint64(raw[8:16]),
		PID:     binary.LittleEndian.Uint32(raw[16:20]),
		TID:     binary.LittleEndian.Uint32(raw[20:24]),
	}
	copy(ev.Comm[:], raw[24:40])
	if int(n) > 0 && len(raw) >= header+int(n) {
		// path includes trailing NUL from bpf_probe_read_user_str
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
