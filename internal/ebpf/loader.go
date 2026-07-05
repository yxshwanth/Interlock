package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ConnectEvent is the Go-side representation of the BPF connect_event struct.
type ConnectEvent struct {
	TSNs     uint64
	PID      uint32
	TID      uint32
	DestIP   uint32
	DestPort uint16
	Comm     [16]byte
}

// DestIPString returns the destination IP as a dotted-quad string.
func (e *ConnectEvent) DestIPString() string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, e.DestIP)
	return ip.String()
}

// CommString returns the process comm as a trimmed string.
func (e *ConnectEvent) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// Loader manages the lifecycle of the compiled BPF connect() probe.
type Loader struct {
	objs   connectObjects
	link   link.Link
	reader *ringbuf.Reader
}

// NewLoader loads the BPF program into the kernel and attaches it to the
// sys_enter_connect tracepoint.
func NewLoader() (*Loader, error) {
	var objs connectObjects
	if err := loadConnectObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TracepointSyscallsSysEnterConnect, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching tracepoint: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return &Loader{
		objs:   objs,
		link:   tp,
		reader: rd,
	}, nil
}

// UpdatePIDSet replaces the BPF PID filter map contents with the given PIDs.
// Only connect() calls from these PIDs will generate events.
func (l *Loader) UpdatePIDSet(pids []int) error {
	// Batch-delete all existing entries isn't available on hash maps easily,
	// so we iterate existing keys and delete, then insert new ones.
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

// ReadEvent blocks until a connect event is available from the ring buffer.
// Returns the decoded event or an error. Callers should check for
// ringbuf.ErrClosed when the reader has been shut down.
func (l *Loader) ReadEvent() (*ConnectEvent, error) {
	record, err := l.reader.Read()
	if err != nil {
		return nil, err
	}

	if len(record.RawSample) < 38 {
		return nil, fmt.Errorf("short record: %d bytes", len(record.RawSample))
	}

	ev := &ConnectEvent{
		TSNs:     binary.LittleEndian.Uint64(record.RawSample[0:8]),
		PID:      binary.LittleEndian.Uint32(record.RawSample[8:12]),
		TID:      binary.LittleEndian.Uint32(record.RawSample[12:16]),
		DestIP:   binary.LittleEndian.Uint32(record.RawSample[16:20]),
		DestPort: binary.LittleEndian.Uint16(record.RawSample[20:22]),
	}
	copy(ev.Comm[:], record.RawSample[22:38])

	return ev, nil
}

// Close tears down the BPF resources in the correct order.
func (l *Loader) Close() error {
	l.reader.Close()
	l.link.Close()
	l.objs.Close()
	return nil
}
