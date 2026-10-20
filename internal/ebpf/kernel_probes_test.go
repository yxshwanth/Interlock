// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"bytes"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// probeCollector drains both rings of a loaded Loader for this process.
type probeCollector struct {
	mu     sync.Mutex
	events []*RingEvent
	stop   atomic.Bool
}

func newProbeCollector(t *testing.T) (*Loader, *probeCollector) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root and BTF")
	}
	loader, err := NewLoader(false)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if err := loader.AddPID(os.Getpid()); err != nil {
		t.Fatalf("AddPID: %v", err)
	}
	c := &probeCollector{}
	for _, read := range []func() (*RingEvent, error){loader.ReadEvent, loader.ReadCriticalEvent} {
		go func() {
			for !c.stop.Load() {
				ev, err := read()
				if err != nil {
					time.Sleep(time.Millisecond)
					continue
				}
				c.mu.Lock()
				c.events = append(c.events, ev)
				c.mu.Unlock()
			}
		}()
	}
	t.Cleanup(func() {
		c.stop.Store(true)
		_ = loader.Close()
	})
	return loader, c
}

func (c *probeCollector) find(pred func(*RingEvent) bool) *RingEvent {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, ev := range c.events {
			if pred(ev) {
				c.mu.Unlock()
				return ev
			}
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func tcpPair(t *testing.T) (client *net.TCPConn, fd int, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 4096)
			for {
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	tc := conn.(*net.TCPConn)
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Control(func(f uintptr) { fd = int(f) })
	return tc, fd, ln.Addr().(*net.TCPAddr).Port
}

// Review #4: the connect event carries the fd the later writes will use.
func TestKernel_ConnectEventCarriesFD(t *testing.T) {
	_, c := newProbeCollector(t)
	_, fd, port := tcpPair(t)
	ev := c.find(func(e *RingEvent) bool {
		return e.Connect != nil && int(e.Connect.DestPort) == port
	})
	if ev == nil {
		t.Fatal("no connect event for the test listener")
	}
	if int(ev.Connect.FD) != fd {
		t.Fatalf("connect event fd = %d, want %d", ev.Connect.FD, fd)
	}
	if got := ev.Connect.DestIPString(); got != "127.0.0.1" {
		t.Fatalf("decoded dest = %q, want 127.0.0.1 (layout/offset check)", got)
	}
	if got := ev.Connect.CommString(); got == "" || ev.Connect.CgroupID == 0 {
		t.Fatalf("comm=%q cgroup=%d: decoder offsets for comm/cgroup look wrong", got, ev.Connect.CgroupID)
	}
}

// Review #3: every iovec up to IOV_MAX is captured, back to back.
func TestKernel_WritevGathersAllIovecs(t *testing.T) {
	_, c := newProbeCollector(t)
	_, fd, _ := tcpPair(t)
	want := []byte("AAAA-BBBB-CCCC-DDDD")
	if _, err := unix.Writev(fd, [][]byte{want[:5], want[5:10], want[10:15], want[15:]}); err != nil {
		t.Fatal(err)
	}
	ev := c.find(func(e *RingEvent) bool {
		return e.Writev != nil && int(e.Writev.FD) == fd && bytes.Equal(e.Writev.Payload, want)
	})
	if ev == nil {
		t.Fatal("writev with 4 iovecs not captured as one contiguous payload")
	}
}

func TestKernel_SendmsgGathersAllIovecs(t *testing.T) {
	_, c := newProbeCollector(t)
	_, fd, _ := tcpPair(t)
	want := []byte("one-two-three")
	if _, err := unix.SendmsgBuffers(fd, [][]byte{want[:4], want[4:8], want[8:]}, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	ev := c.find(func(e *RingEvent) bool {
		return e.Write != nil && int(e.Write.FD) == fd && bytes.Equal(e.Write.Payload, want)
	})
	if ev == nil {
		t.Fatal("sendmsg with 3 iovecs not captured as one contiguous payload")
	}
}

// Review #1: sendmmsg is probed (first message only).
func TestKernel_SendmmsgFirstMessageCaptured(t *testing.T) {
	_, c := newProbeCollector(t)
	_, fd, _ := tcpPair(t)
	want := []byte("mmsg-first-message")
	iov := unix.Iovec{Base: &want[0]}
	iov.SetLen(len(want))
	hdr := struct {
		Hdr unix.Msghdr
		Len uint32
		_   [4]byte
	}{Hdr: unix.Msghdr{Iov: &iov, Iovlen: 1}}
	if _, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&hdr)), 1, 0, 0, 0); errno != 0 {
		t.Fatal(errno)
	}
	ev := c.find(func(e *RingEvent) bool {
		return e.Write != nil && int(e.Write.FD) == fd && bytes.Equal(e.Write.Payload, want)
	})
	if ev == nil {
		t.Fatal("sendmmsg first message not captured")
	}
}

// Review #1 and #2: a sendto to a UDP destination is captured, including when
// the socket has been dup'd onto fd 0 (the old fd < 3 skip).
func TestKernel_SendtoCapturedOnLowFD(t *testing.T) {
	_, c := newProbeCollector(t)
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sock)
	saved, err := unix.Dup(0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(saved)
	if err := unix.Dup3(sock, 0, 0); err != nil {
		t.Fatal(err)
	}
	want := []byte("dup2-evasion-attempt")
	to := &unix.SockaddrInet4{Port: sink.LocalAddr().(*net.UDPAddr).Port, Addr: [4]byte{127, 0, 0, 1}}
	sendErr := unix.Sendto(0, want, 0, to)
	if err := unix.Dup3(saved, 0, 0); err != nil {
		t.Fatal(err)
	}
	if sendErr != nil {
		t.Fatal(sendErr)
	}
	ev := c.find(func(e *RingEvent) bool {
		return e.Sendto != nil && bytes.Equal(e.Sendto.Payload, want)
	})
	if ev == nil {
		t.Fatal("sendto on a socket dup'd onto fd 0 was skipped")
	}
	if ev.Sendto.DestIPString() != "127.0.0.1" || int(ev.Sendto.DestPort) != to.Port {
		t.Fatalf("sendto dest = %s:%d, want 127.0.0.1:%d", ev.Sendto.DestIPString(), ev.Sendto.DestPort, to.Port)
	}
}

// Review #1: send(2) on a connected socket (NULL sockaddr) still produces an event.
func TestKernel_SendWithNullAddressCaptured(t *testing.T) {
	_, c := newProbeCollector(t)
	_, fd, _ := tcpPair(t)
	want := []byte("send-null-sockaddr")
	if err := unix.Sendto(fd, want, 0, nil); err != nil {
		t.Fatal(err)
	}
	ev := c.find(func(e *RingEvent) bool {
		return (e.Sendto != nil && bytes.Equal(e.Sendto.Payload, want)) ||
			(e.Write != nil && bytes.Equal(e.Write.Payload, want))
	})
	if ev == nil {
		t.Fatal("send() with a NULL address produced no event")
	}
}
