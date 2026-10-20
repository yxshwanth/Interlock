// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"bytes"
	"io"
	"log"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

func startSleeper(t *testing.T, attr *syscall.SysProcAttr) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot spawn sleep: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return cmd
}

func exitedWithin(cmd *exec.Cmd, d time.Duration) bool {
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// The review (#21) feared KillProcess(pid) takes out pid's whole process
// group. kill(-pid) signals the group whose ID is pid, which only exists
// when pid leads it, so a co-tenant leader whose group the attributed
// process joined must survive.
func TestKillProcess_SparesLeaderOfJoinedGroup(t *testing.T) {
	leader := startSleeper(t, &syscall.SysProcAttr{Setpgid: true})
	member := startSleeper(t, &syscall.SysProcAttr{Setpgid: true, Pgid: leader.Process.Pid})

	KillProcess(member.Process.Pid)

	if !exitedWithin(member, 2*time.Second) {
		t.Fatal("attributed pid survived SIGKILL")
	}
	if exitedWithin(leader, 300*time.Millisecond) {
		t.Fatal("co-tenant group leader was killed")
	}
}

func TestKillProcess_LeaderTakesItsOwnGroup(t *testing.T) {
	leader := startSleeper(t, &syscall.SysProcAttr{Setpgid: true})
	child := startSleeper(t, &syscall.SysProcAttr{Setpgid: true, Pgid: leader.Process.Pid})

	KillProcess(leader.Process.Pid)

	if !exitedWithin(leader, 2*time.Second) || !exitedWithin(child, 2*time.Second) {
		t.Fatal("group led by the attributed pid not fully killed")
	}
}

func TestUpdateAllowlist_DropsHostnamesWithWarning(t *testing.T) {
	var logs bytes.Buffer
	s := &Sensor{log: log.New(&logs, "", 0)}

	s.UpdateAllowlist([]string{"127.0.0.1", "api.anthropic.com", "::1"})

	if !s.isAllowlisted("127.0.0.1") || !s.isAllowlisted("::1") {
		t.Fatal("IP entries must stay allowlisted")
	}
	if s.allowlist["api.anthropic.com"] {
		t.Fatal("hostname entry kept in an IP-only allowlist")
	}
	if !strings.Contains(logs.String(), `"api.anthropic.com" is not an IP address`) {
		t.Fatalf("no warning for hostname entry; logs:\n%s", logs.String())
	}
}

func newCorrelationSensor(got *[]model.SyscallEvent) *Sensor {
	return &Sensor{
		log:             log.New(io.Discard, "", 0),
		allowlist:       map[string]bool{},
		suspiciousByPID: make(map[int]map[int]pendingConnect),
		handler: func(ev model.SyscallEvent) model.Decision {
			*got = append(*got, ev)
			return model.Decision{}
		},
	}
}

func connectOn(pid, fd uint32, ip byte) *ConnectEvent {
	return &ConnectEvent{PID: pid, FD: fd, Family: afInet, DestAddr: [16]byte{203, 0, 113, ip}, DestPort: 443}
}

// Review #4: correlation is keyed by (pid, fd), so a write after the old 5 s
// window still attributes to the connect, and a write on a different fd does not.
func TestWriteCorrelation_IsFDKeyed(t *testing.T) {
	var got []model.SyscallEvent
	s := newCorrelationSensor(&got)
	s.handleConnect(connectOn(10, 5, 1))
	s.handleConnect(connectOn(10, 6, 2))
	got = nil

	s.suspiciousByPID[10][5] = pendingConnect{destIP: "203.0.113.1", destPort: 443, at: time.Now().Add(-time.Hour / 4)}
	s.handleWrite(&WriteEvent{PID: 10, FD: 5, Len: 1, Payload: []byte("x")})
	s.handleWrite(&WriteEvent{PID: 10, FD: 6, Len: 1, Payload: []byte("x")})
	s.handleWrite(&WriteEvent{PID: 10, FD: 7, Len: 1, Payload: []byte("x")})

	if len(got) != 1 || got[0].DestIP != "203.0.113.2" {
		t.Fatalf("want one event for fd 6 -> 203.0.113.2 (fd 5 aged out, fd 7 never connected), got %+v", got)
	}
}

func TestWriteCorrelation_LateWriteStillCorrelates(t *testing.T) {
	var got []model.SyscallEvent
	s := newCorrelationSensor(&got)
	s.handleConnect(connectOn(10, 5, 1))
	got = nil
	s.suspiciousByPID[10][5] = pendingConnect{destIP: "203.0.113.1", destPort: 443, at: time.Now().Add(-time.Minute)}
	s.handleWrite(&WriteEvent{PID: 10, FD: 5, Len: 1, Payload: []byte("x")})
	if len(got) != 1 || got[0].DestIP != "203.0.113.1" {
		t.Fatalf("write 1 min after connect must still correlate, got %+v", got)
	}
}
