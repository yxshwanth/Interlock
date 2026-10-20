// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"bytes"
	"log"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
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
