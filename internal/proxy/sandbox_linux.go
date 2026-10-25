// SPDX-License-Identifier: Apache-2.0

//go:build linux

package proxy

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// nobodyID is the conventional overflow uid/gid ("nobody"/"nogroup").
const nobodyID = 65534

// applySandboxNetNS sets CLONE_NEWNET on attr when netns is requested.
// The child gets an empty network namespace: no routes to the host NIC and
// no resolver. Loopback is not brought up. Requires CAP_SYS_ADMIN (or root).
func applySandboxNetNS(attr *syscall.SysProcAttr, netns bool) error {
	if !netns {
		return nil
	}
	if attr == nil {
		return fmt.Errorf("sandbox.netns: SysProcAttr is nil")
	}
	attr.Cloneflags |= syscall.CLONE_NEWNET
	return nil
}

// childCredential is the identity a root proxy drops spawned servers to, so
// they hold no capabilities and cannot setns(2) out of sandbox.netns or touch
// BPF maps and evidence (review #7). Under sudo it is the invoking user, who
// can still reach the server binaries; otherwise nobody. A non-root proxy has
// nothing to drop and returns nil (setgroups would fail with EPERM anyway).
func childCredential(euid int, getenv func(string) string) *syscall.Credential {
	if euid != 0 {
		return nil
	}
	uid, uerr := strconv.ParseUint(getenv("SUDO_UID"), 10, 32)
	gid, gerr := strconv.ParseUint(getenv("SUDO_GID"), 10, 32)
	if uerr != nil || gerr != nil || uid == 0 {
		return &syscall.Credential{Uid: nobodyID, Gid: nobodyID}
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
}

// startNoNewPrivs starts cmd from an OS thread with PR_SET_NO_NEW_PRIVS set,
// which the child inherits: exec of setuid or file-capability binaries cannot
// regain privilege. Go's SysProcAttr has no field for this.
func startNoNewPrivs(cmd *exec.Cmd) error {
	errc := make(chan error, 1)
	go func() {
		// Never unlocked: the goroutine exits with the thread locked, so the
		// runtime discards this thread instead of reusing it with the flag set.
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			errc <- fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
			return
		}
		errc <- cmd.Start()
	}()
	return <-errc
}
