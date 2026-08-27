//go:build linux

package proxy

import (
	"fmt"
	"syscall"
)

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
