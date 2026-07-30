//go:build !linux

package proxy

import (
	"fmt"
	"syscall"
)

// applySandboxNetNS rejects netns outside Linux — CLONE_NEWNET is Linux-only.
func applySandboxNetNS(attr *syscall.SysProcAttr, netns bool) error {
	if netns {
		return fmt.Errorf("sandbox.netns: network namespaces require Linux")
	}
	return nil
}
