// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package proxy

import (
	"fmt"
	"os/exec"
	"syscall"
)

// applySandboxNetNS rejects netns outside Linux — CLONE_NEWNET is Linux-only.
func applySandboxNetNS(attr *syscall.SysProcAttr, netns bool) error {
	if netns {
		return fmt.Errorf("sandbox.netns: network namespaces require Linux")
	}
	return nil
}

// childCredential: privilege drop is implemented on Linux only.
func childCredential(int, func(string) string) *syscall.Credential { return nil }

func startNoNewPrivs(cmd *exec.Cmd) error { return cmd.Start() }
