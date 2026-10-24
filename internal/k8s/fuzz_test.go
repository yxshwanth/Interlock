// SPDX-License-Identifier: Apache-2.0

package k8s

import "testing"

// /proc/<pid>/cgroup is read from a process an attacker may control.
func FuzzExtractContainerID(f *testing.F) {
	f.Add("0::/kubepods/burstable/pod1234/cri-containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n")
	f.Add("12:memory:/docker/abc\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ExtractContainerID(s)
	})
}
