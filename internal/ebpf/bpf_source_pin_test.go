// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// These pins read bpf/connect.c because the kernel plane cannot be loaded in
// unit tests (no CAP_BPF). They guard the shape of the fixes from the security
// review; runtime behavior is covered only by REQUIRE_KERNEL=1 scripts/verify-all.sh.

// probeBody returns the C source of the function attached at tracepoint
// syscalls/sys_enter_<name>.
func probeBody(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("bpf/connect.c")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, `SEC("tracepoint/syscalls/sys_enter_`+name+`")`)
	if start < 0 {
		t.Fatalf("no probe for %s", name)
	}
	rest := src[start+1:]
	if end := strings.Index(rest, "\nSEC("); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

func TestBPFSource_PayloadReadsCheckedAndCapSized(t *testing.T) {
	read := regexp.MustCompile(`bpf_probe_read_(user|kernel)\(ev->payload,\s*([^,]+),`)
	for _, name := range []string{"write", "writev", "sendto", "sendmsg"} {
		body := probeBody(t, name)
		if strings.Contains(body, "bpf_probe_read_user(ev->payload, PAYLOAD_MAX") {
			t.Errorf("%s: payload read must use the captured size, not PAYLOAD_MAX", name)
		}
		m := read.FindAllStringSubmatch(body, -1)
		if len(m) == 0 {
			t.Errorf("%s: no payload read found", name)
		}
		if n := strings.Count(body, "bpf_ringbuf_discard(ev, 0)"); n < len(m) {
			t.Errorf("%s: %d payload reads but %d discard paths; every read failure must discard", name, len(m), n)
		}
		for _, line := range strings.Split(body, "\n") {
			if strings.Contains(line, "bpf_probe_read_") && strings.HasSuffix(strings.TrimSpace(line), ");") {
				t.Errorf("%s: unchecked probe read: %s", name, strings.TrimSpace(line))
			}
		}
	}
}

func TestBPFSource_MultiIovecGather(t *testing.T) {
	for _, name := range []string{"writev", "sendmsg"} {
		body := probeBody(t, name)
		if !strings.Contains(body, "gather_iov(") {
			t.Errorf("%s: must gather across iovecs, not read iov[0] only (review #3)", name)
		}
		if strings.Contains(body, "iov0") {
			t.Errorf("%s: still special-cases iov0", name)
		}
	}
}

// sendto/sendmsg only operate on sockets, so they must not skip fd 0-2
// (dup2 evasion, review #2).
func TestBPFSource_SendNoStdioSkip(t *testing.T) {
	for _, name := range []string{"sendto", "sendmsg"} {
		if strings.Contains(probeBody(t, name), "fd < 3") {
			t.Errorf("%s: skips fd<3; a dup2'd socket on stdio would be invisible", name)
		}
	}
}

// write/writev keep the fd<3 skip: they cannot distinguish a socket from a
// tty/pipe, and stdout/stderr traffic would flood the critical ring. The
// dup2'd-socket write is a documented gap (threat_model.md, detection_boundary.md).
func TestBPFSource_WriteStdioSkip_KnownGap(t *testing.T) {
	for _, name := range []string{"write", "writev"} {
		if !strings.Contains(probeBody(t, name), "fd < 3") {
			t.Errorf("%s: fd<3 skip removed; re-evaluate flooding before changing this pin", name)
		}
	}
}
