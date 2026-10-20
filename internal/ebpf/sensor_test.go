// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

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
