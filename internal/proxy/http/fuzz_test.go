// SPDX-License-Identifier: Apache-2.0

package mcphttp

import (
	"strings"
	"testing"
)

func FuzzParseSSEResponse(f *testing.F) {
	f.Add("event: message\ndata: {\"jsonrpc\":\"2.0\"}\n\n")
	f.Add("data: a\ndata: b\n\n")
	f.Add("data: " + strings.Repeat("x", 100000) + "\n\n")
	f.Add(":\n\n\r\n\r")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseSSEResponse(strings.NewReader(s))
	})
}
