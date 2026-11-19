// SPDX-License-Identifier: Apache-2.0

package model

import (
	"encoding/json"
	"testing"
)

func FuzzParseToolCallParams(f *testing.F) {
	f.Add([]byte(`{"name":"send_message","arguments":{"body":"x"}}`))
	f.Add([]byte(`{"name":1}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseToolCallParams(json.RawMessage(raw))
	})
}
