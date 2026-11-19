// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A hostile or truncated config file must produce an error, never a panic.
func FuzzLoad(f *testing.F) {
	f.Add([]byte("enforcement: block\nservers: []\n"))
	f.Add([]byte("servers:\n  - id: a\n    command: ./a\n"))
	f.Add([]byte("a: &x [*x]\n"))
	f.Add([]byte("\x00\xff"))
	f.Add([]byte(""))
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, raw []byte) {
		path := filepath.Join(dir, "interlock.yaml")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Skip()
		}
		_, _ = Load(path)
		_, _ = LoadSensor(path)
	})
}
