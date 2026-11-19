// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Review #13: evidence.json is the same record as the JSONL log, written for
// the viewer, so it must be owner-only as well.
func TestStandaloneEvidence_FileMode0600(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })

	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	sink, err := NewJSONLEvidenceSink(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if err := sink.Emit(testEvidenceRecord()); err != nil {
		t.Fatal(err)
	}

	standalone := filepath.Join(dir, "evidence.json")
	fi, err := os.Stat(standalone)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("evidence.json mode = %o, want 600", perm)
	}
}
