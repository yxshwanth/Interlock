package k8s

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadContainerFile_PathTraversalRejected pins the fix for finding #8:
// a path crafted to walk past /proc/<pid>/root via ".." must be rejected
// before ever being concatenated into a real filesystem read.
func TestReadContainerFile_PathTraversalRejected(t *testing.T) {
	cases := []string{
		"/var/run/secrets/../../../../../etc/shadow",
		"../../../../etc/passwd",
		"/../etc/shadow",
	}
	for _, p := range cases {
		if _, err := ReadContainerFile([]int{os.Getpid()}, p); err == nil {
			t.Fatalf("expected traversal attempt %q to be rejected, got no error", p)
		}
	}
}

// TestReadContainerFile_NoHostFallbackOracle pins the removal of the
// dangerous fallback that used to read `path` directly against the sensor's
// own filesystem when every per-PID /proc/<pid>/root lookup failed — an
// attacker-steerable read oracle onto the host. A path that exists on this
// host but not under any resolvable /proc/<pid>/root candidate must fail,
// not silently succeed by falling back to a direct host read.
func TestReadContainerFile_NoHostFallbackOracle(t *testing.T) {
	dir := t.TempDir()
	hostOnlyFile := filepath.Join(dir, "host-secret")
	if err := os.WriteFile(hostOnlyFile, []byte("host-only-content"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// pid 1 exists but its /proc/1/root won't contain this host tempdir path
	// (this test process isn't PID 1 and doesn't share its rootfs), so this
	// exercises the "every per-PID attempt failed" path.
	got, err := ReadContainerFile([]int{1}, hostOnlyFile)
	if err == nil {
		t.Fatalf("expected failure (no host fallback), but got content: %q", got)
	}
	if strings.Contains(got, "host-only-content") {
		t.Fatalf("host file content leaked via fallback: %q", got)
	}
}

func TestReadContainerFile_EmptyPath(t *testing.T) {
	if _, err := ReadContainerFile([]int{1}, ""); err == nil {
		t.Fatal("expected error for empty path")
	}
}
