//go:build linux

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
)

// TestStartServer_NetNS_ConnectENETUNREACH pins ROADMAP §7: a child spawned
// with sandbox.netns has no route to a non-loopback destination, so connect()
// fails with ENETUNREACH (or EHOSTUNREACH on some kernels).
//
// Skips (does not fail) when CLONE_NEWNET is denied — non-privileged CI stays
// green. Run with CAP_SYS_ADMIN / sudo to verify:
//
//	sudo go test ./internal/proxy/ -run NetNS -v
func TestStartServer_NetNS_ConnectENETUNREACH(t *testing.T) {
	helper := buildNetNSDialHelper(t)
	resolved, err := config.ResolveSpawnExecutable(helper)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := StartServer(ctx, config.ServerConfig{
		ID:      "netns-probe",
		Command: helper,
		Args:    []string{"203.0.113.1:9"},
	}, StartServerOpts{
		NetNS: true,
		SpawnPolicy: SpawnPolicy{
			Allowed: map[string]string{"netns-probe": resolved},
		},
	})
	if err != nil {
		if isNetNSPermissionError(err) {
			t.Skipf("CLONE_NEWNET denied (need CAP_SYS_ADMIN): %v", err)
		}
		t.Fatalf("StartServer(netns): %v", err)
	}

	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() {
		_, _ = io.Copy(&stderr, proc.Stderr)
	}()
	go func() { done <- proc.Wait() }()

	select {
	case err := <-done:
		out := stderr.String()
		if err == nil {
			t.Fatalf("netns child dial unexpectedly succeeded; stderr=%q", out)
		}
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			_ = proc.Stop()
			t.Fatalf("wait: %v (stderr=%q)", err, out)
		}
		// Helper exits 2 on ENETUNREACH/EHOSTUNREACH, 1 on other dial errors, 0 on success.
		if ee.ExitCode() != 2 {
			t.Fatalf("want exit 2 (ENETUNREACH/EHOSTUNREACH), got %d; stderr=%q", ee.ExitCode(), out)
		}
		// Go's syscall.Errno.Error() prints the strerror text, not the C macro name.
		if !strings.Contains(out, "network is unreachable") &&
			!strings.Contains(out, "no route to host") &&
			!strings.Contains(out, "ENETUNREACH") &&
			!strings.Contains(out, "EHOSTUNREACH") {
			t.Fatalf("stderr should indicate unreachable network, got %q", out)
		}
		// Success — do not Stop() (Wait already reaped the child).
		return
	case <-ctx.Done():
		_ = proc.Stop()
		t.Fatal("timed out waiting for netns dial helper")
	}
}

// TestStartServer_WithoutNetNS_LoopbackOK is a minimal control: without netns,
// a child can dial a local TCP listener on 127.0.0.1.
func TestStartServer_WithoutNetNS_LoopbackOK(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()

	helper := buildNetNSDialHelper(t)
	resolved, err := config.ResolveSpawnExecutable(helper)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := StartServer(ctx, config.ServerConfig{
		ID:      "no-netns-probe",
		Command: helper,
		Args:    []string{ln.Addr().String()},
	}, StartServerOpts{
		NetNS: false,
		SpawnPolicy: SpawnPolicy{
			Allowed: map[string]string{"no-netns-probe": resolved},
		},
	})
	if err != nil {
		t.Fatalf("StartServer: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- proc.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loopback dial without netns should succeed: %v", err)
		}
	case <-ctx.Done():
		_ = proc.Stop()
		t.Fatal("timed out")
	}
}

func isNetNSPermissionError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "operation not permitted") ||
		strings.Contains(s, "EPERM") ||
		errors.Is(err, syscall.EPERM)
}

// buildNetNSDialHelper compiles a tiny dialer that prints the errno name and
// exits 2 for ENETUNREACH/EHOSTUNREACH, 1 for other errors, 0 on success.
func buildNetNSDialHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "dial.go")
	bin := filepath.Join(dir, "dial")
	code := `package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dial host:port")
		os.Exit(1)
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", os.Args[1])
	if err == nil {
		_ = c.Close()
		os.Exit(0)
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if en, ok := e.(syscall.Errno); ok {
			fmt.Fprintln(os.Stderr, en.Error())
			if en == syscall.ENETUNREACH || en == syscall.EHOSTUNREACH {
				os.Exit(2)
			}
			os.Exit(1)
		}
	}
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
`
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build dial helper: %v\n%s", err, out)
	}
	return bin
}
