// SPDX-License-Identifier: Apache-2.0

//go:build linux

package proxy

import (
	"context"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
)

func TestChildCredential(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	cases := []struct {
		name     string
		euid     int
		env      map[string]string
		wantNil  bool
		uid, gid uint32
	}{
		{name: "non-root proxy keeps its identity", euid: 1000, wantNil: true},
		{name: "root drops to nobody", euid: 0, uid: 65534, gid: 65534},
		{name: "root under sudo drops to caller", euid: 0, env: map[string]string{"SUDO_UID": "1000", "SUDO_GID": "1001"}, uid: 1000, gid: 1001},
		{name: "sudo from root still drops to nobody", euid: 0, env: map[string]string{"SUDO_UID": "0", "SUDO_GID": "0"}, uid: 65534, gid: 65534},
		{name: "garbage sudo env drops to nobody", euid: 0, env: map[string]string{"SUDO_UID": "x", "SUDO_GID": "1"}, uid: 65534, gid: 65534},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := childCredential(c.euid, env(c.env))
			if c.wantNil {
				if got != nil {
					t.Fatalf("want nil, got %+v", got)
				}
				return
			}
			if got == nil || got.Uid != c.uid || got.Gid != c.gid || len(got.Groups) != 0 || got.NoSetGroups {
				t.Fatalf("got %+v, want uid=%d gid=%d with supplementary groups cleared", got, c.uid, c.gid)
			}
		})
	}
}

// Runs unprivileged: the spawned server reads its own NoNewPrivs flag.
func TestStartServer_ChildHasNoNewPrivs(t *testing.T) {
	grep, err := exec.LookPath("grep")
	if err != nil {
		t.Skipf("grep not found: %v", err)
	}
	resolved, err := config.ResolveSpawnExecutable(grep)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proc, err := StartServer(ctx, config.ServerConfig{
		ID: "nnp", Command: grep, Args: []string{"NoNewPrivs", "/proc/self/status"},
	}, StartServerOpts{SpawnPolicy: SpawnPolicy{Allowed: map[string]string{"nnp": resolved}}})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(proc.Stdout)
	_ = proc.Wait()
	if !strings.Contains(string(out), "NoNewPrivs:\t1") {
		t.Fatalf("child status: %q, want NoNewPrivs:\t1", out)
	}
}
