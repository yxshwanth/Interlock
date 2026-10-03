package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveSpawnExecutable_RejectsTraversal(t *testing.T) {
	_, err := ResolveSpawnExecutable("../bin/sh")
	if err == nil {
		t.Fatal("expected rejection for ..")
	}
}

func TestResolveSpawnExecutable_AbsolutePath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "server")
	if err := os.WriteFile(bin, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveSpawnExecutable(bin)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(bin)
	if err != nil {
		want = bin
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveSpawnExecutable_SymlinkToRealBinary(t *testing.T) {
	dir := t.TempDir()
	realBin := filepath.Join(dir, "real-server")
	if err := os.WriteFile(realBin, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link-server")
	if err := os.Symlink(realBin, link); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveSpawnExecutable(link)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(realBin)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("symlink resolve = %q, want %q (EvalSymlinks target)", got, want)
	}
}

func TestResolveSpawnExecutable_RejectsDotDotEscapeWithoutPrefix(t *testing.T) {
	// Relatives that Clean would walk through parents still contain ".." and
	// must be rejected before Abs — not only leading "../".
	_, err := ResolveSpawnExecutable("servers/../../../bin/sh")
	if err == nil {
		t.Fatal("expected rejection for embedded .. escape")
	}
}

func TestBuildResolvedSpawnCommands(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tickets")
	if err := os.WriteFile(bin, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Servers: []ServerConfig{{ID: "tickets", Command: bin}},
	}
	m, err := cfg.BuildResolvedSpawnCommands()
	if err != nil {
		t.Fatal(err)
	}
	if m["tickets"] == "" {
		t.Fatal("expected resolved path for tickets")
	}
}

func TestLoad_BuildsResolvedSpawnCommands(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "echo-bin")
	if err := os.WriteFile(bin, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := `
servers:
  - id: s1
    command: ` + bin + `
sandbox:
  spawn_allowlist:
    - ` + bin + `
`
	cfg, err := Load(writeTemp(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ResolvedSpawnCommands["s1"] == "" {
		t.Fatal("ResolvedSpawnCommands missing s1")
	}
	if len(cfg.ResolvedSpawnAllowlist) != 1 {
		t.Fatalf("ResolvedSpawnAllowlist len = %d, want 1", len(cfg.ResolvedSpawnAllowlist))
	}
}
