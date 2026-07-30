package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
)

func TestValidateSpawnCommand_RejectsTraversal(t *testing.T) {
	_, err := ValidateSpawnCommand("tickets", "../bin/sh", SpawnPolicy{
		Allowed: map[string]string{"tickets": "/opt/tickets"},
	})
	if err == nil {
		t.Fatal("expected rejection for .. traversal")
	}
}

func TestValidateSpawnCommand_RejectsWrongBinary(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "tickets")
	bad := filepath.Join(dir, "evil")
	for _, p := range []string{good, bad} {
		if err := os.WriteFile(p, []byte{0}, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	resolvedGood, err := config.ResolveSpawnExecutable(good)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ValidateSpawnCommand("tickets", bad, SpawnPolicy{
		Allowed: map[string]string{"tickets": resolvedGood},
	})
	if err == nil {
		t.Fatal("expected rejection for wrong binary")
	}
}

func TestValidateSpawnCommand_SymlinkMustMatchPinnedTarget(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "tickets")
	evil := filepath.Join(dir, "evil")
	for _, p := range []string{good, evil} {
		if err := os.WriteFile(p, []byte{0}, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "tickets-link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	pinned, err := config.ResolveSpawnExecutable(good)
	if err != nil {
		t.Fatal(err)
	}
	// Link to the pinned target is accepted (resolves to same real path).
	if _, err := ValidateSpawnCommand("tickets", link, SpawnPolicy{
		Allowed: map[string]string{"tickets": pinned},
	}); err != nil {
		t.Fatalf("symlink to pinned target: %v", err)
	}
	// Link swapped to a different binary must fail.
	evilLink := filepath.Join(dir, "evil-link")
	if err := os.Symlink(evil, evilLink); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSpawnCommand("tickets", evilLink, SpawnPolicy{
		Allowed: map[string]string{"tickets": pinned},
	}); err == nil {
		t.Fatal("expected rejection when symlink resolves to non-pinned target")
	}
}

func TestValidateSpawnCommand_AcceptsPinnedPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tickets")
	if err := os.WriteFile(bin, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := config.ResolveSpawnExecutable(bin)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ValidateSpawnCommand("tickets", bin, SpawnPolicy{
		Allowed: map[string]string{"tickets": resolved},
	})
	if err != nil {
		t.Fatalf("ValidateSpawnCommand: %v", err)
	}
	if got != resolved {
		t.Fatalf("resolved = %q, want %q", got, resolved)
	}
}

func TestValidateSpawnCommand_AcceptsSpawnAllowlistExtra(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "helper")
	if err := os.WriteFile(helper, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := config.ResolveSpawnExecutable(helper)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ValidateSpawnCommand("probe", helper, SpawnPolicy{
		Allowed: map[string]string{"probe": "/nonexistent/other"},
		Extras:  []string{resolved},
	})
	if err != nil {
		t.Fatalf("extra allowlist: %v", err)
	}
	if got != resolved {
		t.Fatalf("resolved = %q, want %q", got, resolved)
	}
}
