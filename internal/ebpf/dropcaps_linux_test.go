//go:build linux

package ebpf

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFormatCapSummary_Parse(t *testing.T) {
	if !CapBitSet("0000000000000020", unix.CAP_KILL) {
		t.Fatal("expected CAP_KILL in 0x20")
	}
	if !CapBitSet("0000000000200000", unix.CAP_SYS_ADMIN) {
		t.Fatal("expected CAP_SYS_ADMIN in 1<<21")
	}
	sum := FormatCapSummary("0000000000200020")
	if sum == "" {
		t.Fatal("empty summary")
	}
}

func TestDropPostAttach_RootGated(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for Capset / eBPF load")
	}

	before, err := ReadCapEff()
	if err != nil {
		t.Fatal(err)
	}

	loader, err := NewLoader(false)
	if err != nil {
		t.Skipf("NewLoader: %v", err)
	}
	defer loader.Close()

	if err := DropPostAttach(false); err != nil {
		t.Fatalf("DropPostAttach: %v", err)
	}

	after, err := ReadCapEff()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CapEff before=%s after=%s", FormatCapSummary(before), FormatCapSummary(after))

	if CapBitSet(after, unix.CAP_SYS_ADMIN) {
		t.Fatal("CAP_SYS_ADMIN still effective after drop")
	}
	// Map ops should still work with held FDs + BPF/PERFMON.
	if err := loader.SetPayloadCaptureBytes(512); err != nil {
		t.Fatalf("SetPayloadCaptureBytes after drop: %v", err)
	}
	if err := loader.AddPID(os.Getpid()); err != nil {
		t.Fatalf("AddPID after drop: %v", err)
	}
}

func TestDropPostAttach_KeepSYSAdmin(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	before, err := ReadCapEff()
	if err != nil {
		t.Fatal(err)
	}
	had := CapBitSet(before, unix.CAP_SYS_ADMIN)
	if err := DropPostAttach(true); err != nil {
		t.Fatal(err)
	}
	after, err := ReadCapEff()
	if err != nil {
		t.Fatal(err)
	}
	if had && !CapBitSet(after, unix.CAP_SYS_ADMIN) {
		t.Fatal("keepSYSAdmin cleared SYS_ADMIN")
	}
}
