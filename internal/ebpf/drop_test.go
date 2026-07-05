package ebpf

import "testing"

func TestEBPF_RingbufSaturation_KnownGap(t *testing.T) {
	t.Skip("known v0.2 gap: kernel ring buffer saturation not reproducible in CI without root load generator")
}

func TestLoader_DropCount_NoProbe(t *testing.T) {
	// DropCount requires a loaded probe; verify API exists via compile-time check only.
	var fn func(*Loader) (uint64, error) = (*Loader).DropCount
	_ = fn
}
