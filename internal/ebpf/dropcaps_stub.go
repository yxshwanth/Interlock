//go:build !linux

package ebpf

// DropPostAttach is a no-op on non-Linux.
func DropPostAttach(keepSYSAdmin bool) error {
	_ = keepSYSAdmin
	return nil
}

// ReadCapEff is unsupported off Linux.
func ReadCapEff() (string, error) {
	return "", nil
}

// CapBitSet is unsupported off Linux.
func CapBitSet(capEffHex string, cap int) bool {
	return false
}

// FormatCapSummary returns the input unchanged off Linux.
func FormatCapSummary(capEffHex string) string {
	return capEffHex
}
