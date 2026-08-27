package engine

import "strings"

const defaultContentBindMinLen = 16

// CheckContentBind reports whether any stored untrusted excerpt shares a
// contiguous substring of at least minLen bytes with the sink payload/args.
// This is the SUSPICIOUS-tier gate — weaker and separate from CheckOverlap's
// tainted-variant matching used for EXFIL.
func CheckContentBind(excerpts []string, sink string, minLen int) bool {
	if minLen <= 0 {
		minLen = defaultContentBindMinLen
	}
	if sink == "" || len(sink) < minLen {
		return false
	}
	for _, ex := range excerpts {
		if sharedSubstringAtLeast(ex, sink, minLen) {
			return true
		}
	}
	return false
}

func sharedSubstringAtLeast(a, b string, minLen int) bool {
	if len(a) < minLen || len(b) < minLen {
		return false
	}
	short, long := a, b
	if len(a) > len(b) {
		short, long = b, a
	}
	for i := 0; i+minLen <= len(short); i++ {
		if strings.Contains(long, short[i:i+minLen]) {
			return true
		}
	}
	return false
}
