package model

import "strings"

// MeetsMinVerdict reports whether v satisfies the configured minimum alert threshold.
func MeetsMinVerdict(v Verdict, min string) bool {
	switch strings.ToUpper(min) {
	case "EXFIL":
		return v == VerdictExfil
	default:
		return v == VerdictExfil || v == VerdictSuspicious
	}
}
