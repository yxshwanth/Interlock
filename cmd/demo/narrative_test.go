package main

import (
	"strings"
	"testing"
)

// TestDemoQuietNarrative locks the post-v0.2 money-shot copy so Pass 2/3
// beats cannot drift back to literal-only block or connect-tripwire wording.
func TestDemoQuietNarrative(t *testing.T) {
	t.Run("pass2_gzip_base64", func(t *testing.T) {
		if !strings.Contains(beatPass2GzipPrevented, "match_form=gzip_base64") {
			t.Fatalf("Pass 2 prevented beat missing match_form=gzip_base64: %q", beatPass2GzipPrevented)
		}
		if !strings.Contains(beatPass2GzipExfil, "gzip_base64") {
			t.Fatalf("Pass 2 exfil beat missing gzip_base64: %q", beatPass2GzipExfil)
		}
		if !strings.Contains(footerBlock, "gzip_base64") {
			t.Fatalf("results footer Block line missing gzip_base64: %q", footerBlock)
		}
	})

	t.Run("pass3_payload_exfil", func(t *testing.T) {
		for _, s := range []string{beatPass3PayloadExfil, beatPass3MatchWhere, beatPass3Contained, footerEBPF, skipPass3Hint} {
			if strings.Contains(s, "connect() detected") || strings.Contains(s, "connect() only") {
				t.Fatalf("stale connect-tripwire phrasing in %q", s)
			}
		}
		if !strings.Contains(beatPass3PayloadExfil, "payload overlap") {
			t.Fatalf("Pass 3 EXFIL beat missing payload overlap: %q", beatPass3PayloadExfil)
		}
		if beatPass3MatchWhere != "match_where=egress payload" {
			t.Fatalf("Pass 3 match_where beat = %q, want match_where=egress payload", beatPass3MatchWhere)
		}
		if !strings.Contains(beatPass3Contained, "CONTAINED_BY_KILL") {
			t.Fatalf("Pass 3 contained beat missing CONTAINED_BY_KILL: %q", beatPass3Contained)
		}
		if !strings.Contains(footerEBPF, "egress payload") {
			t.Fatalf("results footer eBPF line missing egress payload: %q", footerEBPF)
		}
		if !strings.Contains(skipPass3Hint, "payload-backed") {
			t.Fatalf("Pass 3 skip hint missing payload-backed: %q", skipPass3Hint)
		}
	})
}
