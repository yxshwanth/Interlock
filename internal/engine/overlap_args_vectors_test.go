// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

const (
	overlapArgsKindArgs    = "args"
	overlapArgsKindPayload = "payload"
)

// overlapArgsLimits is the string "default", or every ContainerLimits field.
type overlapArgsLimits struct {
	useDefault bool
	value      ContainerLimits
}

type overlapArgsVector struct {
	Name       string            `json:"name"`
	ResultText string            `json:"result_text"`
	Source     string            `json:"source"`
	Seq        uint64            `json:"seq"`
	Kind       string            `json:"kind"`
	ArgsJSON   string            `json:"args_json"`
	PayloadHex string            `json:"payload_hex"`
	Limits     overlapArgsLimits `json:"limits"`
	Hit        *overlapHitVector `json:"hit"`
	Abort      string            `json:"abort"`
}

type overlapArgsInput struct {
	name       string
	resultText string
	source     string
	seq        uint64
	kind       string
	args       string
	payload    string
	limits     overlapArgsLimits
}

func TestOverlapArgsVectors(t *testing.T) {
	checkVectorFile(t, "testdata/overlap_args_vectors.json", "go test ./internal/engine -run OverlapArgsVectors -update", overlapArgsVectors(t))
}

func overlapArgsVectors(t *testing.T) []overlapArgsVector {
	t.Helper()
	cases := overlapArgsCases(t)
	seen := make(map[string]struct{}, len(cases))
	e, _ := newTestEngine("block")
	out := make([]overlapArgsVector, 0, len(cases))
	for _, c := range cases {
		if _, dup := seen[c.name]; dup {
			t.Fatalf("duplicate case %s", c.name)
		}
		seen[c.name] = struct{}{}
		state := &model.SessionState{SessionID: c.name}
		e.addTainted(state, ExtractTaintedValues(c.resultText, c.source, c.seq))
		var hit *model.OverlapHit
		var abort ContainerAbortReason
		if c.kind == overlapArgsKindPayload {
			hit, abort = CheckOverlapPayloadLimited(state.Tainted, c.payload, c.limits.limits())
		} else {
			hit, abort = CheckOverlapLimited(state.Tainted, json.RawMessage(c.args), c.limits.limits())
		}
		out = append(out, overlapArgsSnapshot(c, hit, abort))
	}
	return out
}

func overlapArgsCases(t *testing.T) []overlapArgsInput {
	t.Helper()
	secret := apiSecret
	half := len(secret) / 2
	// joinJSONStringValues sorts object keys, so part_a then part_b is the secret.
	split := map[string]string{
		"part_a": secret[:half],
		"part_b": secret[half:],
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	hx := hex.EncodeToString([]byte(secret))
	// base64(hex(secret)) is FormBase64Hex, so the fast path reports base64_hex.
	nest := base64.StdEncoding.EncodeToString([]byte(hx))
	// base64(hex(base64(secret))) is outside that closed set, so the decoder
	// reports decoded_base64_hex.
	recursive := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte(b64))))
	gz := base64.StdEncoding.EncodeToString(gzipBytes(t, []byte(secret)))
	zipBlob := zipBytes(t, containerMember{"note.txt", []byte(secret)})
	zipWrapped := base64.StdEncoding.EncodeToString(zipBlob)
	zipHex := base64.StdEncoding.EncodeToString(zipBytes(t, containerMember{"note.txt", []byte(hx)}))
	zipOfB64 := base64.StdEncoding.EncodeToString(zipBytes(t, containerMember{"note.txt", []byte(b64)}))
	// One byte over the secret length, so a cap of len(secret) aborts this zip
	// and still extracts a zip of the secret itself.
	zipOver := base64.StdEncoding.EncodeToString(zipBytes(t, containerMember{"note.txt", bytes.Repeat([]byte("A"), len(secret)+1)}))
	zipParts := base64.StdEncoding.EncodeToString(zipBytes(t,
		containerMember{"a.txt", []byte("x")},
		containerMember{"b.txt", []byte("y")},
	))
	// Tar stores the member in the clear, so the base64 decode matches before
	// container descent and the form is decoded_base64.
	tarWrapped := base64.StdEncoding.EncodeToString(tarBytes(t, containerMember{"note.txt", []byte(secret)}))
	// gzip(secret) is not a substring of the tar bytes or of their base64, so
	// the hit is container_* only after tar-then-gzip descent.
	tarGzWrapped := base64.StdEncoding.EncodeToString(tarBytes(t, containerMember{"note.txt", gzipBytes(t, []byte(secret))}))
	// Three base64 layers around hex(secret). That nest is not a canonical
	// form, and the hex text appears only on the third decode.
	deep := base64.StdEncoding.EncodeToString([]byte(hx))
	deep = base64.StdEncoding.EncodeToString([]byte(deep))
	deep = base64.StdEncoding.EncodeToString([]byte(deep))
	gzCanon, err := gzipBase64(secret)
	if err != nil {
		t.Fatal(err)
	}
	near := []byte(secret)
	near[len(near)-1] ^= 1

	def := defaultOverlapArgsLimits()
	over := DefaultContainerLimits()
	over.MaxDecompressedBytes = 1
	tight := DefaultContainerLimits()
	tight.MaxDecompressedBytes = len(secret)
	// First candidate trips max_parts. The later one trips max_decompressed_bytes.
	last := DefaultContainerLimits()
	last.MaxParts = 1
	last.MaxDecompressedBytes = len(secret)
	off := DefaultContainerLimits()
	off.Enabled = false

	common := overlapArgsInput{
		resultText: secret,
		source:     "tickets/read_ticket",
		seq:        5,
		kind:       overlapArgsKindArgs,
		limits:     def,
	}
	mk := func(name, args string, limits overlapArgsLimits) overlapArgsInput {
		c := common
		c.name = name
		c.args = args
		c.limits = limits
		return c
	}
	payload := func(name, body string) overlapArgsInput {
		c := common
		c.name = name
		c.kind = overlapArgsKindPayload
		c.payload = body
		return c
	}
	payloadLim := func(name, body string, limits overlapArgsLimits) overlapArgsInput {
		c := payload(name, body)
		c.limits = limits
		return c
	}
	// Written z then m. Sorted keys try m first, and m's first blob sorts
	// after the second, so file order or a lexical array sort picks another
	// container form.
	idx0, idx1 := zipHex, zipWrapped
	if idx0 < idx1 {
		idx0, idx1 = idx1, idx0
	}
	orderArgs := `{"z":"` + zipOfB64 + `","m":["` + idx0 + `","` + idx1 + `"]}`
	// a aborts, b holds the secret. Same shape for both entry points.
	abortThenHit := `{"a":"` + zipOver + `","b":"` + zipWrapped + `"}`
	// a aborts max_parts, b aborts max_decompressed_bytes, c completes within
	// the limits with no hit. The last non-empty abort (b's) is returned, so
	// keeping the first abort or the last candidate's empty result both fail.
	zipClean := base64.StdEncoding.EncodeToString(zipBytes(t, containerMember{"ok.txt", []byte("x")}))
	lastAbort := `{"a":"` + zipParts + `","b":"` + zipOver + `","c":"` + zipClean + `"}`

	return []overlapArgsInput{
		mk("args_string_leaf", mustOverlapArgsJSON(t, map[string]string{"body": secret}), def),
		mk("args_split_leaves", mustOverlapArgsJSON(t, split), def),
		mk("args_base64", mustOverlapArgsJSON(t, map[string]string{"body": b64}), def),
		mk("args_hex", mustOverlapArgsJSON(t, map[string]string{"body": hx}), def),
		mk("args_decoded_nest", mustOverlapArgsJSON(t, map[string]string{"body": nest}), def),
		mk("args_recursive_nest", mustOverlapArgsJSON(t, map[string]string{"body": recursive}), def),
		mk("args_gzip", mustOverlapArgsJSON(t, map[string]string{"body": gz}), def),
		mk("args_zip", mustOverlapArgsJSON(t, map[string]string{"body": zipWrapped}), def),
		mk("args_tar", mustOverlapArgsJSON(t, map[string]string{"body": tarWrapped}), def),
		mk("args_tar_gzip", mustOverlapArgsJSON(t, map[string]string{"body": tarGzWrapped}), def),
		mk("args_container_over_cap", mustOverlapArgsJSON(t, map[string]string{"body": zipWrapped}), explicitOverlapArgsLimits(over)),
		mk("args_container_abort_then_hit", abortThenHit, explicitOverlapArgsLimits(tight)),
		mk("args_container_last_abort", lastAbort, explicitOverlapArgsLimits(last)),
		mk("args_container_disabled", mustOverlapArgsJSON(t, map[string]string{"body": zipWrapped}), explicitOverlapArgsLimits(off)),
		mk("args_order_keys_array", orderArgs, def),
		// Array of objects. The string leaf is the third level under the root.
		mk("args_nested_depth_3", mustOverlapArgsJSON(t, []any{
			map[string]any{"mid": map[string]string{"body": secret}},
		}), def),
		// Object keys are not JSON string leaves. The raw args text still contains the secret.
		mk("args_object_key", mustOverlapArgsJSON(t, map[string]string{secret: "x"}), def),
		mk("args_non_string", mustOverlapArgsJSON(t, map[string]any{"n": 9876543210, "ok": false}), def),
		mk("args_empty", "", def),
		mk("args_null", "null", def),
		mk("args_invalid_json", "not json "+secret, def),
		mk("args_near_miss", mustOverlapArgsJSON(t, map[string]string{"body": string(near)}), def),
		payload("payload_plain", secret),
		payload("payload_zip_base64", zipWrapped),
		payload("payload_gzip_base64_canonical", "note "+gzCanon+" trailer"),
		payload("payload_decoded_base64_nest", deep),
		payloadLim("payload_container_abort_then_hit", abortThenHit, explicitOverlapArgsLimits(tight)),
		// The key is the secret and is not a string leaf. The leaf is the nest
		// above, which only the recursive decoder finds. The whole-body scan
		// matches the literal first.
		payload("payload_order_body_before_leaf", `{"`+secret+`":"`+deep+`"}`),
	}
}

func overlapArgsSnapshot(c overlapArgsInput, hit *model.OverlapHit, abort ContainerAbortReason) overlapArgsVector {
	vector := overlapArgsVector{
		Name:       c.name,
		ResultText: c.resultText,
		Source:     c.source,
		Seq:        c.seq,
		Kind:       c.kind,
		ArgsJSON:   c.args,
		PayloadHex: hex.EncodeToString([]byte(c.payload)),
		Limits:     c.limits,
		Abort:      string(abort),
	}
	if hit != nil {
		vector.Hit = &overlapHitVector{
			TaintedHash: hit.TaintedHash,
			Preview:     hit.Preview,
			WhereFound:  hit.WhereFound,
			MatchForm:   hit.MatchForm,
		}
	}
	return vector
}

func (l overlapArgsLimits) limits() ContainerLimits {
	if l.useDefault {
		return DefaultContainerLimits()
	}
	return l.value
}

func defaultOverlapArgsLimits() overlapArgsLimits {
	return overlapArgsLimits{useDefault: true}
}

func explicitOverlapArgsLimits(v ContainerLimits) overlapArgsLimits {
	return overlapArgsLimits{value: v}
}

func (l overlapArgsLimits) MarshalJSON() ([]byte, error) {
	if l.useDefault {
		return []byte(`"default"`), nil
	}
	return json.Marshal(struct {
		Enabled              bool  `json:"enabled"`
		MaxDecompressedBytes int   `json:"max_decompressed_bytes"`
		MaxDescentDepth      int   `json:"max_descent_depth"`
		MaxParts             int   `json:"max_parts"`
		MaxInspect           int64 `json:"max_inspect"`
	}{
		Enabled:              l.value.Enabled,
		MaxDecompressedBytes: l.value.MaxDecompressedBytes,
		MaxDescentDepth:      l.value.MaxDescentDepth,
		MaxParts:             l.value.MaxParts,
		MaxInspect:           int64(l.value.MaxInspect),
	})
}

func (l *overlapArgsLimits) UnmarshalJSON(data []byte) error {
	if string(bytes.TrimSpace(data)) == `"default"` {
		*l = defaultOverlapArgsLimits()
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var body struct {
		Enabled              bool  `json:"enabled"`
		MaxDecompressedBytes int   `json:"max_decompressed_bytes"`
		MaxDescentDepth      int   `json:"max_descent_depth"`
		MaxParts             int   `json:"max_parts"`
		MaxInspect           int64 `json:"max_inspect"`
	}
	if err := dec.Decode(&body); err != nil {
		return err
	}
	*l = explicitOverlapArgsLimits(ContainerLimits{
		Enabled:              body.Enabled,
		MaxDecompressedBytes: body.MaxDecompressedBytes,
		MaxDescentDepth:      body.MaxDescentDepth,
		MaxParts:             body.MaxParts,
		MaxInspect:           time.Duration(body.MaxInspect),
	})
	return nil
}

func mustOverlapArgsJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
