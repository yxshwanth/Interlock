// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
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
	// Tar stores the member in the clear, so the base64 decode matches before
	// container descent and the form is decoded_base64.
	tarWrapped := base64.StdEncoding.EncodeToString(tarBytes(t, containerMember{"note.txt", []byte(secret)}))
	gzCanon, err := gzipBase64(secret)
	if err != nil {
		t.Fatal(err)
	}
	near := []byte(secret)
	near[len(near)-1] ^= 1

	def := defaultOverlapArgsLimits()
	over := DefaultContainerLimits()
	over.MaxDecompressedBytes = 1
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

	return []overlapArgsInput{
		mk("args_string_leaf", mustOverlapArgsJSON(t, map[string]string{"body": secret}), def),
		mk("args_split_leaves", mustOverlapArgsJSON(t, split), def),
		mk("args_base64_and_hex", mustOverlapArgsJSON(t, map[string]string{"b64": b64, "hex": hx}), def),
		mk("args_decoded_nest", mustOverlapArgsJSON(t, map[string]string{"body": nest}), def),
		mk("args_recursive_nest", mustOverlapArgsJSON(t, map[string]string{"body": recursive}), def),
		mk("args_gzip", mustOverlapArgsJSON(t, map[string]string{"body": gz}), def),
		mk("args_zip", mustOverlapArgsJSON(t, map[string]string{"body": zipWrapped}), def),
		mk("args_tar", mustOverlapArgsJSON(t, map[string]string{"body": tarWrapped}), def),
		mk("args_container_over_cap", mustOverlapArgsJSON(t, map[string]string{"body": zipWrapped}), explicitOverlapArgsLimits(over)),
		mk("args_container_disabled", mustOverlapArgsJSON(t, map[string]string{"body": zipWrapped}), explicitOverlapArgsLimits(off)),
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
		payload("payload_gzip_base64_in_noise", "note "+gzCanon+" trailer"),
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

// checkVectorFile rewrites path under -update, otherwise decodes it strictly.
// An omitted key fails before the first value that differs from got.
func checkVectorFile[T any](t *testing.T, path, regenerate string, got T) {
	t.Helper()
	if *updateEncodingVectors {
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v; regenerate with %s", err, regenerate)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var want T
	if err := dec.Decode(&want); err != nil {
		t.Fatalf("decode vectors: %v; regenerate with %s", err, regenerate)
	}
	var parsed any
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&parsed); err != nil {
		t.Fatalf("decode vectors: %v; regenerate with %s", err, regenerate)
	}
	var g, w any
	for _, p := range []struct {
		in  any
		out *any
	}{{got, &g}, {want, &w}} {
		raw, err := json.Marshal(p.in)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, p.out); err != nil {
			t.Fatal(err)
		}
	}
	if where := missingVectorField(g, parsed, ""); where != "" {
		t.Fatalf("missing or null field %s; regenerate with %s", where, regenerate)
	}
	if where, gv, wv, ok := firstVectorDiff(g, w, ""); ok {
		t.Fatalf("%s: got %s, want %s; regenerate with %s", where, gv, wv, regenerate)
	}
}

// missingVectorField reports the first key present in full (the encoded
// result) and absent or null in raw (the file). Typed decode fills those with
// zero values, so the key check has to see the file's object. A null is only
// accepted where the encoded result is null too.
func missingVectorField(full, raw any, path string) string {
	if raw == nil && full != nil {
		return path
	}
	switch f := full.(type) {
	case map[string]any:
		r, ok := raw.(map[string]any)
		if !ok {
			return ""
		}
		keys := make([]string, 0, len(f))
		for k := range f {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, ok := r[k]; !ok {
				return path + "." + k
			}
			if where := missingVectorField(f[k], r[k], path+"."+k); where != "" {
				return where
			}
		}
	case []any:
		r, ok := raw.([]any)
		if !ok {
			return ""
		}
		n := len(f)
		if len(r) < n {
			n = len(r)
		}
		for i := 0; i < n; i++ {
			if where := missingVectorField(f[i], r[i], vectorElemPath(path, i, f[i])); where != "" {
				return where
			}
		}
	}
	return ""
}

func vectorElemPath(prefix string, i int, elem any) string {
	label := fmt.Sprintf("%s[%d]", prefix, i)
	m, ok := elem.(map[string]any)
	if !ok {
		return label
	}
	if name, ok := m["name"].(string); ok {
		label += "(" + name + ")"
	}
	if args, ok := m["args_json"].(string); ok && args != "" {
		label += "(args=" + args + ")"
	}
	if payload, ok := m["payload_hex"].(string); ok && payload != "" {
		label += "(payload_hex=" + payload + ")"
	}
	if p, ok := m["path"].(string); ok {
		label += "(path=" + p + ")"
	}
	if tool, ok := m["tool"].(string); ok {
		server, _ := m["server"].(string)
		label += "(tool=" + tool + " server=" + server + ")"
	}
	return label
}

func firstVectorDiff(got, want any, path string) (string, string, string, bool) {
	switch g := got.(type) {
	case map[string]any:
		w, ok := want.(map[string]any)
		if !ok {
			break
		}
		keys := map[string]bool{}
		for k := range g {
			keys[k] = true
		}
		for k := range w {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			if where, a, b, diff := firstVectorDiff(g[k], w[k], path+"."+k); diff {
				return where, a, b, true
			}
		}
		return "", "", "", false
	case []any:
		w, ok := want.([]any)
		if !ok {
			break
		}
		for i := 0; i < len(g) && i < len(w); i++ {
			if where, a, b, diff := firstVectorDiff(g[i], w[i], vectorElemPath(path, i, g[i])); diff {
				return where, a, b, true
			}
		}
		if len(g) != len(w) {
			return path + ".len", fmt.Sprint(len(g)), fmt.Sprint(len(w)), true
		}
		return "", "", "", false
	}
	gj, _ := json.Marshal(got)
	wj, _ := json.Marshal(want)
	if string(gj) != string(wj) {
		return path, string(gj), string(wj), true
	}
	return "", "", "", false
}
