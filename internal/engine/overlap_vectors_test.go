// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

// apiSecret is the sk-live key ExtractTaintedValues already pins in taint_test.go.
const apiSecret = "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"

// urlSecret needs a character QueryEscape rewrites. The sk-live pattern
// rejects '+', so the token pattern is what extracts it.
const urlSecret = "sk-live+token/special=value"

// longSecret is an sk-live key past the 64-byte chunk minimum. The body
// repeats a 16-character alphabet so each 32-byte chunk clears the entropy floor.
var longSecret = "sk-live-" + strings.Repeat("9fK2mQ7xR4pL8wN3", 6)

type overlapPayloadKind int

const (
	payloadLiteral overlapPayloadKind = iota
	payloadBase64
	payloadHex
	payloadURLEncoded
	payloadReversed
	payloadBase64Hex
	payloadBase64Nest3
	payloadGzipBase64
	payloadNoise
	payloadChunk
	payloadNearMiss
	payloadBenign
	payloadUnextracted
	payloadSecond
)

type overlapInput struct {
	name       string
	resultText string
	source     string
	seq        uint64
	kind       overlapPayloadKind
}

type overlapVector struct {
	Name       string            `json:"name"`
	ResultText string            `json:"result_text"`
	Source     string            `json:"source"`
	Seq        uint64            `json:"seq"`
	PayloadHex string            `json:"payload_hex"`
	Tainted    []overlapTainted  `json:"tainted"`
	Hit        *overlapHitVector `json:"hit"`
}

type overlapTainted struct {
	ValueHex   string   `json:"value_hex"`
	Hash       string   `json:"hash"`
	Preview    string   `json:"preview"`
	Source     string   `json:"source"`
	Seq        uint64   `json:"seq"`
	Forms      []string `json:"forms"`
	ChunkCount int      `json:"chunk_count"`
}

type overlapHitVector struct {
	TaintedHash string `json:"tainted_hash"`
	Preview     string `json:"preview"`
	WhereFound  string `json:"where_found"`
	MatchForm   string `json:"match_form"`
}

func TestOverlapVectors(t *testing.T) {
	const path = "testdata/overlap_vectors.json"
	const regenerate = "go test ./internal/engine -run OverlapVectors -update"

	got := overlapVectors(t)
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
	var raws []json.RawMessage
	if err := json.Unmarshal(data, &raws); err != nil {
		t.Fatalf("decode vectors: %v; regenerate with %s", err, regenerate)
	}
	want := make([]overlapVector, 0, len(raws))
	for i, raw := range raws {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var vector overlapVector
		if err := dec.Decode(&vector); err != nil {
			t.Fatalf("case %d: %v; regenerate with %s", i, err, regenerate)
		}
		want = append(want, vector)
	}
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	for i := 0; i < n; i++ {
		diffOverlapVector(t, got[i], want[i], regenerate)
	}
	if len(got) != len(want) {
		t.Fatalf("cases: got %d, want %d; regenerate with %s", len(got), len(want), regenerate)
	}
}

func overlapVectorCases() []overlapInput {
	return []overlapInput{
		{"literal", apiSecret, "tickets/read_ticket", 5, payloadLiteral},
		{"base64", apiSecret, "tickets/read_ticket", 5, payloadBase64},
		{"hex", apiSecret, "tickets/read_ticket", 5, payloadHex},
		{"url_encoded", "Auth Token: " + urlSecret, "auth/get_token", 1, payloadURLEncoded},
		{"reversed", apiSecret, "tickets/read_ticket", 5, payloadReversed},
		{"base64_of_hex", apiSecret, "tickets/read_ticket", 5, payloadBase64Hex},
		{"base64_nest_3", apiSecret, "tickets/read_ticket", 5, payloadBase64Nest3},
		{"gzip_base64", apiSecret, "tickets/read_ticket", 5, payloadGzipBase64},
		{"surrounded_by_noise", "note " + apiSecret + " trailer", "tickets/read_ticket", 5, payloadNoise},
		{"long_secret_chunk", longSecret, "tickets/read_ticket", 8, payloadChunk},
		{"near_miss", apiSecret, "tickets/read_ticket", 5, payloadNearMiss},
		{"payload_without_secret", apiSecret, "tickets/read_ticket", 5, payloadBenign},
		{"no_extractable_secret", "Hello, this is a regular message with no secrets.", "src", 1, payloadUnextracted},
		{
			"two_secrets",
			"Customer Auth Token: " + apiSecret + "\nAccount ID: acct_prod_jane_7291",
			"tickets/read_ticket",
			5,
			payloadSecond,
		},
	}
}

func overlapVectors(t *testing.T) []overlapVector {
	t.Helper()
	cases := overlapVectorCases()
	got := make([]overlapVector, 0, len(cases))
	for _, c := range cases {
		// ExtractTaintedValues leaves Chunks empty. The engine fills them
		// before overlap, and a long secret matches only through those chunks.
		tainted := ExtractTaintedValues(c.resultText, c.source, c.seq)
		for i := range tainted {
			AttachChunks(&tainted[i], 0, 0)
		}
		payload := overlapPayload(t, c, tainted)
		hit := CheckOverlapPayload(tainted, payload)
		got = append(got, overlapSnapshot(c, tainted, payload, hit))
	}
	return got
}

func overlapPayload(t *testing.T, c overlapInput, tainted []model.TaintedValue) string {
	t.Helper()
	secret := ""
	if len(tainted) > 0 {
		secret = tainted[0].Value
	}
	switch c.kind {
	case payloadLiteral:
		return secret
	case payloadBase64:
		return base64.StdEncoding.EncodeToString([]byte(secret))
	case payloadHex:
		return hex.EncodeToString([]byte(secret))
	case payloadURLEncoded:
		return url.QueryEscape(secret)
	case payloadReversed:
		return model.ReverseString(secret)
	case payloadBase64Hex:
		return base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte(secret))))
	case payloadBase64Nest3:
		nested := base64.StdEncoding.EncodeToString([]byte(secret))
		nested = base64.StdEncoding.EncodeToString([]byte(nested))
		return base64.StdEncoding.EncodeToString([]byte(nested))
	case payloadGzipBase64:
		encoded, err := gzipBase64(secret)
		if err != nil {
			t.Fatalf("case %s: gzip: %v", c.name, err)
		}
		return encoded
	case payloadNoise:
		return "note " + secret + " trailer"
	case payloadChunk:
		if len(tainted) == 0 || len(tainted[0].Chunks) < 2 {
			return ""
		}
		return "note " + tainted[0].Chunks[1].Value + " trailer"
	case payloadNearMiss:
		if secret == "" {
			return ""
		}
		raw := []byte(secret)
		raw[len(raw)-1] ^= 1
		return string(raw)
	case payloadBenign:
		return "status update: all clear"
	case payloadUnextracted:
		return apiSecret
	case payloadSecond:
		if len(tainted) < 2 {
			return ""
		}
		return tainted[1].Value
	default:
		t.Fatalf("case %s: unknown payload kind %d", c.name, c.kind)
		return ""
	}
}

func overlapSnapshot(c overlapInput, tainted []model.TaintedValue, payload string, hit *model.OverlapHit) overlapVector {
	recorded := make([]overlapTainted, 0, len(tainted))
	for _, tv := range tainted {
		forms := make([]string, 0, len(tv.Variants))
		for _, form := range tv.Variants {
			forms = append(forms, form.Form)
		}
		recorded = append(recorded, overlapTainted{
			ValueHex:   hex.EncodeToString([]byte(tv.Value)),
			Hash:       tv.Hash,
			Preview:    tv.Preview,
			Source:     tv.Source,
			Seq:        tv.Seq,
			Forms:      forms,
			ChunkCount: len(tv.Chunks),
		})
	}
	vector := overlapVector{
		Name:       c.name,
		ResultText: c.resultText,
		Source:     c.source,
		Seq:        c.seq,
		PayloadHex: hex.EncodeToString([]byte(payload)),
		Tainted:    recorded,
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

func diffOverlapVector(t *testing.T, got, want overlapVector, regenerate string) {
	t.Helper()
	name := got.Name
	if name == "" {
		name = want.Name
	}
	checkField(t, name, "name", got.Name, want.Name, regenerate)
	checkField(t, name, "result_text", got.ResultText, want.ResultText, regenerate)
	checkField(t, name, "source", got.Source, want.Source, regenerate)
	if got.Seq != want.Seq {
		t.Fatalf("case %s: seq: got %d, want %d; regenerate with %s", name, got.Seq, want.Seq, regenerate)
	}
	checkField(t, name, "payload_hex", got.PayloadHex, want.PayloadHex, regenerate)
	if len(got.Tainted) != len(want.Tainted) {
		t.Fatalf("case %s: tainted: got %d, want %d; regenerate with %s", name, len(got.Tainted), len(want.Tainted), regenerate)
	}
	for i := range got.Tainted {
		diffTainted(t, name, i, got.Tainted[i], want.Tainted[i], regenerate)
	}
	diffHit(t, name, got.Hit, want.Hit, regenerate)
}

func diffTainted(t *testing.T, name string, i int, got, want overlapTainted, regenerate string) {
	t.Helper()
	prefix := "tainted[" + strconv.Itoa(i) + "]"
	checkField(t, name, prefix+".value_hex", got.ValueHex, want.ValueHex, regenerate)
	checkField(t, name, prefix+".hash", got.Hash, want.Hash, regenerate)
	checkField(t, name, prefix+".preview", got.Preview, want.Preview, regenerate)
	checkField(t, name, prefix+".source", got.Source, want.Source, regenerate)
	if got.Seq != want.Seq {
		t.Fatalf("case %s: %s.seq: got %d, want %d; regenerate with %s", name, prefix, got.Seq, want.Seq, regenerate)
	}
	if len(got.Forms) != len(want.Forms) {
		t.Fatalf("case %s: %s.forms: got %d, want %d; regenerate with %s", name, prefix, len(got.Forms), len(want.Forms), regenerate)
	}
	for f := range got.Forms {
		checkField(t, name, prefix+".forms["+strconv.Itoa(f)+"]", got.Forms[f], want.Forms[f], regenerate)
	}
	if got.ChunkCount != want.ChunkCount {
		t.Fatalf("case %s: %s.chunk_count: got %d, want %d; regenerate with %s", name, prefix, got.ChunkCount, want.ChunkCount, regenerate)
	}
}

func diffHit(t *testing.T, name string, got, want *overlapHitVector, regenerate string) {
	t.Helper()
	if got == nil || want == nil {
		if got != want {
			t.Fatalf("case %s: hit: got %s, want %s; regenerate with %s", name, formatHit(got), formatHit(want), regenerate)
		}
		return
	}
	checkField(t, name, "hit.tainted_hash", got.TaintedHash, want.TaintedHash, regenerate)
	checkField(t, name, "hit.preview", got.Preview, want.Preview, regenerate)
	checkField(t, name, "hit.where_found", got.WhereFound, want.WhereFound, regenerate)
	checkField(t, name, "hit.match_form", got.MatchForm, want.MatchForm, regenerate)
}

func checkField(t *testing.T, name, field, got, want, regenerate string) {
	t.Helper()
	if got != want {
		t.Fatalf("case %s: %s: got %q, want %q; regenerate with %s", name, field, got, want, regenerate)
	}
}

func formatHit(hit *overlapHitVector) string {
	if hit == nil {
		return "null"
	}
	return hit.MatchForm
}
