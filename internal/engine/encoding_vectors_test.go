// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

var updateEncodingVectors = flag.Bool("update", false, "rewrite the canonical encoding vectors")

type encodingVector struct {
	InputHex string                  `json:"input_hex"`
	Forms    map[EncodingForm]string `json:"forms"`
}

func TestEncodingVectors(t *testing.T) {
	const path = "testdata/encoding_vectors.json"
	const regenerate = "go test ./internal/engine -run EncodingVectors -update"

	inputs := []string{
		"sample-token_123",
		"space +&=/?#%~*'()!",
		"café 漢字 🙂",
		"-----BEGIN EXAMPLE-----\nc2FtcGxl\n-----END EXAMPLE-----\n",
		strings.Repeat("0123456789abcdef", 64),
		"c2FtcGxl",
		"x",
		"$,:;@\x00\xff",
		"",
	}
	forms := []EncodingForm{
		FormLiteral, FormBase64, FormHex, FormURLEncoded, FormReversed,
		FormBase64Hex, FormHexBase64, FormBase64URL, FormBase64Rev,
	}

	got := make([]encodingVector, 0, len(inputs))
	for i, input := range inputs {
		vector := encodingVector{
			InputHex: hex.EncodeToString([]byte(input)),
			Forms:    make(map[EncodingForm]string),
		}
		for _, variant := range CanonicalEncodings(input) {
			form := EncodingForm(variant.Form)
			if slices.Contains(forms, form) {
				if _, exists := vector.Forms[form]; exists {
					t.Fatalf("vector %d: duplicate form %q", i, form)
				}
				vector.Forms[form] = hex.EncodeToString([]byte(variant.Value))
			}
		}
		if input != "" {
			for _, form := range forms {
				if _, exists := vector.Forms[form]; !exists {
					t.Fatalf("vector %d: encoder omitted form %q", i, form)
				}
			}
		}
		got = append(got, vector)
	}

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
	var want []encodingVector
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("decode vectors: %v; regenerate with %s", err, regenerate)
	}
	for i := range min(len(got), len(want)) {
		if got[i].InputHex != want[i].InputHex {
			t.Fatalf("vector %d input_hex: got %.64q, want %.64q; regenerate with %s", i, got[i].InputHex, want[i].InputHex, regenerate)
		}
		if want[i].Forms == nil {
			t.Fatalf("vector %d: forms must be an object; regenerate with %s", i, regenerate)
		}
		for _, form := range slices.Sorted(maps.Keys(got[i].Forms)) {
			expected, exists := want[i].Forms[form]
			if !exists {
				t.Fatalf("vector %d: fixture missing form %q; regenerate with %s", i, form, regenerate)
			}
			if value := got[i].Forms[form]; value != expected {
				t.Fatalf("vector %d form %q: got %q, want %q (hex); regenerate with %s", i, form, value, expected, regenerate)
			}
		}
		for _, form := range slices.Sorted(maps.Keys(want[i].Forms)) {
			if _, exists := got[i].Forms[form]; !exists {
				t.Fatalf("vector %d: fixture has unexpected form %q; regenerate with %s", i, form, regenerate)
			}
		}
	}
	if len(got) != len(want) {
		t.Fatalf("vector %d: computed %d vectors, fixture has %d; regenerate with %s", min(len(got), len(want)), len(got), len(want), regenerate)
	}
}
