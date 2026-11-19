// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

type decodeAttempt struct {
	DecodedHex string `json:"decoded_hex"`
	OK         bool   `json:"ok"`
}

type decodeVector struct {
	Name              string        `json:"name"`
	InputHex          string        `json:"input_hex"`
	TryBase64         decodeAttempt `json:"try_base64"`
	TryHex            decodeAttempt `json:"try_hex"`
	PlausibleDecoded  bool          `json:"plausible_decoded"`
	LooksLikeHex      bool          `json:"looks_like_hex"`
	LooksLikeBase64   bool          `json:"looks_like_base64"`
	PayloadCandidates []string      `json:"payload_candidates"`
	ArgsCandidates    []string      `json:"args_candidates"`
}

type decodeInput struct {
	name  string
	input string
}

func TestDecodeVectors(t *testing.T) {
	const path = "testdata/decode_vectors.json"
	const regenerate = "go test ./internal/engine -run DecodeVectors -update"

	got := decodeVectorCases(t)
	if *updateEncodingVectors {
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatalf("encode vectors: %v; regenerate with %s", err, regenerate)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatalf("write vectors: %v; regenerate with %s", err, regenerate)
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
	want := make([]decodeVector, 0, len(raws))
	for i, raw := range raws {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var vector decodeVector
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
		diffDecodeVector(t, got[i], want[i], regenerate)
	}
	if len(got) != len(want) {
		name := ""
		if len(got) > len(want) {
			name = got[len(want)].Name
		} else {
			name = want[len(got)].Name
		}
		t.Fatalf("case %s: cases: got %d, want %d; regenerate with %s", name, len(got), len(want), regenerate)
	}
}

func decodeVectorCases(t *testing.T) []decodeVector {
	t.Helper()
	inputs := decodeVectorInputs(t)
	got := make([]decodeVector, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for _, in := range inputs {
		if _, dup := seen[in.name]; dup {
			t.Fatalf("duplicate case %s", in.name)
		}
		seen[in.name] = struct{}{}
		got = append(got, snapshotDecode(in.name, in.input))
	}
	return got
}

func decodeVectorInputs(t *testing.T) []decodeInput {
	t.Helper()
	urlSafe := base64.URLEncoding.EncodeToString([]byte{0xfb, 0xef, 0xbe, 0x00, 0x01, 0xff})
	if !strings.ContainsAny(urlSafe, "-_") {
		t.Fatalf("url-safe input %q does not use the URL alphabet", urlSafe)
	}
	binary := string([]byte{0x00, 0x01, 0x02, 0xff})
	exactly := strings.Repeat("!", 8*1024)
	nested := `{"a":{"b":{"c":"deep"}},"list":["mid",{"d":"deeper"}],"top":"shallow"}`
	several := `{"b64":"aGVsbG8=","hex":"68656c6c6f","note":"alpha beta"}`
	return []decodeInput{
		{"base64_padded", "aGVsbG8="},
		{"base64_missing_padding", "aGVsbG8"},
		{"base64_bad_padding", "aGVsbG8=="},
		{"base64_invalid_char", "aGVsbG8$"},
		{"base64_url_safe", urlSafe},
		{"base64_surrounding_whitespace", " \t\naGVsbG8=\r\n"},
		{"base64_internal_space", "aGVsb G8="},
		{"base64_internal_newline", "aGVsb\nG8="},
		{"hex_lower", "68656c6c6f"},
		{"hex_upper", "68656C6C6F"},
		{"hex_mixed", "68656c6C6F"},
		{"hex_odd_length", "68656c6c6"},
		{"hex_invalid_digit", "68656c6g"},
		{"hex_surrounding_whitespace", " \t68656c6c6f\n"},
		{"hex_binary_not_printable", hex.EncodeToString([]byte(binary))},
		{"base64_binary_not_printable", base64.StdEncoding.EncodeToString([]byte(binary))},
		{"binary_not_printable", binary},
		{"text_exactly_8kib", exactly},
		{"text_one_past_8kib", exactly + "!"},
		{"json_nested_leaves", nested},
		{"payload_several_candidates", several},
		{"payload_embedded_substrings", "prefix 68656c6c6f middle aGVsbG8= suffix"},
		{"json_without_string_leaves", `{"n":1,"ok":true}`},
		{"json_keys_out_of_order", `{"z":"zulu","a":"alpha","m":"mike"}`},
		{"json_duplicate_keys", `{"a":"first","a":"last"}`},
		{"json_escaped_unicode", `{"k":"é中 😀"}`},
		{"at_min_candidate", "abcd"},
		{"base64_interior_padding", "aGVs=bG8="},
		{"hex_0x_prefix", "0x68656c6c6f"},
		{"empty", ""},
		{"below_min_candidate", "abc"},
		{"whitespace_only", " \t\r\n"},
	}
}

func snapshotDecode(name, input string) decodeVector {
	decoded64, ok64 := tryBase64(input)
	decodedHex, okHex := tryHex(input)
	return decodeVector{
		Name:     name,
		InputHex: hex.EncodeToString([]byte(input)),
		TryBase64: decodeAttempt{
			DecodedHex: hex.EncodeToString([]byte(decoded64)),
			OK:         ok64,
		},
		TryHex: decodeAttempt{
			DecodedHex: hex.EncodeToString([]byte(decodedHex)),
			OK:         okHex,
		},
		PlausibleDecoded:  plausibleDecoded(input),
		LooksLikeHex:      looksLikeHex(input),
		LooksLikeBase64:   looksLikeBase64(input),
		PayloadCandidates: hexList(decodeCandidatesFromPayload(input)),
		ArgsCandidates:    hexList(decodeCandidatesFromArgs(json.RawMessage(input))),
	}
}

func hexList(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = hex.EncodeToString([]byte(s))
	}
	return out
}

func diffDecodeVector(t *testing.T, got, want decodeVector, regenerate string) {
	t.Helper()
	name := got.Name
	if name == "" {
		name = want.Name
	}
	checkField(t, name, "name", got.Name, want.Name, regenerate)
	checkField(t, name, "input_hex", got.InputHex, want.InputHex, regenerate)
	diffDecodeAttempt(t, name, "try_base64", got.TryBase64, want.TryBase64, regenerate)
	diffDecodeAttempt(t, name, "try_hex", got.TryHex, want.TryHex, regenerate)
	checkBool(t, name, "plausible_decoded", got.PlausibleDecoded, want.PlausibleDecoded, regenerate)
	checkBool(t, name, "looks_like_hex", got.LooksLikeHex, want.LooksLikeHex, regenerate)
	checkBool(t, name, "looks_like_base64", got.LooksLikeBase64, want.LooksLikeBase64, regenerate)
	diffHexList(t, name, "payload_candidates", got.PayloadCandidates, want.PayloadCandidates, regenerate)
	diffHexList(t, name, "args_candidates", got.ArgsCandidates, want.ArgsCandidates, regenerate)
}

func diffDecodeAttempt(t *testing.T, name, field string, got, want decodeAttempt, regenerate string) {
	t.Helper()
	checkField(t, name, field+".decoded_hex", got.DecodedHex, want.DecodedHex, regenerate)
	checkBool(t, name, field+".ok", got.OK, want.OK, regenerate)
}

func diffHexList(t *testing.T, name, field string, got, want []string, regenerate string) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("case %s: %s: got nil %t, want nil %t; regenerate with %s", name, field, got == nil, want == nil, regenerate)
	}
	if len(got) != len(want) {
		t.Fatalf("case %s: %s: got %d, want %d; regenerate with %s", name, field, len(got), len(want), regenerate)
	}
	for i := range got {
		checkField(t, name, field+"["+strconv.Itoa(i)+"]", got[i], want[i], regenerate)
	}
}

func checkBool(t *testing.T, name, field string, got, want bool, regenerate string) {
	t.Helper()
	if got != want {
		t.Fatalf("case %s: %s: got %t, want %t; regenerate with %s", name, field, got, want, regenerate)
	}
}
