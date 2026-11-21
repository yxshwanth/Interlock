// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

// Outputs at most this long are stored as text_hex. Longer outputs are stored
// as text_len and text_sha256.
const ingestVectorTextHexLimit = 256

// A pad is prefix_hex, then byte (0-255) repeated count times, then
// suffix_hex. ingestPadRule is stored in the fixture as pad_rule.
type resultPad struct {
	PrefixHex string `json:"prefix_hex"`
	Byte      int    `json:"byte"`
	Count     int    `json:"count"`
	SuffixHex string `json:"suffix_hex"`
}

var ingestPadRule = fmt.Sprintf("Concatenate pads in order. Each pad is the bytes of prefix_hex, then byte repeated count times, then the bytes of suffix_hex. byte is an integer from 0 to 255. prefix_hex and suffix_hex are lowercase hex and may be empty. The Rust test expands pads the same way to build the raw result, then compares the extractor output to text_hex when that field is present. When the output is longer than %d bytes, compare its byte length to text_len and the lowercase hex SHA-256 of its bytes to text_sha256. The output is raw bytes and may be invalid UTF-8.", ingestVectorTextHexLimit)

type resultTextVector struct {
	Name       string      `json:"name"`
	ResultHex  *string     `json:"result_hex,omitempty"`
	TextHex    *string     `json:"text_hex,omitempty"`
	Pads       []resultPad `json:"pads,omitempty"`
	TextLen    int         `json:"text_len,omitempty"`
	TextSHA256 string      `json:"text_sha256,omitempty"`
}

type fragmentVector struct {
	Name    string     `json:"name"`
	Appends []string   `json:"appends"`
	Chunks  [][]string `json:"chunks_after_each"`
}

type taintVectorInput struct {
	Value    string   `json:"value_hex"`
	Source   string   `json:"source"`
	Seq      uint64   `json:"seq"`
	Variants []string `json:"variant_forms,omitempty"`
}

// Generate count values of size bytes. Each starts with the zero-padded
// eight-digit decimal counter and is filled to size with ASCII 'x'.
type taintVectorCounter struct {
	Start  int    `json:"start"`
	Count  int    `json:"count"`
	Size   int    `json:"size"`
	Source string `json:"source"`
	Seq    uint64 `json:"seq"`
}

type taintVectorDetails struct {
	Forms      []string `json:"forms"`
	ChunkCount int      `json:"chunk_count"`
	Source     string   `json:"source,omitempty"`
	Seq        uint64   `json:"seq,omitempty"`
}

type taintRegistrationVector struct {
	Name        string                 `json:"name"`
	Batches     [][]taintVectorInput   `json:"batches"`
	Counters    []taintVectorCounter   `json:"counter_batches"`
	Added       [][]string             `json:"added_hashes_per_batch"`
	Tainted     [][]string             `json:"tainted_after_each"`
	Details     [][]taintVectorDetails `json:"added_details_per_batch"`
	pinIdentity bool                   `json:"-"`
}

type containerTaintValue struct {
	taintVectorInput
	Hash    string `json:"hash"`
	Preview string `json:"preview"`
}

type containerTaintVector struct {
	Name     string                `json:"name"`
	Result   string                `json:"result_hex"`
	Source   string                `json:"source"`
	Seq      uint64                `json:"seq"`
	MaxBytes int                   `json:"max_decompressed_bytes"`
	Tainted  []containerTaintValue `json:"tainted"`
}

func ingestHex(s string) string { return hex.EncodeToString([]byte(s)) }

func hexPad(prefix string, b byte, count int, suffix string) resultPad {
	return resultPad{
		PrefixHex: hex.EncodeToString([]byte(prefix)),
		Byte:      int(b),
		Count:     count,
		SuffixHex: hex.EncodeToString([]byte(suffix)),
	}
}

func expandPads(t *testing.T, pads []resultPad) []byte {
	t.Helper()
	var b bytes.Buffer
	for _, p := range pads {
		prefix, err := hex.DecodeString(p.PrefixHex)
		if err != nil {
			t.Fatalf("pad prefix_hex: %v", err)
		}
		suffix, err := hex.DecodeString(p.SuffixHex)
		if err != nil {
			t.Fatalf("pad suffix_hex: %v", err)
		}
		if p.Byte < 0 || p.Byte > 255 || p.Count < 0 {
			t.Fatalf("pad byte %d count %d", p.Byte, p.Count)
		}
		b.Write(prefix)
		b.Write(bytes.Repeat([]byte{byte(p.Byte)}, p.Count))
		b.Write(suffix)
	}
	return b.Bytes()
}

func resultVector(t *testing.T, name string, raw []byte, pads []resultPad) resultTextVector {
	t.Helper()
	if len(pads) > 0 {
		raw = expandPads(t, pads)
	}
	text := extractResultText(raw)
	v := resultTextVector{Name: name, Pads: pads}
	if len(pads) == 0 {
		result := ingestHex(string(raw))
		v.ResultHex = &result
	}
	if len(text) <= ingestVectorTextHexLimit {
		out := ingestHex(text)
		v.TextHex = &out
		return v
	}
	sum := sha256.Sum256([]byte(text))
	v.TextLen = len(text)
	v.TextSHA256 = hex.EncodeToString(sum[:])
	return v
}

func resultTextVectors(t *testing.T) []resultTextVector {
	t.Helper()
	nested := func(depth int) string {
		return strings.Repeat("[", depth) + `"leaf"` + strings.Repeat("]", depth)
	}
	// Maps with several string keys are avoided because Go's iteration order is random.
	inputs := []struct{ name, result string }{
		{"one_text_item", `{"content":[{"type":"text","text":"first"}]}`},
		{"several_text_items", `{"content":[{"type":"text","text":"first"},{"type":"text","text":"second"}]}`},
		{"non_text_item", `{"content":[{"type":"image","data":"picture"}]}`},
		{"bare_string", `"plain"`},
		{"nested_objects_and_arrays", `{"data":[{"first":"alpha"},[true,"beta",null],{"content":["gamma"]}]}`},
		{"depth_at_limit", nested(8)},
		{"depth_past_limit", `["shallow",` + nested(8) + `]`},
		{"invalid_json", "{\xff"},
		{"invalid_json_after_content", `{"content":[{"type":"text","text":"first"}]`},
		{"number_overflow_with_content", `{"content":[{"type":"text","text":"first"}],"number":1e400}`},
		{"empty", ""},
		{"null", "null"},
		{"unicode_and_escapes", `{"content":[{"type":"text","text":"雪 \uD83D\uDE03\n\t\"\\"}]}`},
		{"duplicate_keys", `{"data":"first","data":"last"}`},
		{"content_and_other_strings", `{"content":[{"type":"text","text":"first"},{"type":"image","data":"picture"}],"other":"second"}`},
		{"content_string", `{"content":"str"}`},
		{"content_object", `{"content":{}}`},
		{"content_null", `{"content":null}`},
	}
	vectors := make([]resultTextVector, 0, len(inputs)+3)
	for _, in := range inputs {
		vectors = append(vectors, resultVector(t, in.name, []byte(in.result), nil))
	}
	// 30000 + newline + 30000 + newline leaves the cap inside the next string.
	// cap-1 pad bytes leave the first byte of U+00E9 (c3 a9) on the cut.
	cap := maxExtractBytes
	vectors = append(vectors,
		resultVector(t, "byte_cap_one_string", nil, []resultPad{
			hexPad(`"`, 'a', cap+8, `"`),
		}),
		resultVector(t, "byte_cap_many_strings", nil, []resultPad{
			hexPad(`["`, 'A', 30000, `","`),
			hexPad("", 'B', 30000, `","`),
			hexPad("", 'C', 30000, `","`),
			hexPad("", 'D', 100, `"]`),
		}),
		resultVector(t, "byte_cap_multibyte_rune", nil, []resultPad{
			hexPad(`"`, 'a', cap-1, string([]byte{0xc3, 0xa9})+`"`),
		}),
	)
	return vectors
}

func fragmentVectors() []fragmentVector {
	// Keep the inputs fixed when the defaults change.
	const bytesCap = 64 * 1024
	short := []string{"", "\n"}
	for i := 0; i < 17; i++ {
		short = append(short, fmt.Sprintf("%02d\n", i))
	}
	filled := make([]string, 0, 18)
	for i := 0; i < 16; i++ {
		filled = append(filled, fmt.Sprintf("%02d", i))
	}
	filled = append(filled, "", "\n")
	inputs := []struct {
		name   string
		chunks []string
	}{
		{"chunk_count_cap", short},
		{"byte_cap", []string{"a", strings.Repeat("b", bytesCap-2), "c", "d"}},
		{"oversized_single_chunk", []string{"head" + strings.Repeat("x", bytesCap-1) + "z"}},
		{"empty_after_full", filled},
		{"byte_cap_drops_several", []string{"a", "b", "c", "d", strings.Repeat("e", bytesCap-1)}},
	}
	vectors := make([]fragmentVector, 0, len(inputs))
	eng := &Engine{}
	for _, in := range inputs {
		v := fragmentVector{Name: in.name}
		var state model.SessionState
		for _, chunk := range in.chunks {
			v.Appends = append(v.Appends, ingestHex(chunk))
			after := make([]string, 0, len(state.FragmentChunks)+1)
			eng.appendFragment(&state, chunk)
			for _, got := range state.FragmentChunks {
				after = append(after, ingestHex(got))
			}
			v.Chunks = append(v.Chunks, after)
		}
		vectors = append(vectors, v)
	}
	return vectors
}

func taintRegistrationVectors(t *testing.T) []taintRegistrationVector {
	input := func(value, source string, seq uint64) taintVectorInput {
		return taintVectorInput{Value: ingestHex(value), Source: source, Seq: seq}
	}
	vectors := []taintRegistrationVector{
		{
			Name: "dedupe_and_attachments",
			Batches: [][]taintVectorInput{
				{input("sample +/雪", "first", 1), input("sample +/雪", "duplicate", 2), input(strings.Repeat("1234567890", 30), "first", 1)},
				{input("sample +/雪", "second", 3), input("another + value", "second", 3)},
				{input("another + value", "third", 4)},
			},
			Counters: []taintVectorCounter{},
		},
		{
			Name: "shed_at_count_cap", Batches: [][]taintVectorInput{},
			Counters: []taintVectorCounter{{0, 1023, 8, "counter", 1}, {1023, 1, 8, "counter", 2}, {1024, 2, 8, "counter", 3}},
		},
		{
			Name: "shed_at_byte_cap", Batches: [][]taintVectorInput{},
			Counters: []taintVectorCounter{{0, 15, 65536, "counter", 1}, {15, 1, 65536, "counter", 2}, {16, 2, 65536, "counter", 3}},
		},
		{
			Name: "oversized_single_kept", Batches: [][]taintVectorInput{},
			Counters: []taintVectorCounter{{0, 1, maxTaintedBytesPerSession + 1, "counter", 1}},
		},
		{
			Name: "byte_total_at_cap", Batches: [][]taintVectorInput{},
			Counters: []taintVectorCounter{{0, 2, maxTaintedBytesPerSession / 2, "counter", 1}},
		},
		{
			Name: "shed_keeps_newest", Batches: [][]taintVectorInput{},
			Counters: []taintVectorCounter{
				{0, 1, maxTaintedBytesPerSession / 2, "counter", 1},
				{1, 1, maxTaintedBytesPerSession/2 + 1, "counter", 2},
			},
		},
		{
			Name: "preset_variants", Counters: []taintVectorCounter{},
			Batches: [][]taintVectorInput{{
				{ingestHex("preset-value"), "tool", 4, []string{"preset", "kept"}},
			}},
		},
		{
			Name: "same_value_different_seq", pinIdentity: true, Counters: []taintVectorCounter{},
			Batches: [][]taintVectorInput{{
				{ingestHex("repeat-me"), "first", 1, nil},
				{ingestHex("repeat-me"), "later", 9, nil},
			}},
		},
	}
	eng, _ := newTestEngine("block")
	for i := range vectors {
		v := &vectors[i]
		state := model.SessionState{SessionID: v.Name}
		addBatch := func(batch []model.TaintedValue) {
			added := eng.addTainted(&state, batch)
			details := make([]taintVectorDetails, 0, len(added))
			for _, val := range added {
				forms := make([]string, 0, len(val.Variants))
				for _, variant := range val.Variants {
					forms = append(forms, variant.Form)
				}
				d := taintVectorDetails{Forms: forms, ChunkCount: len(val.Chunks)}
				if v.pinIdentity {
					d.Source = val.Source
					d.Seq = val.Seq
				}
				details = append(details, d)
			}
			v.Added = append(v.Added, ingestHashes(added))
			v.Tainted = append(v.Tainted, ingestHashes(state.Tainted))
			v.Details = append(v.Details, details)
		}
		for _, batch := range v.Batches {
			values := make([]model.TaintedValue, 0, len(batch))
			for _, in := range batch {
				raw, err := hex.DecodeString(in.Value)
				if err != nil {
					t.Fatalf("%s: decode value_hex %q: %v", v.Name, in.Value, err)
				}
				value := string(raw)
				tv := model.TaintedValue{Value: value, Hash: HashValue(value), Source: in.Source, Seq: in.Seq}
				for _, form := range in.Variants {
					tv.Variants = append(tv.Variants, model.TaintedVariant{Form: form})
				}
				values = append(values, tv)
			}
			addBatch(values)
		}
		for _, in := range v.Counters {
			values := make([]model.TaintedValue, 0, in.Count)
			padding := strings.Repeat("x", in.Size-8)
			for n := in.Start; n < in.Start+in.Count; n++ {
				value := fmt.Sprintf("%08d", n) + padding
				values = append(values, model.TaintedValue{Value: value, Hash: HashValue(value), Source: in.Source, Seq: in.Seq})
			}
			addBatch(values)
		}
	}
	return vectors
}

func ingestHashes(values []model.TaintedValue) []string {
	hashes := make([]string, 0, len(values))
	for _, v := range values {
		hashes = append(hashes, v.Hash)
	}
	return hashes
}

func ingestArchive(t *testing.T, format, member string) []byte {
	t.Helper()
	var buf bytes.Buffer
	var writer io.Writer
	var closer io.Closer
	switch format {
	case "zip":
		w := zip.NewWriter(&buf)
		entry, err := w.Create("sample.txt")
		if err != nil {
			t.Fatal(err)
		}
		writer, closer = entry, w
	case "gzip":
		w := gzip.NewWriter(&buf)
		writer, closer = w, w
	case "tar":
		w := tar.NewWriter(&buf)
		if err := w.WriteHeader(&tar.Header{Name: "sample.txt", Mode: 0o644, Size: int64(len(member))}); err != nil {
			t.Fatal(err)
		}
		writer, closer = w, w
	default:
		t.Fatalf("unknown archive format %q", format)
	}
	if _, err := io.WriteString(writer, member); err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func containerTaintVectors(t *testing.T) []containerTaintVector {
	const member = "token=sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef\n"
	inputs := []struct {
		name, format, member string
		maxBytes             int
	}{
		{"zip_secret", "zip", member, 128},
		{"gzip_secret", "gzip", member, 128},
		{"tar_secret", "tar", member, 128},
		{"no_secret", "zip", "ordinary sample text\n", 128},
		{"over_byte_cap", "gzip", member + strings.Repeat("x", 128), 128},
	}
	eng, _ := newTestEngine("block")
	vectors := make([]containerTaintVector, 0, len(inputs))
	for i, in := range inputs {
		result := mustJSON(base64.StdEncoding.EncodeToString(ingestArchive(t, in.format, in.member)))
		v := containerTaintVector{
			Name: in.name, Result: ingestHex(result), Source: "archive/read", Seq: uint64(i + 1),
			MaxBytes: in.maxBytes, Tainted: []containerTaintValue{},
		}
		eng.containerLimits.MaxDecompressedBytes = v.MaxBytes
		for _, val := range eng.taintFromContainer(extractResultText([]byte(result)), v.Source, v.Seq) {
			v.Tainted = append(v.Tainted, containerTaintValue{
				taintVectorInput: taintVectorInput{Value: ingestHex(val.Value), Source: val.Source, Seq: val.Seq},
				Hash:             val.Hash, Preview: val.Preview,
			})
		}
		vectors = append(vectors, v)
	}
	return vectors
}

func TestIngestVectors(t *testing.T) {
	got := struct {
		PadRule      string                    `json:"pad_rule"`
		ResultText   []resultTextVector        `json:"extract_result_text"`
		Fragments    []fragmentVector          `json:"fragments"`
		Registration []taintRegistrationVector `json:"taint_registration"`
		Containers   []containerTaintVector    `json:"container_taint"`
	}{ingestPadRule, resultTextVectors(t), fragmentVectors(), taintRegistrationVectors(t), containerTaintVectors(t)}
	checkVectorFile(t, "testdata/ingest_vectors.json", "go test ./internal/engine -run IngestVectors -update", got)
}
