// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

type resultTextVector struct {
	Name   string `json:"name"`
	Result string `json:"result_hex"`
	Text   string `json:"text_hex"`
}

type fragmentVector struct {
	Name    string     `json:"name"`
	Appends []string   `json:"appends"`
	Chunks  [][]string `json:"chunks_after_each"`
}

type taintVectorInput struct {
	Value  string `json:"value_hex"`
	Source string `json:"source"`
	Seq    uint64 `json:"seq"`
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
}

type taintRegistrationVector struct {
	Name     string                 `json:"name"`
	Batches  [][]taintVectorInput   `json:"batches"`
	Counters []taintVectorCounter   `json:"counter_batches"`
	Added    [][]string             `json:"added_hashes_per_batch"`
	Tainted  [][]string             `json:"tainted_after_each"`
	Details  [][]taintVectorDetails `json:"added_details_per_batch"`
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

func resultTextVectors() []resultTextVector {
	nested := func(depth int) string {
		return strings.Repeat("[", depth) + `"leaf"` + strings.Repeat("]", depth)
	}
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
	}
	vectors := make([]resultTextVector, 0, len(inputs))
	for _, in := range inputs {
		vectors = append(vectors, resultTextVector{in.name, ingestHex(in.result), ingestHex(extractResultText([]byte(in.result)))})
	}
	return vectors
}

func fragmentVectors() []fragmentVector {
	// Keep the inputs fixed when the defaults change.
	const bytesCap = 64 * 1024
	short := []string{"", "\n"}
	for i := 0; i < 17; i++ {
		short = append(short, fmt.Sprintf("%02d\n", i))
	}
	inputs := []struct {
		name   string
		chunks []string
	}{
		{"chunk_count_cap", short},
		{"byte_cap", []string{"a", strings.Repeat("b", bytesCap-2), "c", "d"}},
		{"oversized_single_chunk", []string{"head" + strings.Repeat("x", bytesCap-1) + "z"}},
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
		return taintVectorInput{ingestHex(value), source, seq}
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
				details = append(details, taintVectorDetails{forms, len(val.Chunks)})
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
				values = append(values, model.TaintedValue{Value: value, Hash: HashValue(value), Source: in.Source, Seq: in.Seq})
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
			v.Tainted = append(v.Tainted, containerTaintValue{taintVectorInput{ingestHex(val.Value), val.Source, val.Seq}, val.Hash, val.Preview})
		}
		vectors = append(vectors, v)
	}
	return vectors
}

func TestIngestVectors(t *testing.T) {
	got := struct {
		ResultText   []resultTextVector        `json:"extract_result_text"`
		Fragments    []fragmentVector          `json:"fragments"`
		Registration []taintRegistrationVector `json:"taint_registration"`
		Containers   []containerTaintVector    `json:"container_taint"`
	}{resultTextVectors(), fragmentVectors(), taintRegistrationVectors(t), containerTaintVectors(t)}
	checkVectorFile(t, "testdata/ingest_vectors.json", "go test ./internal/engine -run IngestVectors -update", got)
}
