// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"
)

// containerVectorTime is the fixed modification time baked into every archive.
var containerVectorTime = time.Date(2024, 1, 2, 3, 4, 6, 0, time.UTC)

type containerVectorLimits struct {
	Enabled              bool `json:"enabled"`
	MaxDecompressedBytes int  `json:"max_decompressed_bytes"`
	MaxDescentDepth      int  `json:"max_descent_depth"`
	MaxParts             int  `json:"max_parts"`
}

type containerVector struct {
	Name               string                `json:"name"`
	InputHex           string                `json:"input_hex"`
	Limits             containerVectorLimits `json:"limits"`
	LooksLikeContainer bool                  `json:"looks_like_container"`
	PartsHex           []string              `json:"parts_hex"`
	Abort              string                `json:"abort"`
	Bytes              int                   `json:"bytes"`
	PartsN             int                   `json:"parts_n"`
}

type containerMember struct {
	name string
	data []byte
}

func TestContainerVectors(t *testing.T) {
	const path = "testdata/container_vectors.json"
	const regenerate = "go test ./internal/engine -run ContainerVectors -update"

	got := containerVectors(t)
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
	want := make([]containerVector, 0, len(raws))
	for i, raw := range raws {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var v containerVector
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("case %d: %v; regenerate with %s", i, err, regenerate)
		}
		want = append(want, v)
	}
	n := min(len(got), len(want))
	for i := 0; i < n; i++ {
		diffContainerVector(t, got[i], want[i], regenerate)
	}
	if len(got) != len(want) {
		t.Fatalf("cases: got %d, want %d; regenerate with %s", len(got), len(want), regenerate)
	}
}

func containerVectors(t *testing.T) []containerVector {
	t.Helper()
	def := DefaultContainerLimits()
	limits := func(mut func(*ContainerLimits)) ContainerLimits {
		l := def
		if mut != nil {
			mut(&l)
		}
		return l
	}

	text := []byte("Customer token: sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef\n")
	zipOne := zipBytes(t, containerMember{"note.txt", text})
	zipMany := zipBytes(t,
		containerMember{"a.txt", []byte("alpha member\n")},
		containerMember{"b.txt", []byte("bravo member\n")},
		containerMember{"c.txt", []byte("charlie member\n")},
	)
	zipBinary := zipBytes(t,
		containerMember{"blob.bin", []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x80, 0x81, 0x00}},
		containerMember{"note.txt", []byte("plain text beside the blob\n")},
	)
	gz := gzipBytes(t, text)
	zl := zlibBytes(t, text)
	encryptedZIP := bytes.Clone(zipOne)
	// Set the encrypted bit in both headers. The walker must reject the member
	// before trying to interpret its payload.
	encryptedZIP[6] |= 1
	encryptedZIP[bytes.Index(encryptedZIP, []byte("PK\x01\x02"))+8] |= 1
	badDescriptorZIP := bytes.Clone(zipOne)
	badDescriptorZIP[bytes.Index(badDescriptorZIP, []byte("PK\x07\x08"))+4] ^= 1
	// kept is charged first. fills uses the rest of the budget exactly.
	// over is one byte past that, so the walk aborts on the second member.
	kept := []byte("alpha\n")
	fills := []byte("beta")
	over := append(append([]byte{}, fills...), '!')
	byteBudget := len(kept) + len(fills)
	zipByteExact := zipBytes(t,
		containerMember{"a.txt", kept},
		containerMember{"b.txt", fills},
	)
	zipByteOver := zipBytes(t,
		containerMember{"a.txt", kept},
		containerMember{"b.txt", over},
	)

	type input struct {
		name string
		raw  []byte
		lim  ContainerLimits
	}
	inputs := []input{
		{"zip_one_text_member", zipOne, def},
		{"zip_bad_data_descriptor", badDescriptorZIP, def},
		{"zip_several_members", zipMany, def},
		{"gzip", gz, def},
		{"gzip_multistream", bytes.Join([][]byte{gz, gzipBytes(t, []byte("second stream\n"))}, nil), def},
		{"gzip_truncated_trailer", gz[:len(gz)-1], def},
		{"gzip_trailing_garbage", append(bytes.Clone(gz), 'x'), def},
		{"zlib", zl, def},
		{"zlib_truncated_trailer", zl[:len(zl)-1], def},
		{"zlib_trailing_garbage", append(bytes.Clone(zl), 'x'), def},
		{"tar", tarBytes(t, containerMember{"note.txt", text}), def},
		{"tar_dir_then_file", tarBytes(t,
			containerMember{"dir/", nil},
			containerMember{"dir/note.txt", text},
		), def},
		{"zip_inside_gzip", gzipBytes(t, zipOne), def},
		{"zip_gzip_then_text", zipBytes(t,
			containerMember{"payload.gz", gzipBytes(t, []byte("nested\n"))},
			containerMember{"after.txt", []byte("sibling\n")},
		), def},
		{"zip_binary_member", zipBinary, def},
		{"empty_input", nil, def},
		{"truncated_zip", zipMany[:len(zipMany)/2], def},
		{"encrypted_zip_member", encryptedZIP, def},
		{"zip_duplicate_names", zipBytes(t,
			containerMember{"same.txt", []byte("first\n")},
			containerMember{"same.txt", []byte("second\n")},
		), def},
		{"not_a_container", []byte("just plain text"), def},
		{"disabled", zipOne, limits(func(l *ContainerLimits) { l.Enabled = false })},
		{"cap_max_parts", zipMany, limits(func(l *ContainerLimits) { l.MaxParts = 2 })},
		{"cap_max_bytes", zipOne, limits(func(l *ContainerLimits) { l.MaxDecompressedBytes = 16 })},
		{"cap_max_bytes_later_exact", zipByteExact, limits(func(l *ContainerLimits) { l.MaxDecompressedBytes = byteBudget })},
		{"cap_max_bytes_later_over", zipByteOver, limits(func(l *ContainerLimits) { l.MaxDecompressedBytes = byteBudget })},
		{"cap_tar_exactly_one_byte_over", tarBytes(t, containerMember{"short.txt", fills})[:512+len(fills)],
			limits(func(l *ContainerLimits) { l.MaxDecompressedBytes = len(fills) - 1 })},
		{"cap_max_depth", gzipBytes(t, gzipBytes(t, gzipBytes(t, text))), limits(func(l *ContainerLimits) { l.MaxDescentDepth = 1 })},
	}

	got := make([]containerVector, 0, len(inputs))
	for _, in := range inputs {
		res := InspectContainer(in.raw, in.lim)
		parts := make([]string, 0, len(res.Parts))
		for _, p := range res.Parts {
			parts = append(parts, hex.EncodeToString([]byte(p)))
		}
		got = append(got, containerVector{
			Name:     in.name,
			InputHex: hex.EncodeToString(in.raw),
			Limits: containerVectorLimits{
				Enabled:              in.lim.Enabled,
				MaxDecompressedBytes: in.lim.MaxDecompressedBytes,
				MaxDescentDepth:      in.lim.MaxDescentDepth,
				MaxParts:             in.lim.MaxParts,
			},
			LooksLikeContainer: LooksLikeContainer(in.raw),
			PartsHex:           parts,
			Abort:              string(res.Abort),
			Bytes:              res.Bytes,
			PartsN:             res.PartsN,
		})
	}
	return got
}

func zipBytes(t *testing.T, members ...containerMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: m.name, Method: zip.Deflate, Modified: containerVectorTime})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(m.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Name = "payload"
	gw.ModTime = containerVectorTime
	if _, err := gw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tarBytes(t *testing.T, members ...containerMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		// A name ending in / is a directory header and has no body.
		dir := len(m.name) > 0 && m.name[len(m.name)-1] == '/'
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     m.name,
			Mode:     0o644,
			Size:     int64(len(m.data)),
			ModTime:  containerVectorTime,
			Format:   tar.FormatUSTAR,
		}
		if dir {
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0o755
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if dir {
			continue
		}
		if _, err := tw.Write(m.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func diffContainerVector(t *testing.T, got, want containerVector, regenerate string) {
	t.Helper()
	name := got.Name
	if name == "" {
		name = want.Name
	}
	checkField(t, name, "name", got.Name, want.Name, regenerate)
	checkField(t, name, "input_hex", got.InputHex, want.InputHex, regenerate)
	if got.Limits != want.Limits {
		t.Fatalf("case %s: limits: got %+v, want %+v; regenerate with %s", name, got.Limits, want.Limits, regenerate)
	}
	if got.LooksLikeContainer != want.LooksLikeContainer {
		t.Fatalf("case %s: looks_like_container: got %v, want %v; regenerate with %s", name, got.LooksLikeContainer, want.LooksLikeContainer, regenerate)
	}
	if len(got.PartsHex) != len(want.PartsHex) {
		t.Fatalf("case %s: parts_hex: got %d parts, want %d; regenerate with %s", name, len(got.PartsHex), len(want.PartsHex), regenerate)
	}
	for i := range got.PartsHex {
		checkField(t, name, "parts_hex["+strconv.Itoa(i)+"]", got.PartsHex[i], want.PartsHex[i], regenerate)
	}
	checkField(t, name, "abort", got.Abort, want.Abort, regenerate)
	if got.Bytes != want.Bytes {
		t.Fatalf("case %s: bytes: got %d, want %d; regenerate with %s", name, got.Bytes, want.Bytes, regenerate)
	}
	if got.PartsN != want.PartsN {
		t.Fatalf("case %s: parts_n: got %d, want %d; regenerate with %s", name, got.PartsN, want.PartsN, regenerate)
	}
}
