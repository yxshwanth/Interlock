// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	tarPair := tarBytes(t, containerMember{"first", []byte("first\n")}, containerMember{"next", []byte("next\n")})
	inputs = append(inputs,
		// A nonzero block after an end marker is corrupt, even after a text member.
		input{"tar_zero_then_entry", bytes.Join([][]byte{tarPair[:1024], make([]byte, 512), tarPair[1024:]}, nil), def},
		// A partial block after an end marker is also corrupt.
		input{"tar_zero_then_partial", append(bytes.Clone(tarPair[:2560]), 'x'), def},
		// PAX path restores a legacy regular file and PAX size controls alignment.
		input{"tar_pax_path_and_size", tarPAXOverrides(t), def},
		// GNU long names replace the short path before legacy directory detection.
		input{"tar_gnu_long_name", tarGNULongName(t), def},
		// PAX 1.0 sparse maps are consumed and holes count toward the logical size.
		input{"tar_pax_sparse_1_0", tarPAXSparse(t), def},
		// A high-bit name byte distinguishes the accepted signed checksum.
		input{"tar_signed_checksum", tarSignedChecksum(t), def},
		// A short trailing central-directory extra record is ignored.
		input{"zip_truncated_extra", zipTruncatedExtra(zipOne), def},
		// A zero CRC with no data descriptor leaves CRC validation disabled.
		input{"zip_omitted_crc", zipStored(t, []byte("text without a CRC\n"), 0), def},
		// Trailing bytes after the declared ZIP comment are ignored.
		input{"zip_trailing_after_comment", zipTrailing(zipOne), def},
		// A non-ZIP prefix prevents container detection.
		input{"zip_prepended_plain_data", append([]byte("stub"), zipOne...), def},
		// A local-header signature in the prefix preserves detection and shifts the base offset.
		input{"zip_prepended_zip_data", append(bytes.Clone(zipOne[:30]), zipOne...), def},
	)

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

func zipTrailing(raw []byte) []byte {
	out := bytes.Clone(raw)
	binary.LittleEndian.PutUint16(out[len(out)-2:], 3)
	return append(out, "ziptrailing bytes"...)
}

func zipStored(t *testing.T, data []byte, crc uint32) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{
		Name: "file", Method: zip.Store, CRC32: crc,
		CompressedSize64: uint64(len(data)), UncompressedSize64: uint64(len(data)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipTruncatedExtra(raw []byte) []byte {
	const central = "PK\x01\x02"
	start := bytes.Index(raw, []byte(central))
	end := len(raw) - 22
	out := append(bytes.Clone(raw[:end]), 0xfe, 0xca, 0x01)
	out = append(out, raw[end:]...)
	binary.LittleEndian.PutUint16(out[start+30:], binary.LittleEndian.Uint16(raw[start+30:])+3)
	binary.LittleEndian.PutUint32(out[end+3+12:], uint32(end+3-start))
	return out
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

func tarPAXOverrides(t *testing.T) []byte {
	data := bytes.Repeat([]byte("a"), 513)
	raw := tarBytes(t,
		containerMember{"pax", []byte("13 path=file\n12 size=513\n")},
		containerMember{"short", data},
		containerMember{"next", []byte("next\n")},
	)
	raw[156] = tar.TypeXHeader
	tarChecksum(raw[:512], false)
	hdr := raw[1024:1536]
	copy(hdr, "short/")
	hdr[156] = tar.TypeRegA
	copy(hdr[124:136], "00000000001\x00")
	tarChecksum(hdr, false)
	return raw[:len(raw)-1024]
}

func tarGNULongName(t *testing.T) []byte {
	raw := tarBytes(t,
		containerMember{"long", append(bytes.Repeat([]byte("a"), 101), 0)},
		containerMember{"short", []byte("long name content\n")},
		containerMember{"next", []byte("next\n")},
	)
	raw[156] = tar.TypeGNULongName
	tarChecksum(raw[:512], false)
	hdr := raw[1024:1536]
	copy(hdr, "short/")
	hdr[156] = tar.TypeRegA
	tarChecksum(hdr, false)
	return raw[:len(raw)-1024]
}

func tarPAXSparse(t *testing.T) []byte {
	data := make([]byte, 512)
	copy(data, "1\n1\n12\n")
	data = append(data, "sparse text\n"...)
	raw := tarBytes(t,
		containerMember{"pax", []byte("22 GNU.sparse.major=1\n22 GNU.sparse.minor=0\n26 GNU.sparse.realsize=14\n")},
		containerMember{"sparse", data},
		containerMember{"next", []byte("next\n")},
	)
	raw[156] = tar.TypeXHeader
	tarChecksum(raw[:512], false)
	return raw[:len(raw)-1024]
}

func tarSignedChecksum(t *testing.T) []byte {
	raw := tarBytes(t, containerMember{"note", []byte("signed header\n")})
	raw[0] = 0xff
	tarChecksum(raw[:512], true)
	return raw[:1024]
}

func tarChecksum(header []byte, signed bool) {
	copy(header[148:156], "        ")
	sum := 0
	for _, b := range header {
		if signed {
			sum += int(int8(b))
		} else {
			sum += int(b)
		}
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", sum))
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
