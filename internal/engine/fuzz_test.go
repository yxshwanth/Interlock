// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

// Fuzz targets (ROADMAP §84). `go test` runs the seeds below plus anything in
// testdata/fuzz as ordinary tests; scripts/fuzz.sh explores for real. The
// invariants are the ones the rest of the system relies on.

const fuzzSecret = "sk-live-Fz7Qw3ErTy5UiOp9AsDf"

func fuzzTainted() []model.TaintedValue {
	return ExtractTaintedValues("auth token: "+fuzzSecret, "fuzz", 1)
}

func zipSeed() []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, _ := w.Create("a.txt")
	f.Write([]byte("hello " + fuzzSecret))
	w.Close()
	return b.Bytes()
}

func gzipSeed(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func zlibSeed(s string) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

// Hostile archives must stay inside the configured limits and never panic.
func FuzzInspectContainer(f *testing.F) {
	f.Add(zipSeed())
	f.Add(gzipSeed("hello " + fuzzSecret))
	f.Add(zlibSeed("hello " + fuzzSecret))
	f.Add(append(bytes.Repeat([]byte{0}, 257), []byte("ustar")...))
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		lim := DefaultContainerLimits()
		res := InspectContainer(raw, lim)
		if res.PartsN > lim.MaxParts+1 {
			t.Fatalf("PartsN %d exceeds MaxParts %d", res.PartsN, lim.MaxParts)
		}
		if res.Bytes > 2*lim.MaxDecompressedBytes {
			t.Fatalf("Bytes %d exceeds twice MaxDecompressedBytes", res.Bytes)
		}
	})
}

// Whatever arrives as sink args, overlap checking must not panic.
func FuzzCheckOverlap(f *testing.F) {
	f.Add([]byte(`{"body":"` + fuzzSecret + `"}`))
	f.Add([]byte(`{"a":["x",{"b":"y"}],"c":null}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`"\ud800"`))
	tainted := fuzzTainted()
	f.Fuzz(func(t *testing.T, args []byte) {
		CheckOverlap(tainted, json.RawMessage(args))
		CheckOverlapPayload(tainted, string(args))
	})
}

// Metamorphic: no surrounding text, however odd, may hide a literal secret
// inside a JSON string. Adding noise never removes a catch.
func FuzzCheckOverlap_PlantedLiteralIsFound(f *testing.F) {
	f.Add("", "")
	f.Add("Here is the data: ", " thanks")
	f.Add("\x00‮\U0001f600", "\n\t\"\\")
	f.Add(strings.Repeat("A", 4000), strings.Repeat("B", 4000))
	tainted := fuzzTainted()
	f.Fuzz(func(t *testing.T, prefix, suffix string) {
		args, err := json.Marshal(map[string]string{"body": prefix + fuzzSecret + suffix})
		if err != nil {
			t.Skip()
		}
		if CheckOverlap(tainted, args) == nil {
			t.Fatalf("literal secret hidden by prefix %q suffix %q", prefix, suffix)
		}
	})
}

func FuzzDecodeMatchCandidates(f *testing.F) {
	f.Add("c2stbGl2ZS1GejdRdzNFclR5NVVpT3A5QXNEZg==")
	f.Add("736b2d6c6976652d")
	f.Add(strings.Repeat("A", 70000))
	f.Add("====")
	tainted := fuzzTainted()
	f.Fuzz(func(t *testing.T, s string) {
		decodeMatchCandidates(s, tainted, nil, 0)
	})
}

// Every extracted value must come from the text it was extracted from.
func FuzzExtractTaintedValues(f *testing.F) {
	f.Add("auth token: " + fuzzSecret)
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----")
	f.Add("acct_" + strings.Repeat("a", 5000))
	f.Fuzz(func(t *testing.T, text string) {
		for _, v := range ExtractTaintedValues(text, "fuzz", 1) {
			if !strings.Contains(text, v.Value) {
				t.Fatalf("value %q is not a substring of its source", v.Value)
			}
		}
	})
}

func FuzzVerifyChain(f *testing.F) {
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"session_id":"s","chain_seq":0,"hash":"","prev_hash":""}]`))
	f.Add([]byte(`[{"chain_seq":5},{"chain_seq":1,"prev_hash":"zz"}]`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var recs []model.EvidenceRecord
		if json.Unmarshal(raw, &recs) != nil {
			t.Skip()
		}
		_ = VerifyChain(recs)
	})
}
