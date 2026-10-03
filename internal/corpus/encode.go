package corpus

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strconv"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/yxshwanth/Interlock/internal/model"
)

// Independent encoding helpers for scenario construction. Deliberately not
// calling engine.CanonicalEncodings — a corpus that encodes its "attack"
// payloads with the exact function it's testing would validate nothing.
// These mirror the transforms in internal/engine/encoding.go by using the
// same stdlib / third-party primitives directly, the same way
// internal/engine/*_test.go already does for its encoded-exfil tests.

func b64(s string) string    { return base64.StdEncoding.EncodeToString([]byte(s)) }
func hx(s string) string     { return hex.EncodeToString([]byte(s)) }
func urlEnc(s string) string { return url.QueryEscape(s) }

func reversed(s string) string { return model.ReverseString(s) }

func gzipB64(s string) string {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(s))
	_ = gz.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func brotliB64(s string) string {
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func zstdB64(s string) string {
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		return ""
	}
	_, _ = enc.Write([]byte(s))
	_ = enc.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func lz4B64(s string) string {
	var buf bytes.Buffer
	w := lz4.NewWriter(&buf)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// zipMember builds a minimal ZIP archive with a single named text member.
func zipMember(name, contents string) string {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		return ""
	}
	if _, err := w.Write([]byte(contents)); err != nil {
		_ = zw.Close()
		return ""
	}
	if err := zw.Close(); err != nil {
		return ""
	}
	return buf.String()
}

// zipManyParts builds a ZIP with n small text members (inspect-bomb fixture).
func zipManyParts(n int) string {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < n; i++ {
		name := "p" + strconv.Itoa(i) + ".txt"
		w, err := zw.Create(name)
		if err != nil {
			_ = zw.Close()
			return ""
		}
		if _, err := w.Write([]byte("pad")); err != nil {
			_ = zw.Close()
			return ""
		}
	}
	if err := zw.Close(); err != nil {
		return ""
	}
	return buf.String()
}

// zlibWrap compresses s with zlib (packfile-adjacent flat wire shape).
func zlibWrap(s string) string {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		_ = zw.Close()
		return ""
	}
	if err := zw.Close(); err != nil {
		return ""
	}
	return buf.String()
}
