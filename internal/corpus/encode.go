package corpus

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"net/url"
)

// Independent encoding helpers for scenario construction. Deliberately not
// calling engine.CanonicalEncodings — a corpus that encodes its "attack"
// payloads with the exact function it's testing would validate nothing.
// These mirror the transforms in internal/engine/encoding.go by using the
// same stdlib primitives directly, the same way internal/engine/*_test.go
// already does for its encoded-exfil tests.

func b64(s string) string    { return base64.StdEncoding.EncodeToString([]byte(s)) }
func hx(s string) string     { return hex.EncodeToString([]byte(s)) }
func urlEnc(s string) string { return url.QueryEscape(s) }

func reversed(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func gzipB64(s string) string {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(s))
	_ = gz.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}
