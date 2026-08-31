package engine

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"net/url"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/yxshwanth/Interlock/internal/model"
)

// EncodingForm names a canonical transform applied to a tainted value at registration.
type EncodingForm string

const (
	FormLiteral      EncodingForm = "literal"
	FormBase64       EncodingForm = "base64"
	FormHex          EncodingForm = "hex"
	FormURLEncoded   EncodingForm = "url_encoded"
	FormReversed     EncodingForm = "reversed"
	FormBase64Hex    EncodingForm = "base64_hex" // base64(hex(secret))
	FormHexBase64    EncodingForm = "hex_base64" // hex(base64(secret))
	FormBase64URL    EncodingForm = "base64_url" // base64(url_encoded(secret))
	FormBase64Rev    EncodingForm = "base64_reversed"
	FormGzipBase64   EncodingForm = "gzip_base64"   // base64(gzip(secret))
	FormBrotliBase64 EncodingForm = "brotli_base64" // base64(brotli(secret))
	FormZstdBase64   EncodingForm = "zstd_base64"   // base64(zstd(secret))
	FormLZ4Base64    EncodingForm = "lz4_base64"    // base64(lz4-frame(secret))
)

// CanonicalEncodings returns the fixed transform set for a raw secret
// as TaintedVariant values ready for overlap checks and redaction.
// Includes single forms, a closed depth-2 nest set, and compressor+base64
// forms (gzip, brotli, zstd, lz4). Empty values return nil.
func CanonicalEncodings(value string) []model.TaintedVariant {
	if value == "" {
		return nil
	}

	b64 := base64.StdEncoding.EncodeToString([]byte(value))
	hx := hex.EncodeToString([]byte(value))
	ue := url.QueryEscape(value)
	rev := model.ReverseString(value)

	out := []model.TaintedVariant{
		{Form: string(FormLiteral), Value: value},
		{Form: string(FormBase64), Value: b64},
		{Form: string(FormHex), Value: hx},
		{Form: string(FormURLEncoded), Value: ue},
		{Form: string(FormReversed), Value: rev},
		// Depth-2 nests (closed list).
		{Form: string(FormBase64Hex), Value: base64.StdEncoding.EncodeToString([]byte(hx))},
		{Form: string(FormHexBase64), Value: hex.EncodeToString([]byte(b64))},
		{Form: string(FormBase64URL), Value: base64.StdEncoding.EncodeToString([]byte(ue))},
		{Form: string(FormBase64Rev), Value: base64.StdEncoding.EncodeToString([]byte(rev))},
	}
	if gz, err := gzipBase64(value); err == nil {
		out = append(out, model.TaintedVariant{Form: string(FormGzipBase64), Value: gz})
	}
	if br, err := brotliBase64(value); err == nil {
		out = append(out, model.TaintedVariant{Form: string(FormBrotliBase64), Value: br})
	}
	if zs, err := zstdBase64(value); err == nil {
		out = append(out, model.TaintedVariant{Form: string(FormZstdBase64), Value: zs})
	}
	if lz, err := lz4Base64(value); err == nil {
		out = append(out, model.TaintedVariant{Form: string(FormLZ4Base64), Value: lz})
	}
	return out
}

func gzipBase64(value string) (string, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(value)); err != nil {
		_ = gz.Close()
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func brotliBase64(value string) (string, error) {
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write([]byte(value)); err != nil {
		_ = w.Close()
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func zstdBase64(value string) (string, error) {
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		return "", err
	}
	if _, err := enc.Write([]byte(value)); err != nil {
		_ = enc.Close()
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func lz4Base64(value string) (string, error) {
	var buf bytes.Buffer
	w := lz4.NewWriter(&buf)
	if _, err := w.Write([]byte(value)); err != nil {
		_ = w.Close()
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
