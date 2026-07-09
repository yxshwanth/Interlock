package engine

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"

	"github.com/yxshwanth/Interlock/internal/model"
)

// EncodingForm names a canonical transform applied to a tainted value at registration.
type EncodingForm string

const (
	FormLiteral    EncodingForm = "literal"
	FormBase64     EncodingForm = "base64"
	FormHex        EncodingForm = "hex"
	FormURLEncoded EncodingForm = "url_encoded"
	FormReversed   EncodingForm = "reversed"
)

// CanonicalEncodings returns the fixed v0.2 transform set for a raw secret
// as TaintedVariant values ready for overlap checks and redaction.
// Empty values return nil.
func CanonicalEncodings(value string) []model.TaintedVariant {
	if value == "" {
		return nil
	}

	return []model.TaintedVariant{
		{Form: string(FormLiteral), Value: value},
		{Form: string(FormBase64), Value: base64.StdEncoding.EncodeToString([]byte(value))},
		{Form: string(FormHex), Value: hex.EncodeToString([]byte(value))},
		{Form: string(FormURLEncoded), Value: url.QueryEscape(value)},
		{Form: string(FormReversed), Value: reverseString(value)},
	}
}

func reverseString(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}
