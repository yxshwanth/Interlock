package engine

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
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

// EncodedForm pairs a transform name with its encoded string for overlap checks.
type EncodedForm struct {
	Form  EncodingForm
	Value string
}

// CanonicalEncodings returns the fixed v0.2 transform set for a raw secret.
// Empty values return nil.
func CanonicalEncodings(value string) []EncodedForm {
	if value == "" {
		return nil
	}

	return []EncodedForm{
		{Form: FormLiteral, Value: value},
		{Form: FormBase64, Value: base64.StdEncoding.EncodeToString([]byte(value))},
		{Form: FormHex, Value: hex.EncodeToString([]byte(value))},
		{Form: FormURLEncoded, Value: url.QueryEscape(value)},
		{Form: FormReversed, Value: reverseString(value)},
	}
}

func reverseString(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}
