package engine

import (
	"fmt"
	"strings"

	"github.com/yxshwanth/Interlock/internal/model"
)

const (
	defaultChunkMatchBytes = 32
	defaultChunkMatchMinLen = 64
)

// AttachChunks populates tv.Chunks with non-overlapping contiguous N-byte
// slices of the secret body when len(value) >= minLen. PEM/PuTTY armor
// headers are stripped first so universal constants like
// "-----BEGIN PRIVATE KEY-----" cannot alone produce an EXFIL hit.
//
// n <= 0 or minLen <= 0 use package defaults (32 / 64).
func AttachChunks(tv *model.TaintedValue, n, minLen int) {
	if tv == nil || tv.Value == "" {
		return
	}
	tv.Chunks = ContiguousChunks(tv.Value, n, minLen)
}

// ContiguousChunks returns non-overlapping N-byte chunks of the chunkable
// body of value (PEM/PuTTY headers stripped when present). Returns nil when
// value is shorter than minLen or the body is shorter than n.
func ContiguousChunks(value string, n, minLen int) []model.TaintedVariant {
	if n <= 0 {
		n = defaultChunkMatchBytes
	}
	if minLen <= 0 {
		minLen = defaultChunkMatchMinLen
	}
	if len(value) < minLen {
		return nil
	}
	body := chunkableBody(value)
	if len(body) < n {
		return nil
	}
	form := chunkMatchForm(n)
	out := make([]model.TaintedVariant, 0, len(body)/n)
	for i := 0; i+n <= len(body); i += n {
		out = append(out, model.TaintedVariant{
			Form:  form,
			Value: body[i : i+n],
		})
	}
	return out
}

func chunkMatchForm(n int) string {
	return fmt.Sprintf("chunk_%d", n)
}

// chunkableBody returns the unique interior of PEM / PuTTY blocks, or the
// full value for ordinary secrets.
func chunkableBody(value string) string {
	if body, ok := pemInterior(value); ok {
		return body
	}
	if body, ok := puttyInterior(value); ok {
		return body
	}
	return value
}

// pemInterior extracts base64 body lines between the first BEGIN line and the
// last END line. Returns ok=false when the value is not PEM-shaped.
func pemInterior(value string) (string, bool) {
	begin := strings.Index(value, "-----BEGIN ")
	if begin < 0 {
		return "", false
	}
	// Find end of BEGIN line.
	nl := strings.IndexByte(value[begin:], '\n')
	if nl < 0 {
		return "", false
	}
	bodyStart := begin + nl + 1
	end := strings.LastIndex(value, "-----END ")
	if end < 0 || end <= bodyStart {
		return "", false
	}
	body := value[bodyStart:end]
	// Drop trailing newlines before END.
	body = strings.TrimRight(body, "\r\n")
	if body == "" {
		return "", false
	}
	return body, true
}

// puttyInterior skips the structural header of a PuTTY .ppk and returns the
// remainder (private lines + MAC). Conservative: everything after the first
// blank line, or after "Private-Lines:" content start if no blank line.
func puttyInterior(value string) (string, bool) {
	if !strings.HasPrefix(value, "PuTTY-User-Key-File-") {
		return "", false
	}
	// Prefer content after the first blank line (headers vs body).
	if i := strings.Index(value, "\n\n"); i >= 0 && i+2 < len(value) {
		body := value[i+2:]
		if body != "" {
			return body, true
		}
	}
	// Fallback: start at Private-Lines payload (skip the count line).
	const marker = "Private-Lines:"
	if i := strings.Index(value, marker); i >= 0 {
		rest := value[i+len(marker):]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 && nl+1 < len(rest) {
			return rest[nl+1:], true
		}
	}
	return "", false
}
