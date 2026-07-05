package mcphttp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// WriteSSE encodes a complete JSON-RPC response as a single SSE message stream.
// Inspect-then-forward: jsonBody must be fully formed before calling.
func WriteSSE(w http.ResponseWriter, jsonBody []byte) error {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("response writer does not support flushing")
	}

	for _, line := range bytes.Split(jsonBody, []byte("\n")) {
		if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

// WriteJSON writes a JSON-RPC response with application/json content type.
func WriteJSON(w http.ResponseWriter, status int, jsonBody []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(jsonBody)
}

// WriteJSONRPCError writes a JSON-RPC error with optional HTTP status.
func WriteJSONRPCError(w http.ResponseWriter, httpStatus int, code int, message string) {
	body := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","error":{"code":%d,"message":%q}}`, code, message))
	WriteJSON(w, httpStatus, body)
}

// ParseSSEResponse reads an SSE stream and returns concatenated data payload bytes.
func ParseSSEResponse(r io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)

	var parts []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "data: ") {
			parts = append(parts, strings.TrimPrefix(line, "data: "))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return []byte(strings.Join(parts, "\n")), nil
}

// WriteResponse chooses JSON or SSE encoding per inspect-then-forward rules.
func WriteResponse(w http.ResponseWriter, jsonBody []byte, useSSE bool, blocked bool) error {
	if blocked || !useSSE {
		WriteJSON(w, http.StatusOK, jsonBody)
		return nil
	}
	return WriteSSE(w, jsonBody)
}
