package proxy

import (
	"bufio"
	"bytes"
	"io"
	"sync"
)

const maxFrameSize = 1 << 20 // 1 MB

// FrameReader reads newline-delimited JSON-RPC frames from a byte stream.
// It handles partial reads, multiple messages per read, and skips blank lines,
// per the MCP stdio transport specification.
type FrameReader struct {
	scanner *bufio.Scanner
}

// NewFrameReader wraps r in a buffered frame reader with a 1MB max line size.
func NewFrameReader(r io.Reader) *FrameReader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), maxFrameSize)
	return &FrameReader{scanner: s}
}

// ReadFrame returns the next non-blank line as a byte slice.
// Returns io.EOF when the underlying stream is closed.
func (fr *FrameReader) ReadFrame() ([]byte, error) {
	for fr.scanner.Scan() {
		line := fr.scanner.Bytes()
		trimmed := bytes.TrimRight(line, "\r")
		if len(bytes.TrimSpace(trimmed)) == 0 {
			continue
		}
		out := make([]byte, len(trimmed))
		copy(out, trimmed)
		return out, nil
	}
	if err := fr.scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

// FrameWriter writes newline-delimited JSON-RPC frames to a byte stream.
// It is safe for concurrent use.
type FrameWriter struct {
	w  io.Writer
	mu sync.Mutex
}

// NewFrameWriter wraps w in a thread-safe frame writer.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

// WriteFrame writes data followed by a newline. Thread-safe.
func (fw *FrameWriter) WriteFrame(data []byte) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	buf := make([]byte, len(data)+1)
	copy(buf, data)
	buf[len(data)] = '\n'

	_, err := fw.w.Write(buf)
	return err
}
