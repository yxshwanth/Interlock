package proxy

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestFrameReaderSingleMessage(t *testing.T) {
	input := `{"jsonrpc":"2.0","method":"ping"}` + "\n"
	fr := NewFrameReader(strings.NewReader(input))

	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(frame) != `{"jsonrpc":"2.0","method":"ping"}` {
		t.Errorf("got %q", string(frame))
	}

	_, err = fr.ReadFrame()
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestFrameReaderMultipleMessages(t *testing.T) {
	input := `{"method":"a"}` + "\n" + `{"method":"b"}` + "\n" + `{"method":"c"}` + "\n"
	fr := NewFrameReader(strings.NewReader(input))

	for _, want := range []string{`{"method":"a"}`, `{"method":"b"}`, `{"method":"c"}`} {
		frame, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(frame) != want {
			t.Errorf("got %q, want %q", string(frame), want)
		}
	}

	_, err := fr.ReadFrame()
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestFrameReaderSkipsBlankLines(t *testing.T) {
	input := "\n\n" + `{"method":"a"}` + "\n" + "\n" + `{"method":"b"}` + "\n" + "\n"
	fr := NewFrameReader(strings.NewReader(input))

	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(frame) != `{"method":"a"}` {
		t.Errorf("got %q", string(frame))
	}

	frame, err = fr.ReadFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(frame) != `{"method":"b"}` {
		t.Errorf("got %q", string(frame))
	}
}

func TestFrameReaderCRLF(t *testing.T) {
	input := `{"method":"a"}` + "\r\n" + `{"method":"b"}` + "\r\n"
	fr := NewFrameReader(strings.NewReader(input))

	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(frame) != `{"method":"a"}` {
		t.Errorf("got %q, want without \\r", string(frame))
	}

	frame, err = fr.ReadFrame()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(frame) != `{"method":"b"}` {
		t.Errorf("got %q", string(frame))
	}
}

func TestFrameReaderPartialReads(t *testing.T) {
	// Simulate a slow writer that sends a message in chunks
	pr, pw := io.Pipe()
	fr := NewFrameReader(pr)

	done := make(chan struct{})
	var got string
	var readErr error

	go func() {
		defer close(done)
		var frame []byte
		frame, readErr = fr.ReadFrame()
		if readErr == nil {
			got = string(frame)
		}
	}()

	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_ticket"}}`
	// Write in three chunks with delays
	chunks := []string{msg[:20], msg[20:50], msg[50:] + "\n"}
	for _, chunk := range chunks {
		time.Sleep(5 * time.Millisecond)
		if _, err := pw.Write([]byte(chunk)); err != nil {
			t.Fatalf("write chunk: %v", err)
		}
	}
	pw.Close()

	<-done
	if readErr != nil {
		t.Fatalf("unexpected error: %v", readErr)
	}
	if got != msg {
		t.Errorf("got %q, want %q", got, msg)
	}
}

func TestFrameReaderEOFOnClose(t *testing.T) {
	pr, pw := io.Pipe()
	fr := NewFrameReader(pr)
	pw.Close()

	_, err := fr.ReadFrame()
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestFrameWriterSingle(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)

	if err := fw.WriteFrame([]byte(`{"method":"ping"}`)); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "{\"method\":\"ping\"}\n" {
		t.Errorf("got %q", buf.String())
	}
}

func TestFrameWriterRejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)
	huge := make([]byte, maxFrameSize+1)
	if err := fw.WriteFrame(huge); err == nil {
		t.Fatal("expected error for oversized frame")
	}
	if buf.Len() != 0 {
		t.Fatalf("wrote %d bytes on reject", buf.Len())
	}
}

func TestFrameWriterMultiple(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)

	fw.WriteFrame([]byte(`{"a":1}`))
	fw.WriteFrame([]byte(`{"b":2}`))

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	if lines[0] != `{"a":1}` {
		t.Errorf("line 0 = %q", lines[0])
	}
	if lines[1] != `{"b":2}` {
		t.Errorf("line 1 = %q", lines[1])
	}
}

func TestFrameWriterConcurrent(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)

	const n = 100
	done := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			fw.WriteFrame([]byte(`{"ok":true}`))
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != n {
		t.Errorf("got %d lines, want %d", len(lines), n)
	}
}
