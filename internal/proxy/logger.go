package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/yxshwanth/Interlock/internal/model"
)

// EventLogger writes InterceptedEvents to both a JSONL file and stderr.
type EventLogger struct {
	file *os.File
	enc  *json.Encoder
	mu   sync.Mutex
}

// NewEventLogger creates a logger that appends JSONL to the given path.
// Pass "" to disable file logging (stderr-only).
func NewEventLogger(path string) (*EventLogger, error) {
	l := &EventLogger{}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("opening log file %s: %w", path, err)
		}
		l.file = f
		l.enc = json.NewEncoder(f)
		l.enc.SetEscapeHTML(false)
	}
	return l, nil
}

// Log writes ev to stderr (human-readable) and to the JSONL file (if configured).
func (l *EventLogger) Log(ev model.InterceptedEvent) {
	logEventStderr(ev)

	if l.enc != nil {
		l.mu.Lock()
		l.enc.Encode(ev)
		l.mu.Unlock()
	}
}

// Close flushes and closes the JSONL file.
func (l *EventLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// logEventStderr writes a human-readable one-line summary to stderr.
func logEventStderr(ev model.InterceptedEvent) {
	arrow := "agent→server"
	detail := ev.Method
	if ev.Direction == model.ServerToAgent {
		arrow = "server→agent"
		if ev.Method == "" {
			if len(ev.Result) > 0 {
				detail = "result"
			} else {
				detail = "response"
			}
		}
	}
	if ev.ToolName != "" {
		detail = fmt.Sprintf("%s %s", ev.Method, ev.ToolName)
	}

	fmt.Fprintf(os.Stderr, "[interlock] #%d %s %s (session=%s, server=%s, pid=%d)\n",
		ev.Seq, arrow, detail, ev.SessionID, ev.ServerID, ev.ServerPID)
}
