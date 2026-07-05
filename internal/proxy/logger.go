package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

type logJob struct {
	event *model.InterceptedEvent
	audit *model.SecurityAuditEvent
}

// EventLogger writes InterceptedEvents to both a JSONL file and stderr.
type EventLogger struct {
	file         *os.File
	enc          *json.Encoder
	mu           sync.Mutex
	backpressure string
	queue        chan logJob
	stats        *RuntimeStats
	done         chan struct{}
	wg           sync.WaitGroup
}

// NewEventLogger creates a logger that appends JSONL to the given path.
// Pass "" to disable file logging (stderr-only).
func NewEventLogger(path string, logCfg config.LoggingConfig, stats *RuntimeStats) (*EventLogger, error) {
	l := &EventLogger{
		backpressure: logCfg.Backpressure,
		stats:        stats,
	}
	if l.backpressure == "" {
		l.backpressure = "block"
	}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("opening log file %s: %w", path, err)
		}
		l.file = f
		l.enc = json.NewEncoder(f)
		l.enc.SetEscapeHTML(false)
	}
	if l.backpressure == "drop" && l.enc != nil {
		size := logCfg.QueueSize
		if size <= 0 {
			size = 256
		}
		l.queue = make(chan logJob, size)
		l.done = make(chan struct{})
		l.wg.Add(1)
		go l.writeLoop()
	}
	return l, nil
}

func (l *EventLogger) writeLoop() {
	defer l.wg.Done()
	for {
		select {
		case <-l.done:
			return
		case job := <-l.queue:
			l.writeJob(job)
		}
	}
}

func (l *EventLogger) writeJob(job logJob) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.enc == nil {
		return
	}
	if job.event != nil {
		_ = l.enc.Encode(job.event)
	}
	if job.audit != nil {
		_ = l.enc.Encode(job.audit)
	}
}

func (l *EventLogger) enqueue(job logJob) {
	select {
	case l.queue <- job:
	default:
		if l.stats != nil {
			l.stats.DroppedEvents.Add(1)
		}
	}
}

// Log writes ev to stderr (human-readable) and to the JSONL file (if configured).
func (l *EventLogger) Log(ev model.InterceptedEvent) {
	logEventStderr(ev)

	if l.enc == nil {
		return
	}
	if l.backpressure == "drop" && l.queue != nil {
		evCopy := ev
		l.enqueue(logJob{event: &evCopy})
		return
	}
	l.mu.Lock()
	l.enc.Encode(ev)
	l.mu.Unlock()
}

// Close flushes and closes the JSONL file.
func (l *EventLogger) Close() error {
	if l.done != nil {
		close(l.done)
		l.wg.Wait()
	}
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// EmitSecurityAudit appends a security audit record to events.jsonl and stderr.
func (l *EventLogger) EmitSecurityAudit(rec model.SecurityAuditEvent) error {
	fmt.Fprintf(os.Stderr,
		"[interlock] [SECURITY] audit %s: %s syscall=%s pid=%d comm=%q dest=%s:%d\n",
		rec.Kind, rec.Reason, rec.Syscall.Syscall, rec.Syscall.PID, rec.Syscall.Comm,
		rec.Syscall.DestIP, rec.Syscall.DestPort)

	if l.enc == nil {
		return nil
	}
	if l.backpressure == "drop" && l.queue != nil {
		recCopy := rec
		l.enqueue(logJob{audit: &recCopy})
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enc.Encode(rec)
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
