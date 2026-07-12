package bridge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

const (
	DefaultSocketPath = "/var/run/interlock/taint.sock"
	OpRegisterTaint   = "register_taint"
	maxLineBytes      = 256 * 1024
	maxValueBytes     = 64 * 1024
)

// VariantWire is a serializable encoding form for the bridge protocol.
type VariantWire struct {
	Form  string `json:"form"`
	Value string `json:"value"`
}

// RegisterTaintMsg is one NDJSON line on the Unix socket.
type RegisterTaintMsg struct {
	Op       string        `json:"op"`
	PodUID   string        `json:"pod_uid"`
	Source   string        `json:"source"`
	Seq      uint64        `json:"seq"`
	Hash     string        `json:"hash"`
	Preview  string        `json:"preview"`
	Value    string        `json:"value"`
	Variants []VariantWire `json:"variants"`
}

// Handler receives validated register_taint messages on the sensor.
type Handler func(msg RegisterTaintMsg) error

// Server listens on a Unix socket and dispatches NDJSON register_taint messages.
type Server struct {
	path    string
	handler Handler
	ln      net.Listener
	logf    func(string, ...any)

	mu       sync.Mutex
	closed   bool
	wg       sync.WaitGroup
}

// NewServer creates a bridge server. Call Listen then Serve.
func NewServer(socketPath string, handler Handler, logf func(string, ...any)) *Server {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Server{path: socketPath, handler: handler, logf: logf}
}

// Listen creates the socket directory and binds the Unix listener.
func (s *Server) Listen() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("bridge mkdir %s: %w", dir, err)
	}
	_ = os.Remove(s.path)
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("bridge listen %s: %w", s.path, err)
	}
	if err := os.Chmod(s.path, 0o660); err != nil {
		_ = ln.Close()
		return fmt.Errorf("bridge chmod %s: %w", s.path, err)
	}
	s.ln = ln
	s.logf("taint bridge listening on %s", s.path)
	return nil
}

// Serve accepts connections until Close. Safe to call once after Listen.
func (s *Server) Serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			s.logf("taint bridge accept: %v", err)
			continue
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c)
		}(conn)
	}
}

// Close stops accepting and waits for in-flight handlers.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	var err error
	if s.ln != nil {
		err = s.ln.Close()
	}
	s.wg.Wait()
	_ = os.Remove(s.path)
	return err
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReaderSize(conn, maxLineBytes)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				s.logf("taint bridge read: %v", err)
			}
			return
		}
		line = trimNL(line)
		if len(line) == 0 {
			continue
		}
		msg, err := parseRegisterLine(line)
		if err != nil {
			s.logf("taint bridge reject: %v", err)
			continue
		}
		if s.handler != nil {
			if herr := s.handler(msg); herr != nil {
				s.logf("taint bridge handler: %v", herr)
			}
		}
	}
}

func parseRegisterLine(line []byte) (RegisterTaintMsg, error) {
	var msg RegisterTaintMsg
	if err := json.Unmarshal(line, &msg); err != nil {
		return msg, fmt.Errorf("json: %w", err)
	}
	if msg.Op != OpRegisterTaint {
		return msg, fmt.Errorf("unknown op %q", msg.Op)
	}
	msg.PodUID = strings.TrimSpace(msg.PodUID)
	if msg.PodUID == "" {
		return msg, fmt.Errorf("empty pod_uid")
	}
	if msg.Value == "" || msg.Hash == "" {
		return msg, fmt.Errorf("missing value or hash")
	}
	if len(msg.Value) > maxValueBytes {
		return msg, fmt.Errorf("value too large (%d bytes)", len(msg.Value))
	}
	return msg, nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// ToTaintedValue converts a wire message into an in-memory TaintedValue.
func ToTaintedValue(msg RegisterTaintMsg) model.TaintedValue {
	variants := make([]model.TaintedVariant, 0, len(msg.Variants))
	for _, v := range msg.Variants {
		if v.Value == "" {
			continue
		}
		variants = append(variants, model.TaintedVariant{Form: v.Form, Value: v.Value})
	}
	return model.TaintedValue{
		Value:    msg.Value,
		Variants: variants,
		Hash:     msg.Hash,
		Preview:  msg.Preview,
		Source:   msg.Source,
		Seq:      msg.Seq,
	}
}

// Client dials the sensor Unix socket and sends register_taint messages.
type Client struct {
	path string
	mu   sync.Mutex
	conn net.Conn
}

// NewClient returns a client for socketPath (default DefaultSocketPath).
func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return &Client{path: socketPath}
}

// Close closes any open connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// Register sends one taint registration for podUID.
func (c *Client) Register(podUID string, tv model.TaintedValue) error {
	podUID = strings.TrimSpace(podUID)
	if podUID == "" {
		return fmt.Errorf("bridge: empty pod_uid")
	}
	if tv.Value == "" || tv.Hash == "" {
		return fmt.Errorf("bridge: missing value or hash")
	}
	msg := RegisterTaintMsg{
		Op:      OpRegisterTaint,
		PodUID:  podUID,
		Source:  tv.Source,
		Seq:     tv.Seq,
		Hash:    tv.Hash,
		Preview: tv.Preview,
		Value:   tv.Value,
	}
	for _, v := range tv.Variants {
		msg.Variants = append(msg.Variants, VariantWire{Form: v.Form, Value: v.Value})
	}
	line, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureConnLocked(); err != nil {
		return err
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.conn.Write(line); err != nil {
		_ = c.conn.Close()
		c.conn = nil
		if err2 := c.ensureConnLocked(); err2 != nil {
			return fmt.Errorf("bridge write: %w", err)
		}
		_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.conn.Write(line); err != nil {
			_ = c.conn.Close()
			c.conn = nil
			return fmt.Errorf("bridge write: %w", err)
		}
	}
	return nil
}

func (c *Client) ensureConnLocked() error {
	if c.conn != nil {
		return nil
	}
	conn, err := net.DialTimeout("unix", c.path, 2*time.Second)
	if err != nil {
		return fmt.Errorf("bridge dial %s: %w", c.path, err)
	}
	c.conn = conn
	return nil
}
