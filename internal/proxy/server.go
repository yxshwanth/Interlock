package proxy

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"syscall"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
)

// ServerProcess manages a single MCP server child process with piped stdio.
type ServerProcess struct {
	ID     string
	Cmd    *exec.Cmd
	Stdin  io.WriteCloser
	Stdout io.ReadCloser
	Stderr io.ReadCloser
	PID    int
}

// StartServer launches an MCP server as a child process, wiring its
// stdin/stdout/stderr as pipes for the proxy to interpose on.
func StartServer(ctx context.Context, cfg config.ServerConfig) (*ServerProcess, error) {
	cmd := exec.CommandContext(ctx, cfg.Command, cfg.Args...)
	// Isolate the child in its own process group so we can kill it cleanly.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("server %s: stdin pipe: %w", cfg.ID, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("server %s: stdout pipe: %w", cfg.ID, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("server %s: stderr pipe: %w", cfg.ID, err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("server %s: start: %w", cfg.ID, err)
	}

	return &ServerProcess{
		ID:     cfg.ID,
		Cmd:    cmd,
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		PID:    cmd.Process.Pid,
	}, nil
}

// Wait blocks until the server process exits and returns its error status.
func (s *ServerProcess) Wait() error {
	return s.Cmd.Wait()
}

// Stop gracefully shuts down the server: closes stdin (signals EOF to the
// child), sends SIGTERM, waits briefly, then SIGKILL if still alive.
func (s *ServerProcess) Stop() error {
	if s.Cmd.Process == nil {
		return nil
	}

	// Close stdin to signal the child that no more input is coming.
	s.Stdin.Close()

	// SIGTERM first.
	_ = s.Cmd.Process.Signal(syscall.SIGTERM)

	done := make(chan error, 1)
	go func() { done <- s.Cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		// Force kill after timeout.
		_ = s.Cmd.Process.Signal(syscall.SIGKILL)
		return <-done
	}
}
