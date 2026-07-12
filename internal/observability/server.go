package observability

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server serves /metrics and /healthz on a single listen address.
type Server struct {
	httpServer *http.Server
	ready      atomic.Bool
	ln         net.Listener
}

// Start begins serving metrics and health on listen. Empty listen is a no-op (returns nil).
// ready returns whether the process is healthy (e.g. eBPF sensor started).
func Start(listen, metricsPath, healthPath string, ready func() bool) (*Server, error) {
	if listen == "" {
		return nil, nil
	}
	if metricsPath == "" {
		metricsPath = "/metrics"
	}
	if healthPath == "" {
		healthPath = "/healthz"
	}
	if ready == nil {
		ready = func() bool { return true }
	}

	s := &Server{}
	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.Handler())
	mux.HandleFunc(healthPath, func(w http.ResponseWriter, r *http.Request) {
		if !ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("observability listen %s: %w", listen, err)
	}
	s.ln = ln
	s.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	SetUp(1)
	s.ready.Store(true)

	go func() {
		_ = s.httpServer.Serve(ln)
	}()
	return s, nil
}

// Addr returns the bound address (useful in tests).
func (s *Server) Addr() string {
	if s == nil || s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Close shuts down the HTTP server.
func (s *Server) Close() error {
	if s == nil || s.httpServer == nil {
		return nil
	}
	SetUp(0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}
