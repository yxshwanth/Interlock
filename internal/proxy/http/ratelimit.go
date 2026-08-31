package mcphttp

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type ipRateLimiter struct {
	mu      sync.Mutex
	limit   float64
	clients map[string]*rateClient
}

type rateClient struct {
	tokens   float64
	lastSeen time.Time
}

func newIPRateLimiter(rps float64) *ipRateLimiter {
	if rps <= 0 {
		return nil
	}
	return &ipRateLimiter{
		limit:   rps,
		clients: make(map[string]*rateClient),
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	if l == nil {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.clients[ip]
	if !ok {
		l.clients[ip] = &rateClient{tokens: l.limit - 1, lastSeen: now}
		return true
	}
	elapsed := now.Sub(c.lastSeen).Seconds()
	c.tokens += elapsed * l.limit
	if c.tokens > l.limit {
		c.tokens = l.limit
	}
	c.lastSeen = now
	if c.tokens < 1 {
		return false
	}
	c.tokens--
	return true
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		return host[:i]
	}
	return host
}

func validateBearer(r *http.Request, want string) bool {
	if want == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	return strings.TrimSpace(auth[len(prefix):]) == want
}
