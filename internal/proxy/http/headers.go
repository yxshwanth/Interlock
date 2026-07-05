package mcphttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/yxshwanth/Interlock/internal/model"
)

const (
	HeaderProtocolVersion = "MCP-Protocol-Version"
	HeaderSessionID       = "Mcp-Session-Id"
	HeaderMcpMethod       = "Mcp-Method"
	HeaderMcpName         = "Mcp-Name"
)

// RequestMeta holds parsed HTTP headers for logging (secrets redacted).
type RequestMeta struct {
	ProtocolVersion string `json:"protocol_version,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	McpMethod       string `json:"mcp_method,omitempty"`
	McpName         string `json:"mcp_name,omitempty"`
	Authorization   string `json:"authorization,omitempty"` // redacted
	Cookie          string `json:"cookie,omitempty"`        // redacted
}

// ParseRequestMeta extracts MCP HTTP headers from the request.
func ParseRequestMeta(r *http.Request) RequestMeta {
	return RequestMeta{
		ProtocolVersion: r.Header.Get(HeaderProtocolVersion),
		SessionID:       r.Header.Get(HeaderSessionID),
		McpMethod:       r.Header.Get(HeaderMcpMethod),
		McpName:         r.Header.Get(HeaderMcpName),
		Authorization:   RedactCredential(r.Header.Get("Authorization")),
		Cookie:          RedactCredential(r.Header.Get("Cookie")),
	}
}

// RedactCredential masks secret header values for logs.
func RedactCredential(v string) string {
	if v == "" {
		return ""
	}
	if len(v) <= 8 {
		return "[REDACTED]"
	}
	return v[:4] + "…[REDACTED]"
}

// ValidateAccept ensures the client accepts JSON and SSE responses.
func ValidateAccept(r *http.Request) error {
	accept := r.Header.Get("Accept")
	if accept == "" {
		return fmt.Errorf("missing Accept header")
	}
	if !strings.Contains(accept, "application/json") || !strings.Contains(accept, "text/event-stream") {
		return fmt.Errorf("Accept must include application/json and text/event-stream")
	}
	return nil
}

// ValidateOrigin rejects invalid Origin headers (DNS rebinding mitigation).
func ValidateOrigin(r *http.Request, allowedHosts []string) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	for _, h := range allowedHosts {
		if strings.Contains(origin, h) {
			return nil
		}
	}
	return fmt.Errorf("invalid Origin: %s", origin)
}

// ValidateProtocolVersion checks MCP-Protocol-Version against config default.
func ValidateProtocolVersion(got, want string) error {
	if got == "" {
		return fmt.Errorf("missing %s header", HeaderProtocolVersion)
	}
	if want != "" && got != want {
		return fmt.Errorf("%s mismatch: got %q want %q", HeaderProtocolVersion, got, want)
	}
	return nil
}

// ValidateHeaderBodyMatch ensures Mcp-Method / Mcp-Name match the JSON-RPC body (SEP-2243 baseline).
func ValidateHeaderBodyMatch(meta RequestMeta, body []byte) error {
	var msg model.JSONRPCMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}

	if meta.McpMethod != "" && msg.Method != "" && meta.McpMethod != msg.Method {
		return fmt.Errorf("Mcp-Method header %q does not match body method %q", meta.McpMethod, msg.Method)
	}

	if meta.McpName == "" || msg.Method != "tools/call" {
		return nil
	}

	tc, err := model.ParseToolCallParams(msg.Params)
	if err != nil {
		return nil
	}
	if tc.Name != "" && meta.McpName != tc.Name {
		return fmt.Errorf("Mcp-Name header %q does not match body tool %q", meta.McpName, tc.Name)
	}
	return nil
}

// RequireSession returns an error if a non-initialize request lacks Mcp-Session-Id.
func RequireSession(meta RequestMeta, body []byte) error {
	var msg model.JSONRPCMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return err
	}
	if msg.Method == "initialize" || msg.IsNotification() {
		return nil
	}
	if meta.SessionID == "" {
		return fmt.Errorf("missing %s header", HeaderSessionID)
	}
	return nil
}
