package mcphttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a minimal Streamable HTTP MCP client (2025-11-25).
type Client struct {
	BaseURL         string
	ProtocolVersion string
	HTTP            *http.Client
	sessionID       string
	nextID          int
}

// NewClient creates an HTTP MCP client targeting baseURL (e.g. http://127.0.0.1:8080/mcp).
func NewClient(baseURL, protocolVersion string) *Client {
	return &Client{
		BaseURL:         strings.TrimRight(baseURL, "/"),
		ProtocolVersion: protocolVersion,
		HTTP:            http.DefaultClient,
	}
}

// SessionID returns the MCP session id after initialize.
func (c *Client) SessionID() string {
	return c.sessionID
}

// CallResult is the outcome of a timed MCP call.
type CallResult struct {
	Body     json.RawMessage
	Duration time.Duration
}

// Call sends a JSON-RPC request and returns the response body (JSON or parsed from SSE).
func (c *Client) Call(method string, params any, mcpName string) (json.RawMessage, error) {
	res, err := c.CallDuration(method, params, mcpName)
	return res.Body, err
}

// CallDuration sends a JSON-RPC request and returns the response body and wall-clock latency.
func (c *Client) CallDuration(method string, params any, mcpName string) (CallResult, error) {
	c.nextID++
	id := c.nextID
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		body["params"] = params
	}
	data, err := json.Marshal(body)
	if err != nil {
		return CallResult{}, err
	}
	return c.postDuration(data, method, mcpName)
}

// Notify sends a JSON-RPC notification (202 Accepted, no body).
func (c *Client) Notify(method string) error {
	body := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, err = c.postDuration(data, method, "")
	return err
}

func (c *Client) postDuration(data []byte, method, mcpName string) (CallResult, error) {
	start := time.Now()
	req, err := http.NewRequest(http.MethodPost, c.BaseURL, bytes.NewReader(data))
	if err != nil {
		return CallResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(HeaderProtocolVersion, c.ProtocolVersion)
	if method != "" {
		req.Header.Set(HeaderMcpMethod, method)
	}
	if mcpName != "" {
		req.Header.Set(HeaderMcpName, mcpName)
	}
	if c.sessionID != "" {
		req.Header.Set(HeaderSessionID, c.sessionID)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return CallResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		return CallResult{Duration: time.Since(start)}, nil
	}
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return CallResult{Duration: time.Since(start)}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}

	if sid := resp.Header.Get(HeaderSessionID); sid != "" {
		c.sessionID = sid
	}

	ct := resp.Header.Get("Content-Type")
	body, err := io.ReadAll(resp.Body)
	dur := time.Since(start)
	if err != nil {
		return CallResult{Duration: dur}, err
	}

	if strings.Contains(ct, "text/event-stream") {
		parsed, err := ParseSSEResponse(bytes.NewReader(body))
		if err != nil {
			return CallResult{Duration: dur}, err
		}
		return CallResult{Body: json.RawMessage(parsed), Duration: dur}, nil
	}
	return CallResult{Body: json.RawMessage(body), Duration: dur}, nil
}
