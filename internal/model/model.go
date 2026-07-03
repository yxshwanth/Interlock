// Package model defines the shared data types used across Interlock.
// See docs/architecture.md §8 for the full specification.
package model

import (
	"encoding/json"
	"time"
)

// Direction indicates which way a JSON-RPC frame is traveling.
type Direction string

const (
	AgentToServer Direction = "agent_to_server"
	ServerToAgent Direction = "server_to_agent"
)

// InterceptedEvent is emitted for every JSON-RPC frame the proxy sees.
type InterceptedEvent struct {
	SessionID   string          `json:"session_id"`
	Seq         uint64          `json:"seq"`
	TSWall      time.Time       `json:"ts_wall"`
	TSMono      int64           `json:"ts_mono_ns"`
	Direction   Direction       `json:"direction"`
	Method      string          `json:"jsonrpc_method"`
	ToolName    string          `json:"tool_name,omitempty"`
	ToolArgs    json.RawMessage `json:"tool_args,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	ServerID    string          `json:"server_id"`
	ServerPID   int             `json:"server_pid"`
	Tags        []string        `json:"tags,omitempty"`
	Decision    string          `json:"decision"`
	BlockReason string          `json:"block_reason,omitempty"`
}

// JSONRPCMessage is the generic envelope for parsing any JSON-RPC 2.0 message.
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// IsRequest returns true if this message has a method and an id (a JSON-RPC request).
func (m *JSONRPCMessage) IsRequest() bool {
	return m.Method != "" && len(m.ID) > 0
}

// IsNotification returns true if this message has a method but no id.
func (m *JSONRPCMessage) IsNotification() bool {
	return m.Method != "" && len(m.ID) == 0
}

// IsResponse returns true if this message has no method (it's a response).
func (m *JSONRPCMessage) IsResponse() bool {
	return m.Method == ""
}

// ToolCallParams holds the parsed params for a "tools/call" request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ParseToolCallParams extracts tool name and arguments from a tools/call params blob.
func ParseToolCallParams(params json.RawMessage) (ToolCallParams, error) {
	var tc ToolCallParams
	if err := json.Unmarshal(params, &tc); err != nil {
		return tc, err
	}
	return tc, nil
}
