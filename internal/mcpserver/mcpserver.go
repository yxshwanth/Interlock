// Package mcpserver provides a reusable MCP stdio server harness.
// It handles the JSON-RPC dispatch loop, initialize handshake, tools/list,
// tools/call routing, ping, and error responses so toy servers only need
// to register their tools and call Run().
package mcpserver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// ToolDef describes a tool the server exposes.
type ToolDef struct {
	Name        string
	Description string
	InputSchema json.RawMessage
	Handler     func(args json.RawMessage) (string, error)
}

// Server is a minimal MCP stdio server.
type Server struct {
	Name    string
	Version string
	Tools   []ToolDef

	handlers map[string]ToolDef
}

// Run reads JSON-RPC messages from stdin, dispatches them, and writes
// responses to stdout. It blocks until stdin is closed.
func (s *Server) Run() error {
	s.handlers = make(map[string]ToolDef, len(s.Tools))
	for _, t := range s.Tools {
		s.handlers[t.Name] = t
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)

	for scanner.Scan() {
		line := bytes.TrimRight(scanner.Bytes(), "\r")
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var msg struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id,omitempty"`
			Method  string          `json:"method,omitempty"`
			Params  json.RawMessage `json:"params,omitempty"`
		}
		if err := json.Unmarshal(line, &msg); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] invalid json: %v\n", s.Name, err)
			continue
		}

		// Notifications have no id and expect no response.
		if msg.Method != "" && len(msg.ID) == 0 {
			continue
		}

		switch msg.Method {
		case "initialize":
			s.sendResult(msg.ID, map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    s.Name,
					"version": s.Version,
				},
			})
		case "ping":
			s.sendResult(msg.ID, map[string]any{})
		case "tools/list":
			s.handleToolsList(msg.ID)
		case "tools/call":
			s.handleToolsCall(msg.ID, msg.Params)
		default:
			s.sendError(msg.ID, -32601, fmt.Sprintf("method not found: %s", msg.Method))
		}
	}
	return scanner.Err()
}

func (s *Server) handleToolsList(id json.RawMessage) {
	tools := make([]map[string]any, 0, len(s.Tools))
	for _, t := range s.Tools {
		td := map[string]any{
			"name":        t.Name,
			"description": t.Description,
		}
		if len(t.InputSchema) > 0 {
			var schema any
			json.Unmarshal(t.InputSchema, &schema)
			td["inputSchema"] = schema
		}
		tools = append(tools, td)
	}
	s.sendResult(id, map[string]any{"tools": tools})
}

func (s *Server) handleToolsCall(id json.RawMessage, params json.RawMessage) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		s.sendError(id, -32602, fmt.Sprintf("invalid params: %v", err))
		return
	}

	handler, ok := s.handlers[p.Name]
	if !ok {
		s.sendError(id, -32602, fmt.Sprintf("unknown tool: %s", p.Name))
		return
	}

	text, err := handler.Handler(p.Arguments)
	if err != nil {
		s.sendResult(id, map[string]any{
			"isError": true,
			"content": []map[string]any{
				{"type": "text", "text": err.Error()},
			},
		})
		return
	}

	s.sendResult(id, map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
	})
}

func (s *Server) sendResult(id json.RawMessage, result any) {
	s.writeMessage(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"result":  result,
	})
}

func (s *Server) sendError(id json.RawMessage, code int, message string) {
	s.writeMessage(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

func (s *Server) writeMessage(msg map[string]any) {
	data, err := json.Marshal(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] marshal error: %v\n", s.Name, err)
		return
	}
	data = append(data, '\n')
	os.Stdout.Write(data)
}
