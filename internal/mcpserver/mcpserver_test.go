package mcpserver

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestHandleToolsList(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	s := &Server{Name: "test", Version: "0.0.1", Tools: []ToolDef{{Name: "echo", Description: "echo"}}}
	s.handlers = map[string]ToolDef{"echo": s.Tools[0]}
	s.handleToolsList(json.RawMessage(`1`))

	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)

	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &resp); err != nil {
		t.Fatal(err)
	}
	result, _ := resp["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools=%v", tools)
	}
}

func TestHandleToolsCall(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	s := &Server{Name: "test", Version: "0.0.1"}
	s.handlers = map[string]ToolDef{
		"echo": {
			Name: "echo",
			Handler: func(args json.RawMessage) (string, error) {
				return string(args), nil
			},
		},
	}
	s.handleToolsCall(json.RawMessage(`2`), json.RawMessage(`{"name":"echo","arguments":{"x":1}}`))

	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), `\"x\":1`) {
		t.Fatalf("out=%s", out)
	}
}

func TestHandleToolsCall_UnknownTool(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	s := &Server{Name: "test", Version: "0.0.1", handlers: map[string]ToolDef{}}
	s.handleToolsCall(json.RawMessage(`3`), json.RawMessage(`{"name":"missing"}`))

	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == nil {
		t.Fatalf("expected error, got %s", out)
	}
}
