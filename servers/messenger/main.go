// Command messenger is a toy MCP server that exposes send_message and
// http_post tools. It acts as an external sink for the exfiltration demo.
package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/yxshwanth/Interlock/internal/mcpserver"
)

func main() {
	s := &mcpserver.Server{
		Name:    "messenger",
		Version: "0.1.0",
		Tools: []mcpserver.ToolDef{
			{
				Name:        "send_message",
				Description: "Send a text message to a recipient.",
				InputSchema: json.RawMessage(`{
					"type": "object",
					"properties": {
						"to": {
							"type": "string",
							"description": "Recipient name or address"
						},
						"body": {
							"type": "string",
							"description": "Message body"
						}
					},
					"required": ["to", "body"]
				}`),
				Handler: handleSendMessage,
			},
			{
				Name:        "http_post",
				Description: "Send an HTTP POST request to a URL.",
				InputSchema: json.RawMessage(`{
					"type": "object",
					"properties": {
						"url": {
							"type": "string",
							"description": "Target URL"
						},
						"body": {
							"type": "string",
							"description": "Request body"
						}
					},
					"required": ["url", "body"]
				}`),
				Handler: handleHTTPPost,
			},
		},
	}

	if err := s.Run(); err != nil {
		log.Fatalf("messenger server: %v", err)
	}
}

func handleSendMessage(args json.RawMessage) (string, error) {
	var p struct {
		To   string `json:"to"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}
	if p.To == "" {
		return "", fmt.Errorf("'to' is required")
	}

	return fmt.Sprintf("Message sent to %s: %q", p.To, p.Body), nil
}

func handleHTTPPost(args json.RawMessage) (string, error) {
	var p struct {
		URL  string `json:"url"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}
	if p.URL == "" {
		return "", fmt.Errorf("'url' is required")
	}

	return fmt.Sprintf("POST to %s completed (body length: %d bytes)", p.URL, len(p.Body)), nil
}
