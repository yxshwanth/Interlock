// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"encoding/json"
	"fmt"

	"github.com/yxshwanth/Interlock/internal/model"
)

// resultStep builds a server->agent tools/call result step (IngestResult).
func resultStep(sessionID, toolName, serverID string, seq uint64, resultJSON string) Step {
	return Step{
		Kind: StepResult,
		Event: model.InterceptedEvent{
			SessionID: sessionID,
			Seq:       seq,
			Direction: model.ServerToAgent,
			Method:    "tools/call",
			ToolName:  toolName,
			ServerID:  serverID,
			Result:    json.RawMessage(resultJSON),
			Decision:  "forwarded",
		},
	}
}

// requestStep builds an agent->server tools/call request step (EvaluateRequest).
func requestStep(sessionID, toolName, serverID string, seq uint64, argsJSON string) Step {
	return Step{
		Kind: StepRequest,
		Event: model.InterceptedEvent{
			SessionID: sessionID,
			Seq:       seq,
			Direction: model.AgentToServer,
			Method:    "tools/call",
			ToolName:  toolName,
			ServerID:  serverID,
			ToolArgs:  json.RawMessage(argsJSON),
			Decision:  "pending",
		},
	}
}

// syscallStep builds a Variant B eBPF syscall step (IngestSyscall).
func syscallStep(sessionID, syscall, destIP string, destPort int, pid int, comm, path, payload string) Step {
	return Step{
		Kind: StepSyscall,
		Syscall: model.SyscallEvent{
			PID:            pid,
			Comm:           comm,
			Syscall:        syscall,
			DestIP:         destIP,
			DestPort:       destPort,
			Path:           path,
			PayloadExcerpt: payload,
			SessionID:      sessionID,
		},
	}
}

// resultJSON wraps text as an MCP tools/call result body.
func resultJSON(text string) string {
	b, _ := json.Marshal(map[string]any{
		"content": []map[string]string{{"type": "text", "text": text}},
	})
	return string(b)
}

// argsJSON builds a small tool-args JSON object from key/value pairs.
func argsJSON(kv map[string]string) string {
	b, _ := json.Marshal(kv)
	return string(b)
}

var seqCounter uint64

// nextSeq returns a fresh monotonic sequence number for building scenarios.
// Scenarios build their steps at package-init time in a single goroutine,
// so a package-level counter is safe and keeps scenario definitions terse.
func nextSeq() uint64 {
	seqCounter++
	return seqCounter
}

// sid generates a readable, unique session ID scoped to a scenario ID.
func sid(scenarioID string) string {
	return fmt.Sprintf("corpus:%s", scenarioID)
}
