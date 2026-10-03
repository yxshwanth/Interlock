package corpus

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

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

// syscallSensorStep builds a sensor-only (v0.3 Phase 1) syscall step
// (IngestSyscallSensor). fileContents seeds taint on openat; leave empty
// for non-sensitive file reads or non-openat syscalls.
func syscallSensorStep(sessionID, syscall, destIP string, destPort int, pid int, comm, path, payload, fileContents string) Step {
	return Step{
		Kind: StepSyscallSensor,
		Syscall: model.SyscallEvent{
			PID:            pid,
			Comm:           comm,
			Syscall:        syscall,
			DestIP:         destIP,
			DestPort:       destPort,
			Path:           path,
			PayloadExcerpt: payload,
			SessionID:      sessionID,
			FileContents:   fileContents,
		},
	}
}

// advanceTimeStep rewinds LitAt on lit legs for sessionID by d so the next
// engine call observes trifecta.leg_ttl expiry (default 30m).
func advanceTimeStep(sessionID string, d time.Duration) Step {
	return Step{
		Kind:      StepAdvanceTime,
		SessionID: sessionID,
		AdvanceBy: d,
	}
}

// resultJSON wraps text as an MCP tools/call result body.
func resultJSON(text string) string {
	b, _ := json.Marshal(map[string]any{
		"content": []map[string]string{{"type": "text", "text": text}},
	})
	return string(b)
}

// nestedLargeTicketResult builds a large, deeply nested MCP result envelope
// with the ticket text in content[].text (so extractResultText still finds
// secrets) plus bulky nested metadata that production tools often return.
func nestedLargeTicketResult(ticketText string) string {
	meta := map[string]any{}
	for i := 0; i < 40; i++ {
		meta["field_"+strconv.Itoa(i)] = map[string]any{
			"label":  "nested-label-" + strconv.Itoa(i),
			"values": []string{"a", "b", "c", "padding-" + strconv.Itoa(i)},
			"child": map[string]any{
				"depth2": map[string]any{
					"depth3": "leaf-" + strconv.Itoa(i),
				},
			},
		}
	}
	b, _ := json.Marshal(map[string]any{
		"content": []map[string]string{
			{"type": "text", "text": ticketText},
			{"type": "text", "text": "Related notes: see metadata for audit trail."},
		},
		"isError":  false,
		"metadata": meta,
		"_meta": map[string]any{
			"progressToken": "tok-large-result",
			"annotations": map[string]any{
				"audience": []string{"user", "assistant"},
				"priority": 0.5,
			},
		},
	})
	return string(b)
}

// nestedResultWithBuriedSecretShaped puts a secret-shaped string only in
// nested metadata, while content[].text is benign. extractResultText should
// return only the content text and not register taint from the buried value.
func nestedResultWithBuriedSecretShaped(buried string) string {
	b, _ := json.Marshal(map[string]any{
		"content": []map[string]string{
			{"type": "text", "text": "Ticket T-2201: UI polish only. No credentials in this ticket body."},
		},
		"metadata": map[string]any{
			"debug": map[string]any{
				"raw_snapshot": map[string]any{
					"maybe_token": buried,
					"padding":     strings.Repeat("x", 2048),
				},
			},
		},
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
