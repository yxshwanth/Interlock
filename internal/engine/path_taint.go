package engine

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

var sensitiveExtensions = []string{
	".p12", ".pfx", ".kdbx", ".xlsx", ".xlsm", ".xls",
	".pem", ".key", ".crt", ".cer", ".jks",
}

var sensitiveBasenameSubstrings = []string{
	"credentials", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
	"secrets", "kubeconfig", ".aws", "service-account",
}

var pathArgKeys = map[string]bool{
	"path": true, "file": true, "filepath": true, "file_path": true,
	"excel_file": true, "filename": true, "source": true, "target": true,
}

// IsSensitiveResourcePath reports whether path matches configured prefixes
// or built-in extension/name heuristics for credential containers.
func IsSensitiveResourcePath(path string, prefixes []string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	lower := strings.ToLower(path)
	base := strings.ToLower(filepath.Base(path))
	for _, ext := range sensitiveExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	for _, sub := range sensitiveBasenameSubstrings {
		if strings.Contains(base, sub) {
			return true
		}
	}
	return false
}

// ExtractPathsFromToolArgs walks JSON tool arguments for path-like string values.
func ExtractPathsFromToolArgs(args json.RawMessage) []string {
	if len(args) == 0 {
		return nil
	}
	var root any
	if err := json.Unmarshal(args, &root); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	collectPaths(root, "", seen, &out)
	return out
}

func collectPaths(v any, key string, seen map[string]bool, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			collectPaths(child, k, seen, out)
		}
	case []any:
		for _, child := range t {
			collectPaths(child, key, seen, out)
		}
	case string:
		if !looksLikePathValue(key, t) {
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
		*out = append(*out, t)
	}
}

func looksLikePathValue(key, val string) bool {
	val = strings.TrimSpace(val)
	if val == "" {
		return false
	}
	if pathArgKeys[strings.ToLower(key)] {
		return true
	}
	if strings.HasPrefix(val, "/") || strings.Contains(val, "/") {
		return strings.Contains(val, ".") || strings.Contains(strings.ToLower(val), "credential")
	}
	return false
}

// TaintPathDrivenContent registers the entire content blob as tainted when a
// sensitive resource path was read. Used when secretPatterns find nothing.
func TaintPathDrivenContent(content, path, source string, seq uint64) []model.TaintedValue {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}
	now := time.Now().UnixNano()
	return []model.TaintedValue{{
		Value:        content,
		Variants:     CanonicalEncodings(content),
		Hash:         HashValue(content),
		Preview:      MaskValue(content),
		Source:       source + " (path:" + path + ")",
		Seq:          seq,
		RegisteredAt: now,
	}}
}

func pendingReadPathKey(serverID, toolName string) string {
	return serverID + "/" + toolName
}

func (e *Engine) stashSensitiveReadPath(state *model.SessionState, ev model.InterceptedEvent) {
	if e.tagger == nil || !e.tagger.IsSensitiveSource(ev.ToolName, ev.ServerID) {
		return
	}
	for _, p := range ExtractPathsFromToolArgs(ev.ToolArgs) {
		if IsSensitiveResourcePath(p, e.sensitivePaths) {
			if state.PendingSensitiveReadPaths == nil {
				state.PendingSensitiveReadPaths = make(map[string]string)
			}
			state.PendingSensitiveReadPaths[pendingReadPathKey(ev.ServerID, ev.ToolName)] = p
			return
		}
	}
}

func consumePendingSensitiveReadPath(state *model.SessionState, serverID, toolName string) string {
	if state.PendingSensitiveReadPaths == nil {
		return ""
	}
	key := pendingReadPathKey(serverID, toolName)
	p := state.PendingSensitiveReadPaths[key]
	delete(state.PendingSensitiveReadPaths, key)
	return p
}

// taintFromContainer runs bounded container descent on content and extracts
// secretPatterns from interior text only (FP-safe: does not whole-blob-taint
// every cell). Logs aborts; never promotes abort to EXFIL.
func (e *Engine) taintFromContainer(content, source string, seq uint64) []model.TaintedValue {
	if !e.containerLimits.Enabled {
		return nil
	}
	raw := unwrapContainerBlob([]byte(content))
	if raw == nil {
		return nil
	}
	res := InspectContainer(raw, e.containerLimits)
	if res.Abort != ContainerAbortNone {
		e.log.Printf("container inspect abort=%s source=%s parts=%d bytes=%d",
			res.Abort, source, res.PartsN, res.Bytes)
		return nil
	}
	if len(res.Parts) == 0 {
		return nil
	}
	joined := JoinContainerParts(res.Parts)
	vals := ExtractTaintedValues(joined, source+" (container)", seq)
	return vals
}
