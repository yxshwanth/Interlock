package engine

import (
	"encoding/json"
	"strings"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

// VaultSecretClassExtracted is the v1 class for everything ExtractTaintedValues registers.
const VaultSecretClassExtracted = "extracted"

// VaultDummy returns a stable inert token for a secret value.
// Format: ilk.vault.<16 hex of SHA-256> — dots break secretPatterns' alnum
// captures so a rewritten "auth token: …" line cannot re-taint the dummy.
func VaultDummy(secret string) string {
	h := HashValue(secret)
	if len(h) > 16 {
		h = h[:16]
	}
	return "ilk.vault." + h
}

func (e *Engine) vaultMint(state *model.SessionState, values []model.TaintedValue) {
	if !e.vaultEnabled || len(values) == 0 {
		return
	}
	if state.Vault == nil {
		state.Vault = make(map[string]model.VaultEntry)
	}
	for _, tv := range values {
		if tv.Value == "" {
			continue
		}
		dummy := VaultDummy(tv.Value)
		state.Vault[dummy] = model.VaultEntry{
			Real:  tv.Value,
			Class: VaultSecretClassExtracted,
		}
	}
}

// VaultEnabled reports whether token vaulting is on.
func (e *Engine) VaultEnabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.vaultEnabled
}

// VaultRewriteFrame replaces vaulted secrets in a JSON-RPC frame with dummies.
// Returns the original frame unchanged when vault is off or no mappings apply.
func (e *Engine) VaultRewriteFrame(sessionID string, frame []byte) []byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.vaultEnabled || sessionID == "" || len(frame) == 0 {
		return frame
	}
	state := e.store.Get(sessionID)
	if state == nil || len(state.Vault) == 0 {
		return frame
	}
	return vaultReplaceReals(frame, state.Vault)
}

// vaultReplaceReals substitutes real secrets (and their registered variants that
// appear in the blob) with dummies. Longest-first would be ideal; for v1 we
// replace each vaulted real value, then any tainted variant equal to that real's
// encodings is already covered by replacing the literal real in result text.
func vaultReplaceReals(raw []byte, vault map[string]model.VaultEntry) []byte {
	s := string(raw)
	changed := false
	for dummy, entry := range vault {
		if entry.Real == "" || !strings.Contains(s, entry.Real) {
			continue
		}
		s = strings.ReplaceAll(s, entry.Real, dummy)
		changed = true
	}
	if !changed {
		return raw
	}
	return []byte(s)
}

func vaultDetokenize(raw json.RawMessage, vault map[string]model.VaultEntry, allowClass func(string) bool) json.RawMessage {
	if len(raw) == 0 || len(vault) == 0 {
		return raw
	}
	s := string(raw)
	changed := false
	for dummy, entry := range vault {
		if !allowClass(entry.Class) {
			continue
		}
		if dummy == "" || !strings.Contains(s, dummy) {
			continue
		}
		s = strings.ReplaceAll(s, dummy, entry.Real)
		changed = true
	}
	if !changed {
		return raw
	}
	return json.RawMessage(s)
}

func (e *Engine) vaultToolAuthorized(tool string) (ok bool, allowClass func(string) bool) {
	for _, a := range e.vaultAuthorize {
		if a.Tool != tool {
			continue
		}
		classes := a.SecretClasses
		return true, func(class string) bool {
			if len(classes) == 0 {
				return class == VaultSecretClassExtracted
			}
			for _, c := range classes {
				if c == "*" || c == class {
					return true
				}
			}
			return false
		}
	}
	return false, nil
}

// applyVaultAuthorize copies authorize entries from config (nil-safe).
func applyVaultAuthorize(entries []config.VaultAuthorizeEntry) []config.VaultAuthorizeEntry {
	if len(entries) == 0 {
		return nil
	}
	out := make([]config.VaultAuthorizeEntry, len(entries))
	copy(out, entries)
	return out
}
