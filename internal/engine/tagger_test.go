package engine

import (
	"reflect"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
)

func newTestConfig() *config.Config {
	return &config.Config{
		Enforcement: "block",
		Servers: []config.ServerConfig{
			{ID: "tickets", Command: "./tickets", ProvidesTags: []string{"sensitive_source"}},
			{ID: "messenger", Command: "./messenger", ProvidesTags: []string{"external_sink"}},
			{ID: "bare", Command: "./bare"},
		},
		ToolTags: map[string][]string{
			"read_ticket":  {"sensitive_source"},
			"send_message": {"external_sink"},
			"http_post":    {"external_sink"},
		},
		UntrustedOrigins: struct {
			ToolResults bool `yaml:"tool_results"`
			WebFetches  bool `yaml:"web_fetches"`
		}{ToolResults: true, WebFetches: true},
	}
}

func TestTagger_PerToolOverrideWins(t *testing.T) {
	tagger := NewTagger(newTestConfig())

	// read_ticket has an explicit tool_tags entry -> should use that,
	// not the server's provides_tags (even though they happen to match).
	tags := tagger.TagsFor("read_ticket", "tickets")
	if !reflect.DeepEqual(tags, []string{"sensitive_source"}) {
		t.Fatalf("expected [sensitive_source], got %v", tags)
	}

	// send_message has a tool_tags entry even though it's on the messenger server.
	tags = tagger.TagsFor("send_message", "messenger")
	if !reflect.DeepEqual(tags, []string{"external_sink"}) {
		t.Fatalf("expected [external_sink], got %v", tags)
	}
}

func TestTagger_ServerFallback(t *testing.T) {
	cfg := newTestConfig()
	// Remove the per-tool override for read_ticket.
	delete(cfg.ToolTags, "read_ticket")
	tagger := NewTagger(cfg)

	// Should fall back to the tickets server's provides_tags.
	tags := tagger.TagsFor("read_ticket", "tickets")
	if !reflect.DeepEqual(tags, []string{"sensitive_source"}) {
		t.Fatalf("expected server fallback [sensitive_source], got %v", tags)
	}
}

func TestTagger_UnknownToolEmpty(t *testing.T) {
	tagger := NewTagger(newTestConfig())

	tags := tagger.TagsFor("nonexistent_tool", "bare")
	if len(tags) != 0 {
		t.Fatalf("expected empty tags for unknown tool on bare server, got %v", tags)
	}
}

func TestTagger_UnknownToolOnTaggedServer(t *testing.T) {
	tagger := NewTagger(newTestConfig())

	// A tool with no per-tool override on a tagged server gets server tags.
	tags := tagger.TagsFor("unknown_tool", "tickets")
	if !reflect.DeepEqual(tags, []string{"sensitive_source"}) {
		t.Fatalf("expected server fallback for unknown tool, got %v", tags)
	}
}

func TestTagger_IsSensitiveSource(t *testing.T) {
	tagger := NewTagger(newTestConfig())

	if !tagger.IsSensitiveSource("read_ticket", "tickets") {
		t.Fatal("read_ticket should be sensitive_source")
	}
	if tagger.IsSensitiveSource("send_message", "messenger") {
		t.Fatal("send_message should not be sensitive_source")
	}
	if tagger.IsSensitiveSource("unknown", "bare") {
		t.Fatal("unknown tool on bare server should not be sensitive_source")
	}
}

func TestTagger_IsExternalSink(t *testing.T) {
	tagger := NewTagger(newTestConfig())

	if !tagger.IsExternalSink("send_message", "messenger") {
		t.Fatal("send_message should be external_sink")
	}
	if !tagger.IsExternalSink("http_post", "messenger") {
		t.Fatal("http_post should be external_sink")
	}
	if tagger.IsExternalSink("read_ticket", "tickets") {
		t.Fatal("read_ticket should not be external_sink")
	}
}

func TestTagger_BothTagTypes(t *testing.T) {
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{ID: "multi", Command: "./multi", ProvidesTags: []string{"sensitive_source", "external_sink"}},
		},
		ToolTags: map[string][]string{},
	}
	tagger := NewTagger(cfg)

	if !tagger.IsSensitiveSource("any_tool", "multi") {
		t.Fatal("tool on multi-tagged server should be sensitive_source")
	}
	if !tagger.IsExternalSink("any_tool", "multi") {
		t.Fatal("tool on multi-tagged server should be external_sink")
	}
}

func TestTagger_PerToolOverrideShadowsServerTag(t *testing.T) {
	cfg := &config.Config{
		Servers: []config.ServerConfig{
			{ID: "tickets", Command: "./tickets", ProvidesTags: []string{"sensitive_source"}},
		},
		ToolTags: map[string][]string{
			"special_tool": {"external_sink"},
		},
	}
	tagger := NewTagger(cfg)

	// The tool-level override should shadow the server default entirely.
	if tagger.IsSensitiveSource("special_tool", "tickets") {
		t.Fatal("per-tool override should shadow server provides_tags")
	}
	if !tagger.IsExternalSink("special_tool", "tickets") {
		t.Fatal("per-tool override should provide external_sink")
	}
}
