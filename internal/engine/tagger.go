package engine

import (
	"github.com/yxshwanth/Interlock/internal/config"
)

// Tagger resolves tool tags from two sources:
//  1. Per-tool overrides (tool_tags in config) — authoritative.
//  2. Server-level defaults (provides_tags on the server config) — fallback.
type Tagger struct {
	toolTags   map[string][]string // tool name -> tags (from config.ToolTags)
	serverTags map[string][]string // server ID -> provides_tags
}

// NewTagger builds a Tagger from the loaded config.
func NewTagger(cfg *config.Config) *Tagger {
	t := &Tagger{
		toolTags:   make(map[string][]string),
		serverTags: make(map[string][]string),
	}

	for tool, tags := range cfg.ToolTags {
		t.toolTags[tool] = tags
	}

	for _, sc := range cfg.Servers {
		if len(sc.ProvidesTags) > 0 {
			t.serverTags[sc.ID] = sc.ProvidesTags
		}
	}

	return t
}

// TagsFor returns the tags for a tool. Per-tool overrides take priority;
// if none exist, the server's provides_tags are used as a fallback.
func (t *Tagger) TagsFor(toolName, serverID string) []string {
	if tags, ok := t.toolTags[toolName]; ok {
		return tags
	}
	if tags, ok := t.serverTags[serverID]; ok {
		return tags
	}
	return nil
}

// IsSensitiveSource returns true if the tool carries the "sensitive_source" tag.
func (t *Tagger) IsSensitiveSource(toolName, serverID string) bool {
	return hasTag(t.TagsFor(toolName, serverID), "sensitive_source")
}

// IsExternalSink returns true if the tool carries the "external_sink" tag.
func (t *Tagger) IsExternalSink(toolName, serverID string) bool {
	return hasTag(t.TagsFor(toolName, serverID), "external_sink")
}

// HasSensitiveSource returns true if any tool or server is tagged sensitive_source.
func (t *Tagger) HasSensitiveSource() bool {
	return t.hasAnyTag("sensitive_source")
}

// HasExternalSink returns true if any tool or server is tagged external_sink.
func (t *Tagger) HasExternalSink() bool {
	return t.hasAnyTag("external_sink")
}

func (t *Tagger) hasAnyTag(target string) bool {
	for _, tags := range t.toolTags {
		if hasTag(tags, target) {
			return true
		}
	}
	for _, tags := range t.serverTags {
		if hasTag(tags, target) {
			return true
		}
	}
	return false
}

func hasTag(tags []string, target string) bool {
	for _, tag := range tags {
		if tag == target {
			return true
		}
	}
	return false
}
