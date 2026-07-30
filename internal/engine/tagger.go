package engine

import (
	"github.com/yxshwanth/Interlock/internal/config"
)

// Tagger resolves tool tags from two sources:
//  1. Per-tool overrides (tool_tags in config) — authoritative for TagsFor.
//  2. Server-level defaults (provides_tags on the server config) — fallback.
//
// When server_defaults.inherit_sink_suspicion is on, IsExternalSink also
// treats tools on sensitive_source servers as sinks unless allowlisted
// (ROADMAP §14). Empty per-tool overrides (tool_tags: {name: []}) do not
// exempt — sink_suspicion_allowlist is the sole escape hatch.
type Tagger struct {
	toolTags             map[string][]string // tool name -> tags (from config.ToolTags)
	serverTags           map[string][]string // server ID -> provides_tags
	inheritSinkSuspicion bool
	sinkAllowlist        map[string]bool
}

// NewTagger builds a Tagger from the loaded config.
func NewTagger(cfg *config.Config) *Tagger {
	t := &Tagger{
		toolTags:             make(map[string][]string),
		serverTags:           make(map[string][]string),
		inheritSinkSuspicion: cfg != nil && cfg.ServerDefaults.InheritSinkSuspicion,
		sinkAllowlist:        make(map[string]bool),
	}

	if cfg == nil {
		return t
	}

	for tool, tags := range cfg.ToolTags {
		t.toolTags[tool] = tags
	}

	for _, sc := range cfg.Servers {
		if len(sc.ProvidesTags) > 0 {
			t.serverTags[sc.ID] = sc.ProvidesTags
		}
	}

	for _, name := range cfg.ServerDefaults.SinkSuspicionAllowlist {
		if name != "" {
			t.sinkAllowlist[name] = true
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

// IsExternalSink returns true if the tool carries the "external_sink" tag,
// or (when inherit_sink_suspicion is on) the tool runs on a sensitive_source
// server and is not on the allowlist — even if an empty tool_tags override
// shadowed server provides_tags for TagsFor.
func (t *Tagger) IsExternalSink(toolName, serverID string) bool {
	if hasTag(t.TagsFor(toolName, serverID), "external_sink") {
		return true
	}
	if !t.inheritSinkSuspicion {
		return false
	}
	if t.sinkAllowlist[toolName] {
		return false
	}
	return t.serverIsSensitiveSource(serverID)
}

func (t *Tagger) serverIsSensitiveSource(serverID string) bool {
	return hasTag(t.serverTags[serverID], "sensitive_source")
}

// HasSensitiveSource returns true if any tool or server is tagged sensitive_source.
func (t *Tagger) HasSensitiveSource() bool {
	return t.hasAnyTag("sensitive_source")
}

// HasExternalSink returns true if any tool or server is tagged external_sink,
// or inherit would make a sensitive_source server a sink host.
func (t *Tagger) HasExternalSink() bool {
	if t.hasAnyTag("external_sink") {
		return true
	}
	if t.inheritSinkSuspicion {
		for id := range t.serverTags {
			if t.serverIsSensitiveSource(id) {
				return true
			}
		}
	}
	return false
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
