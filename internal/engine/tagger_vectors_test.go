// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
)

type taggerVectorConfig struct {
	ToolTags               map[string][]string  `json:"tool_tags"`
	Servers                []taggerVectorServer `json:"servers"`
	InheritSinkSuspicion   bool                 `json:"inherit_sink_suspicion"`
	SinkSuspicionAllowlist []string             `json:"sink_suspicion_allowlist"`
}

type taggerVectorServer struct {
	ID           string   `json:"id"`
	ProvidesTags []string `json:"provides_tags"`
}

type taggerVectorQuery struct {
	Tool            string   `json:"tool"`
	Server          string   `json:"server"`
	Tags            []string `json:"tags"`
	SensitiveSource bool     `json:"sensitive_source"`
	ExternalSink    bool     `json:"external_sink"`
}

type taggerVector struct {
	Name               string              `json:"name"`
	Config             taggerVectorConfig  `json:"config"`
	Queries            []taggerVectorQuery `json:"queries"`
	HasSensitiveSource bool                `json:"has_sensitive_source"`
	HasExternalSink    bool                `json:"has_external_sink"`
}

const (
	tagSource = "sensitive_source"
	tagSink   = "external_sink"
)

func taggerVectorInputs() []taggerVector {
	q := func(tool, server string) taggerVectorQuery { return taggerVectorQuery{Tool: tool, Server: server} }
	return []taggerVector{
		{
			Name: "tool_tagged_directly",
			Config: taggerVectorConfig{ToolTags: map[string][]string{
				"read_secret": {tagSource},
				"post_url":    {tagSink},
				"both":        {tagSource, tagSink},
			}},
			Queries: []taggerVectorQuery{q("read_secret", "fs"), q("post_url", "web"), q("both", "fs"), q("other", "fs")},
		},
		{
			Name: "server_tagged_tool_inherits",
			Config: taggerVectorConfig{
				ToolTags: map[string][]string{"override": {"custom"}},
				Servers: []taggerVectorServer{
					{ID: "vault", ProvidesTags: []string{tagSource}},
					{ID: "mail", ProvidesTags: []string{tagSink}},
					{ID: "plain"},
				},
			},
			Queries: []taggerVectorQuery{q("get", "vault"), q("send", "mail"), q("list", "plain"), q("override", "vault"), q("get", "unknown")},
		},
		{
			Name:    "no_tags",
			Config:  taggerVectorConfig{Servers: []taggerVectorServer{{ID: "fs"}}},
			Queries: []taggerVectorQuery{q("read", "fs"), q("read", "")},
		},
		{
			Name: "same_tool_on_two_servers_server_tags",
			Config: taggerVectorConfig{Servers: []taggerVectorServer{
				{ID: "a", ProvidesTags: []string{tagSource}},
				{ID: "b", ProvidesTags: []string{tagSink}},
			}},
			Queries: []taggerVectorQuery{q("run", "a"), q("run", "b"), q("run", "c")},
		},
		{
			Name: "same_tool_on_two_servers_tool_tag_wins",
			Config: taggerVectorConfig{
				ToolTags: map[string][]string{"run": {tagSink}},
				Servers: []taggerVectorServer{
					{ID: "a", ProvidesTags: []string{tagSource}},
					{ID: "b"},
				},
			},
			Queries: []taggerVectorQuery{q("run", "a"), q("run", "b")},
		},
		{
			Name: "empty_tool_tags_shadow_server_tags",
			Config: taggerVectorConfig{
				ToolTags: map[string][]string{"quiet": {}},
				Servers:  []taggerVectorServer{{ID: "vault", ProvidesTags: []string{tagSource}}},
			},
			Queries: []taggerVectorQuery{q("quiet", "vault"), q("loud", "vault")},
		},
		{
			Name: "tags_in_different_case",
			Config: taggerVectorConfig{
				ToolTags: map[string][]string{
					"Read_Secret": {"Sensitive_Source"},
					"post":        {"EXTERNAL_SINK"},
					"lower":       {tagSource},
				},
				Servers: []taggerVectorServer{{ID: "Vault", ProvidesTags: []string{"SENSITIVE_SOURCE"}}},
			},
			Queries: []taggerVectorQuery{q("Read_Secret", "x"), q("read_secret", "x"), q("post", "x"), q("lower", "x"), q("LOWER", "x"), q("any", "Vault"), q("any", "vault")},
		},
		{
			Name: "empty_tool_and_server_strings",
			Config: taggerVectorConfig{
				ToolTags: map[string][]string{"": {tagSink}},
				Servers:  []taggerVectorServer{{ID: "", ProvidesTags: []string{tagSource}}},
			},
			Queries: []taggerVectorQuery{q("", ""), q("", "fs"), q("read", ""), q("read", "fs")},
		},
		{
			Name:    "empty_strings_without_config",
			Queries: []taggerVectorQuery{q("", ""), q("", "fs"), q("read", "")},
		},
		{
			Name: "inherit_sink_suspicion",
			Config: taggerVectorConfig{
				InheritSinkSuspicion:   true,
				SinkSuspicionAllowlist: []string{"list", ""},
				ToolTags:               map[string][]string{"quiet": {}},
				Servers: []taggerVectorServer{
					{ID: "vault", ProvidesTags: []string{tagSource}},
					{ID: "plain"},
				},
			},
			Queries: []taggerVectorQuery{q("get", "vault"), q("list", "vault"), q("quiet", "vault"), q("get", "plain"), q("", "vault")},
		},
		{
			Name: "inherit_sink_suspicion_off",
			Config: taggerVectorConfig{
				SinkSuspicionAllowlist: []string{"list"},
				Servers:                []taggerVectorServer{{ID: "vault", ProvidesTags: []string{tagSource}}},
			},
			Queries: []taggerVectorQuery{q("get", "vault")},
		},
		{
			Name: "explicit_sink_on_allowlist",
			Config: taggerVectorConfig{
				InheritSinkSuspicion:   true,
				SinkSuspicionAllowlist: []string{"post"},
				ToolTags:               map[string][]string{"post": {tagSink}},
				Servers:                []taggerVectorServer{{ID: "vault", ProvidesTags: []string{tagSource}}},
			},
			Queries: []taggerVectorQuery{q("post", "vault")},
		},
		{
			Name: "has_external_sink_ignores_allowlist",
			Config: taggerVectorConfig{
				InheritSinkSuspicion:   true,
				SinkSuspicionAllowlist: []string{"get"},
				Servers:                []taggerVectorServer{{ID: "vault", ProvidesTags: []string{tagSource}}},
			},
			Queries: []taggerVectorQuery{q("get", "vault")},
		},
		{
			Name: "allowlist_exact_case",
			Config: taggerVectorConfig{
				InheritSinkSuspicion:   true,
				SinkSuspicionAllowlist: []string{"Get"},
				Servers:                []taggerVectorServer{{ID: "vault", ProvidesTags: []string{tagSource}}},
			},
			Queries: []taggerVectorQuery{q("Get", "vault"), q("get", "vault")},
		},
	}
}

func taggerVectors() []taggerVector {
	cases := taggerVectorInputs()
	for i := range cases {
		c := &cases[i]
		cfg := &config.Config{
			ToolTags: c.Config.ToolTags,
			ServerDefaults: config.ServerDefaultsConfig{
				InheritSinkSuspicion:   c.Config.InheritSinkSuspicion,
				SinkSuspicionAllowlist: c.Config.SinkSuspicionAllowlist,
			},
		}
		for _, s := range c.Config.Servers {
			cfg.Servers = append(cfg.Servers, config.ServerConfig{ID: s.ID, ProvidesTags: s.ProvidesTags})
		}
		tg := NewTagger(cfg)
		for j := range c.Queries {
			qr := &c.Queries[j]
			qr.Tags = append([]string{}, tg.TagsFor(qr.Tool, qr.Server)...)
			qr.SensitiveSource = tg.IsSensitiveSource(qr.Tool, qr.Server)
			qr.ExternalSink = tg.IsExternalSink(qr.Tool, qr.Server)
		}
		c.HasSensitiveSource = tg.HasSensitiveSource()
		c.HasExternalSink = tg.HasExternalSink()
	}
	return cases
}

func TestTaggerVectors(t *testing.T) {
	checkVectorFile(t, "testdata/tagger_vectors.json", "go test ./internal/engine -run TaggerVectors -update", taggerVectors())
}

// checkVectorFile rewrites path under -update, otherwise decodes it strictly.
// An omitted key fails before the first value that differs from got.
func checkVectorFile[T any](t *testing.T, path, regenerate string, got T) {
	t.Helper()
	if *updateEncodingVectors {
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v; regenerate with %s", err, regenerate)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var want T
	if err := dec.Decode(&want); err != nil {
		t.Fatalf("decode vectors: %v; regenerate with %s", err, regenerate)
	}
	var parsed any
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&parsed); err != nil {
		t.Fatalf("decode vectors: %v; regenerate with %s", err, regenerate)
	}
	var g, w any
	for _, p := range []struct {
		in  any
		out *any
	}{{got, &g}, {want, &w}} {
		raw, err := json.Marshal(p.in)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, p.out); err != nil {
			t.Fatal(err)
		}
	}
	if where := missingVectorField(g, parsed, ""); where != "" {
		t.Fatalf("missing or null field %s; regenerate with %s", where, regenerate)
	}
	if where, gv, wv, ok := firstVectorDiff(g, w, ""); ok {
		t.Fatalf("%s: got %s, want %s; regenerate with %s", where, gv, wv, regenerate)
	}
}

// missingVectorField reports the first key present in full (the encoded
// result) and absent or null in raw (the file). Typed decode fills those with
// zero values, so the key check has to see the file's object. A null is only
// accepted where the encoded result is null too.
func missingVectorField(full, raw any, path string) string {
	if raw == nil && full != nil {
		return path
	}
	switch f := full.(type) {
	case map[string]any:
		r, ok := raw.(map[string]any)
		if !ok {
			return ""
		}
		keys := make([]string, 0, len(f))
		for k := range f {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, ok := r[k]; !ok {
				return path + "." + k
			}
			if where := missingVectorField(f[k], r[k], path+"."+k); where != "" {
				return where
			}
		}
	case []any:
		r, ok := raw.([]any)
		if !ok {
			return ""
		}
		n := len(f)
		if len(r) < n {
			n = len(r)
		}
		for i := 0; i < n; i++ {
			if where := missingVectorField(f[i], r[i], vectorElemPath(path, i, f[i])); where != "" {
				return where
			}
		}
	}
	return ""
}

func vectorElemPath(prefix string, i int, elem any) string {
	label := fmt.Sprintf("%s[%d]", prefix, i)
	m, ok := elem.(map[string]any)
	if !ok {
		return label
	}
	if name, ok := m["name"].(string); ok {
		label += "(" + name + ")"
	}
	if args, ok := m["args_json"].(string); ok {
		label += "(args=" + args + ")"
	}
	if p, ok := m["path"].(string); ok {
		label += "(path=" + p + ")"
	}
	if tool, ok := m["tool"].(string); ok {
		server, _ := m["server"].(string)
		label += "(tool=" + tool + " server=" + server + ")"
	}
	return label
}

func firstVectorDiff(got, want any, path string) (string, string, string, bool) {
	switch g := got.(type) {
	case map[string]any:
		w, ok := want.(map[string]any)
		if !ok {
			break
		}
		keys := map[string]bool{}
		for k := range g {
			keys[k] = true
		}
		for k := range w {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			if where, a, b, diff := firstVectorDiff(g[k], w[k], path+"."+k); diff {
				return where, a, b, true
			}
		}
		return "", "", "", false
	case []any:
		w, ok := want.([]any)
		if !ok {
			break
		}
		for i := 0; i < len(g) && i < len(w); i++ {
			if where, a, b, diff := firstVectorDiff(g[i], w[i], vectorElemPath(path, i, g[i])); diff {
				return where, a, b, true
			}
		}
		if len(g) != len(w) {
			return path + ".len", fmt.Sprint(len(g)), fmt.Sprint(len(w)), true
		}
		return "", "", "", false
	}
	gj, _ := json.Marshal(got)
	wj, _ := json.Marshal(want)
	if string(gj) != string(wj) {
		return path, string(gj), string(wj), true
	}
	return "", "", "", false
}
