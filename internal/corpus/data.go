// SPDX-License-Identifier: Apache-2.0

package corpus

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

// The corpus is data, not code: data/*.json is the specification of engine
// behavior and the acceptance contract for any other implementation (the Rust
// port reads the same files). The wire types below are deliberately separate
// from model.* so the file format does not move when an internal struct
// changes, and so fields tagged json:"-" there (SyscallEvent.FileContents)
// still round-trip.

//go:embed data/*.json
var dataFS embed.FS

type fileWire struct {
	Profile   string         `json:"profile"`
	Scenarios []scenarioWire `json:"scenarios"`
}

type scenarioWire struct {
	ID                     string      `json:"id"`
	Description            string      `json:"description"`
	Category               Category    `json:"category"`
	Variant                Variant     `json:"variant"`
	Enforcement            string      `json:"enforcement,omitempty"`
	KnownGap               bool        `json:"known_gap,omitempty"`
	GapTag                 string      `json:"gap_tag,omitempty"`
	GapNote                string      `json:"gap_note,omitempty"`
	PreExistingGap         bool        `json:"pre_existing_gap,omitempty"`
	ExpectTripByDesign     bool        `json:"expect_trip_by_design,omitempty"`
	DesignNote             string      `json:"design_note,omitempty"`
	CVERef                 *cveRefWire `json:"cve_ref,omitempty"`
	VaultEnabled           bool        `json:"vault_enabled,omitempty"`
	VaultAuthorize         []vaultWire `json:"vault_authorize,omitempty"`
	InheritSinkSuspicion   bool        `json:"inherit_sink_suspicion,omitempty"`
	SinkSuspicionAllowlist []string    `json:"sink_suspicion_allowlist,omitempty"`
	MaxDecodeDepth         int         `json:"max_decode_depth,omitempty"`
	Steps                  []stepWire  `json:"steps"`
}

type cveRefWire struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	RealWorld string `json:"real_world"`
}

type vaultWire struct {
	Tool          string   `json:"tool"`
	SecretClasses []string `json:"secret_classes,omitempty"`
}

// stepWire is a tagged union on Kind: result and request use the
// event fields, syscall and syscall_sensor the syscall fields, advance_time
// uses session_id and advance_by (a Go duration string such as "31m").
type stepWire struct {
	Kind StepKind `json:"kind"`

	SessionID string          `json:"session_id,omitempty"`
	Seq       uint64          `json:"seq,omitempty"`
	Direction model.Direction `json:"direction,omitempty"`
	Method    string          `json:"method,omitempty"`
	ToolName  string          `json:"tool_name,omitempty"`
	ServerID  string          `json:"server_id,omitempty"`
	ToolArgs  json.RawMessage `json:"tool_args,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Decision  string          `json:"decision,omitempty"`

	TSMono       int64  `json:"ts_mono_ns,omitempty"`
	PID          int    `json:"pid,omitempty"`
	Comm         string `json:"comm,omitempty"`
	Syscall      string `json:"syscall,omitempty"`
	DestIP       string `json:"dest_ip,omitempty"`
	DestPort     int    `json:"dest_port,omitempty"`
	Path         string `json:"path,omitempty"`
	Payload      string `json:"payload,omitempty"`
	FileContents string `json:"file_contents,omitempty"`
	// *_b64 carry the same field when its bytes are not valid UTF-8 (compressed
	// or binary payloads); JSON strings would silently replace those bytes.
	PayloadB64      string `json:"payload_b64,omitempty"`
	FileContentsB64 string `json:"file_contents_b64,omitempty"`

	AdvanceBy string `json:"advance_by,omitempty"`
}

type profileWire struct {
	Servers []struct {
		ID           string   `json:"id"`
		Command      string   `json:"command"`
		ProvidesTags []string `json:"provides_tags"`
	} `json:"servers"`
	ToolTags map[string][]string `json:"tool_tags"`
}

func readData(name string, v any) {
	raw, err := dataFS.ReadFile("data/" + name)
	if err != nil {
		panic(fmt.Sprintf("corpus: %v", err))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // a typo in a data file must fail loudly, not be ignored
	if err := dec.Decode(v); err != nil {
		panic(fmt.Sprintf("corpus: data/%s: %v", name, err))
	}
}

func loadScenarios(name string) []Scenario {
	var f fileWire
	readData(name, &f)
	out := make([]Scenario, 0, len(f.Scenarios))
	for _, w := range f.Scenarios {
		out = append(out, w.scenario())
	}
	return out
}

func (w scenarioWire) scenario() Scenario {
	sc := Scenario{
		ID: w.ID, Description: w.Description, Category: w.Category, Variant: w.Variant,
		Enforcement: w.Enforcement, KnownGap: w.KnownGap, GapTag: w.GapTag, GapNote: w.GapNote,
		PreExistingGap: w.PreExistingGap, ExpectTripByDesign: w.ExpectTripByDesign,
		DesignNote: w.DesignNote, VaultEnabled: w.VaultEnabled,
		InheritSinkSuspicion: w.InheritSinkSuspicion, SinkSuspicionAllowlist: w.SinkSuspicionAllowlist,
		MaxDecodeDepth: w.MaxDecodeDepth,
	}
	if w.CVERef != nil {
		sc.CVERef = &CVERef{ID: w.CVERef.ID, Source: w.CVERef.Source, RealWorld: w.CVERef.RealWorld}
	}
	for _, v := range w.VaultAuthorize {
		sc.VaultAuthorize = append(sc.VaultAuthorize, config.VaultAuthorizeEntry{Tool: v.Tool, SecretClasses: v.SecretClasses})
	}
	for _, s := range w.Steps {
		sc.Steps = append(sc.Steps, s.step(w.ID))
	}
	return sc
}

func (s stepWire) step(scenarioID string) Step {
	switch s.Kind {
	case StepResult, StepRequest:
		return Step{Kind: s.Kind, Event: model.InterceptedEvent{
			SessionID: s.SessionID, Seq: s.Seq, Direction: s.Direction, Method: s.Method,
			ToolName: s.ToolName, ServerID: s.ServerID, ToolArgs: compactJSON(s.ToolArgs), Result: compactJSON(s.Result),
			Decision: s.Decision,
		}}
	case StepSyscall, StepSyscallSensor:
		return Step{Kind: s.Kind, Syscall: model.SyscallEvent{
			TSMono: s.TSMono, PID: s.PID, Comm: s.Comm, Syscall: s.Syscall, DestIP: s.DestIP, DestPort: s.DestPort,
			Path: s.Path, PayloadExcerpt: textOrB64(s.Payload, s.PayloadB64), SessionID: s.SessionID,
			FileContents: textOrB64(s.FileContents, s.FileContentsB64),
		}}
	case StepAdvanceTime:
		d, err := time.ParseDuration(s.AdvanceBy)
		if err != nil {
			panic(fmt.Sprintf("corpus: %s: advance_by %q: %v", scenarioID, s.AdvanceBy, err))
		}
		return Step{Kind: s.Kind, SessionID: s.SessionID, AdvanceBy: d}
	}
	panic(fmt.Sprintf("corpus: %s: unknown step kind %q", scenarioID, s.Kind))
}

func textOrB64(text, b64 string) string {
	if b64 == "" {
		return text
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic(fmt.Sprintf("corpus: bad base64: %v", err))
	}
	return string(raw)
}

// compactJSON undoes the re-indentation the pretty-printed data files apply to
// embedded JSON values, so the engine sees the same bytes a Go builder produced.
func compactJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// profileConfig builds the fixture config a data file's profile names.
func profileConfig(profile string) func(mode string) *config.Config {
	var all map[string]profileWire
	readData("profiles.json", &all)
	p, ok := all[profile]
	if !ok {
		panic("corpus: unknown profile " + profile)
	}
	return func(mode string) *config.Config {
		cfg := &config.Config{Enforcement: mode, ToolTags: map[string][]string{}}
		for _, s := range p.Servers {
			cfg.Servers = append(cfg.Servers, config.ServerConfig{ID: s.ID, Command: s.Command, ProvidesTags: s.ProvidesTags})
		}
		for k, v := range p.ToolTags {
			cfg.ToolTags[k] = v
		}
		cfg.UntrustedOrigins.ToolResults = true
		return cfg
	}
}
