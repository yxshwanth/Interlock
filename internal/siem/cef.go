package siem

import (
	"fmt"
	"strings"

	"github.com/yxshwanth/Interlock/internal/model"
)

// ToCEF maps an EvidenceRecord to an ArcSight CEF 0 line (no trailing newline).
func ToCEF(rec model.EvidenceRecord) string {
	sev := cefSeverity(rec.Verdict)
	sig := string(rec.Variant)
	if sig == "" {
		sig = "unknown"
	}
	name := string(rec.Verdict)
	if name == "" {
		name = "UNKNOWN"
	}
	msg := fmt.Sprintf("Interlock %s detection variant=%s action=%s confidence=%.2f",
		rec.Verdict, rec.Variant, rec.Action, rec.Confidence)

	var b strings.Builder
	b.WriteString("CEF:0|Interlock|Interlock|0.4|")
	b.WriteString(cefHeaderEscape(sig))
	b.WriteByte('|')
	b.WriteString(cefHeaderEscape(name))
	b.WriteByte('|')
	b.WriteString(fmt.Sprintf("%d", sev))
	b.WriteByte('|')

	ext := []string{
		"msg=" + cefExtEscape(msg),
		"cs1=" + cefExtEscape(rec.SessionID),
		"cs1Label=session_id",
		"cs2=" + cefExtEscape(string(rec.Action)),
		"cs2Label=action",
		"cs3=" + cefExtEscape(string(rec.Variant)),
		"cs3Label=variant",
		"cn1=" + fmt.Sprintf("%.2f", rec.Confidence),
		"cn1Label=confidence",
	}
	if rec.Pod != nil && rec.Pod.PodName != "" {
		ext = append(ext,
			"cs4="+cefExtEscape(rec.Pod.PodName),
			"cs4Label=pod_name",
		)
		if rec.Pod.Namespace != "" {
			ext = append(ext, "cs5="+cefExtEscape(rec.Pod.Namespace), "cs5Label=namespace")
		}
		if rec.Pod.NodeName != "" {
			ext = append(ext, "cs6="+cefExtEscape(rec.Pod.NodeName), "cs6Label=node_name")
		}
	}
	if rec.ValueOverlap != nil && rec.ValueOverlap.WhereFound != "" {
		ext = append(ext, "cs7="+cefExtEscape(rec.ValueOverlap.WhereFound), "cs7Label=where_found")
	}
	b.WriteString(strings.Join(ext, " "))
	return b.String()
}

func cefSeverity(v model.Verdict) int {
	if v == model.VerdictExfil {
		return 10
	}
	return 5
}

// cefHeaderEscape escapes pipe and backslash in CEF header fields.
func cefHeaderEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return s
}

// cefExtEscape escapes CEF extension special characters (= \ | \n \r).
func cefExtEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '=':
			b.WriteString(`\=`)
		case '|':
			b.WriteString(`\|`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
