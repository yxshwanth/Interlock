package siem_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
	"github.com/yxshwanth/Interlock/internal/siem"
)

func TestToCEF_RequiredFields(t *testing.T) {
	rec := sampleRec()
	rec.Pod = &model.PodContext{PodName: "agent-1", Namespace: "default", NodeName: "node-a"}
	line := siem.ToCEF(rec)
	if !strings.HasPrefix(line, "CEF:0|Interlock|Interlock|0.4|") {
		t.Fatalf("header=%q", line)
	}
	for _, want := range []string{
		"|EXFIL|10|",
		"cs1=sess-1",
		"cs1Label=session_id",
		"cs2Label=action",
		"cs3Label=variant",
		"cs4=agent-1",
		"cs4Label=pod_name",
		"cn1=0.95",
		"cn1Label=confidence",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in %s", want, line)
		}
	}
	if strings.Contains(line, "\n") {
		t.Fatal("CEF line must not contain newline")
	}
}

func TestToCEF_EscapesExtension(t *testing.T) {
	rec := sampleRec()
	rec.SessionID = `a=b|c\d`
	line := siem.ToCEF(rec)
	if !strings.Contains(line, `cs1=a\=b\|c\\d`) {
		t.Fatalf("escape failed: %s", line)
	}
}

func TestExporter_CEF_FileAndHTTP(t *testing.T) {
	var posted []byte
	var ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		posted, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "siem.cef")
	rc := &recCounter{}
	exp, err := siem.NewExporter(config.SIEMConfig{
		Format:     "cef",
		Path:       path,
		URL:        srv.URL,
		MinVerdict: "SUSPICIOUS",
		Timeout:    "2s",
	}, rc)
	if err != nil || exp == nil {
		t.Fatalf("exp=%v err=%v", exp, err)
	}
	exp.OnEvidenceEmitted(sampleRec())
	exp.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.HasPrefix(body, "CEF:0|") {
		t.Fatalf("file=%s", body)
	}
	if !strings.HasPrefix(string(posted), "CEF:0|") {
		t.Fatalf("posted=%s", posted)
	}
	if ct != "text/plain" {
		t.Fatalf("Content-Type=%q", ct)
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.m["siem:ok"] != 1 {
		t.Fatalf("recorder=%v", rc.m)
	}
}
