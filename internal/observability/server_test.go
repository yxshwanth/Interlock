package observability_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
	"github.com/yxshwanth/Interlock/internal/observability"
)

func TestServer_HealthAndMetrics(t *testing.T) {
	ready := false
	srv, err := observability.Start("127.0.0.1:0", "/metrics", "/healthz", func() bool { return ready })
	if err != nil {
		t.Fatal(err)
	}
	if srv == nil {
		t.Fatal("expected server")
	}
	defer srv.Close()

	base := "http://" + srv.Addr()

	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("not ready: status=%d body=%s", resp.StatusCode, body)
	}

	ready = true
	resp, err = http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ready: status=%d", resp.StatusCode)
	}

	m := observability.NewMetrics()
	m.RecordDetection(model.EvidenceRecord{
		Verdict: model.VerdictExfil,
		Variant: model.VariantB,
		Action:  model.ActionContained,
	})

	deadline := time.Now().Add(2 * time.Second)
	var metricsBody string
	for time.Now().Before(deadline) {
		resp, err = http.Get(base + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		metricsBody = string(b)
		if strings.Contains(metricsBody, "interlock_detections_total") &&
			strings.Contains(metricsBody, "interlock_up") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(metricsBody, "interlock_detections_total") {
		t.Fatalf("metrics missing detections:\n%s", metricsBody)
	}
	if !strings.Contains(metricsBody, `verdict="EXFIL"`) {
		t.Fatalf("metrics missing EXFIL label:\n%s", metricsBody)
	}
}

func TestStart_EmptyListen(t *testing.T) {
	srv, err := observability.Start("", "/metrics", "/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if srv != nil {
		t.Fatal("expected nil server when listen empty")
	}
}
