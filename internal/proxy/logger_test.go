// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"os"
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

func TestEventLogger_DropBackpressure(t *testing.T) {
	stats := &model.RuntimeStats{}
	path := t.TempDir() + "/events.jsonl"
	logger, err := NewEventLogger(path, config.LoggingConfig{
		Backpressure: "drop",
		QueueSize:    1,
	}, stats)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	ev := model.InterceptedEvent{SessionID: "s", Seq: 1, Method: "ping"}
	for i := 0; i < 10; i++ {
		logger.Log(ev)
	}
	if stats.DroppedEvents.Load() == 0 {
		t.Fatal("expected dropped events under saturated drop queue")
	}
}

// Review #13: event logs carry tool args and results, so they must not be
// world-readable.
func TestEventLogger_CreatesFileOwnerOnly(t *testing.T) {
	path := t.TempDir() + "/events.jsonl"
	logger, err := NewEventLogger(path, config.LoggingConfig{}, &model.RuntimeStats{})
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("event log mode %o, want 600", perm)
	}
}

func TestEventLogger_DiskFull_KnownGap(t *testing.T) {
	t.Skip("known v0.2 gap: behavior when filesystem write fails is undefined")
}
