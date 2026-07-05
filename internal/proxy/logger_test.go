package proxy

import (
	"testing"

	"github.com/yxshwanth/Interlock/internal/config"
	"github.com/yxshwanth/Interlock/internal/model"
)

func TestEventLogger_DropBackpressure(t *testing.T) {
	stats := &RuntimeStats{}
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

func TestEventLogger_DiskFull_KnownGap(t *testing.T) {
	t.Skip("known v0.2 gap: behavior when filesystem write fails is undefined")
}
