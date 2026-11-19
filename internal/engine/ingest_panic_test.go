// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

func TestIngestResult_PanicReleasesEngineLock(t *testing.T) {
	e, _ := newTestEngine("block")
	logger := e.log
	e.log = nil // makes the untrusted-result path panic while e.mu is held

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected IngestResult to panic")
			}
		}()
		e.IngestResult(model.InterceptedEvent{SessionID: "s", ToolName: "t", Seq: 1})
	}()

	e.log = logger
	next := makeResultEvent("next", "fetch_page", "web", 2, `{"content":[{"type":"text","text":"next page"}]}`)
	done := make(chan struct{})
	go func() {
		e.IngestResult(next)
		close(done)
	}()

	select {
	case <-done:
		state := e.store.Get(next.SessionID)
		if state == nil || state.Legs.UntrustedContentPresent.TriggerSeq != next.Seq {
			t.Fatal("next result did not update the session after the panic")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("next result did not finish after the panic")
	}
}
