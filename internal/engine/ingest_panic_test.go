// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"

	"github.com/yxshwanth/Interlock/internal/model"
)

func TestIngestResult_PanicReleasesEngineLock(t *testing.T) {
	e, _ := newTestEngine("block")
	e.log = nil // makes the untrusted-result path panic while e.mu is held

	func() {
		defer func() { _ = recover() }()
		e.IngestResult(model.InterceptedEvent{SessionID: "s", ToolName: "t", Seq: 1})
	}()

	if !e.mu.TryLock() {
		t.Fatal("engine mutex still held after IngestResult panicked: every later engine call would wedge")
	}
	e.mu.Unlock()
}
