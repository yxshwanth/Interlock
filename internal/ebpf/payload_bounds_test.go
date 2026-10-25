// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"encoding/binary"
	"testing"
)

// A record whose header claims more payload than the sample carries must not
// report a Len the Payload cannot back (review #6).
func TestDecode_LenBoundedToCapturedSize(t *testing.T) {
	w := make([]byte, writeHeaderLen+3)
	binary.LittleEndian.PutUint32(w[0:4], eventTypeWrite)
	binary.LittleEndian.PutUint32(w[4:8], 1024)
	copy(w[writeHeaderLen:], "abc")
	ev, err := decodeRingEvent(w)
	if err != nil || ev.Write == nil {
		t.Fatalf("decode: %+v %v", ev, err)
	}
	if ev.Write.Len != 3 || string(ev.Write.Payload) != "abc" {
		t.Fatalf("len=%d payload=%q, want 3/abc", ev.Write.Len, ev.Write.Payload)
	}

	s := make([]byte, sendtoHeaderLen+2)
	binary.LittleEndian.PutUint32(s[0:4], eventTypeSendto)
	binary.LittleEndian.PutUint32(s[4:8], 500)
	copy(s[sendtoHeaderLen:], "xy")
	ev, err = decodeRingEvent(s)
	if err != nil || ev.Sendto == nil || ev.Sendto.Len != 2 || string(ev.Sendto.Payload) != "xy" {
		t.Fatalf("sendto decode: %+v %v", ev, err)
	}
}
