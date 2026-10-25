// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"encoding/binary"
	"testing"
)

// The ring buffer is a trust boundary: records come from the kernel but their
// content (comm, payload, addresses) is attacker-influenced, and a short or
// inconsistent record must be rejected, never indexed out of range.
func FuzzDecodeRingEvent(f *testing.F) {
	for _, typ := range []uint32{eventTypeConnect, eventTypeWrite, eventTypeSendto, eventTypeOpenat, eventTypeLSMDeny, eventTypeWritev, eventTypeSendmsg} {
		rec := make([]byte, 128)
		binary.LittleEndian.PutUint32(rec[0:4], typ)
		f.Add(rec)
		f.Add(rec[:9])
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = decodeRingEvent(raw)
	})
}
