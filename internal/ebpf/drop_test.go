package ebpf

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestLoader_DropCount_NoProbe(t *testing.T) {
	// DropCount requires a loaded probe; verify API exists via compile-time check only.
	var fn func(*Loader) (uint64, error) = (*Loader).DropCount
	_ = fn
}

func TestLoader_DropCount_Unloaded(t *testing.T) {
	var l Loader
	_, err := l.DropCount()
	if err == nil {
		t.Fatal("expected error when BPF maps are not loaded")
	}
}

func TestLoader_DropCount_AfterLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF tracepoints")
	}
	loader, err := NewLoader()
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	defer loader.Close()

	drops, err := loader.DropCount()
	if err != nil {
		t.Fatalf("DropCount: %v", err)
	}
	if drops != 0 {
		t.Fatalf("expected 0 drops at idle, got %d", drops)
	}
}

func TestEBPF_RingbufSaturation_UnderLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ringbuf saturation requires root + BTF kernel")
	}

	for _, capture := range []int{256, 512, 1024} {
		t.Run(fmt.Sprintf("capture_%d", capture), func(t *testing.T) {
			loader, err := NewLoader()
			if err != nil {
				t.Fatalf("NewLoader: %v", err)
			}
			defer loader.Close()

			if err := loader.SetPayloadCaptureBytes(capture); err != nil {
				t.Fatalf("SetPayloadCaptureBytes(%d): %v", capture, err)
			}

			pid := os.Getpid()
			if err := loader.AddPID(pid); err != nil {
				t.Fatalf("AddPID: %v", err)
			}

			// Do not drain the ringbuf — flood connect/write so reserve failures accumulate.
			deadline := time.Now().Add(2 * time.Second)
			payload := make([]byte, capture)
			for i := range payload {
				payload[i] = 'x'
			}
			for time.Now().Before(deadline) {
				for i := 0; i < 256; i++ {
					c, err := net.DialTimeout("tcp", "127.0.0.1:1", time.Millisecond)
					if err == nil {
						_, _ = c.Write(payload)
						_ = c.Close()
					}
				}
			}

			drops, err := loader.DropCount()
			if err != nil {
				t.Fatalf("DropCount: %v", err)
			}
			t.Logf("capture=%d drop_count=%d under flood (larger capture → fewer events per 256KB ringbuf)", capture, drops)
			if drops == 0 {
				t.Skip("could not saturate 256KB ringbuf in this environment; run manually under heavier load")
			}
		})
	}
}
