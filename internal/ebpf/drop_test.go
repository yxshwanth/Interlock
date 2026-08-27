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
	var cfn func(*Loader) (uint64, error) = (*Loader).CriticalDropCount
	_ = cfn
}

func TestLoader_DropCount_Unloaded(t *testing.T) {
	var l Loader
	_, err := l.DropCount()
	if err == nil {
		t.Fatal("expected error when BPF maps are not loaded")
	}
	_, err = l.CriticalDropCount()
	if err == nil {
		t.Fatal("expected error when critical_drop_count map is not loaded")
	}
	_, err = l.ReadCriticalEvent()
	if err == nil {
		t.Fatal("expected error when critical ringbuf reader is not loaded")
	}
}

func TestLoader_DropCount_AfterLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load BPF tracepoints")
	}
	loader, err := NewLoader(false)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	defer loader.Close()

	drops, err := loader.DropCount()
	if err != nil {
		t.Fatalf("DropCount: %v", err)
	}
	if drops != 0 {
		t.Fatalf("expected 0 routine drops at idle, got %d", drops)
	}
	crit, err := loader.CriticalDropCount()
	if err != nil {
		t.Fatalf("CriticalDropCount: %v", err)
	}
	if crit != 0 {
		t.Fatalf("expected 0 critical drops at idle, got %d", crit)
	}
}

func TestEBPF_RingbufSaturation_UnderLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ringbuf saturation requires root + BTF kernel")
	}

	t.Run("connect_flood_routine_only", func(t *testing.T) {
		loader, err := NewLoader(false)
		if err != nil {
			t.Fatalf("NewLoader: %v", err)
		}
		defer loader.Close()

		pid := os.Getpid()
		if err := loader.AddPID(pid); err != nil {
			t.Fatalf("AddPID: %v", err)
		}

		// Drain critical so incidental Go-runtime writes do not inflate
		// critical_drop_count; assert no connect events land on that ring.
		stopDrain := make(chan struct{})
		drainDone := make(chan struct{})
		var criticalConnects, criticalEvents int
		go func() {
			defer close(drainDone)
			for {
				select {
				case <-stopDrain:
					return
				default:
				}
				ev, err := loader.ReadCriticalEvent()
				if err != nil {
					continue
				}
				criticalEvents++
				if ev.Connect != nil {
					criticalConnects++
				}
			}
		}()

		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			for i := 0; i < 256; i++ {
				c, err := net.DialTimeout("tcp", "127.0.0.1:1", time.Millisecond)
				if err == nil {
					_ = c.Close()
				}
			}
		}

		close(stopDrain)
		loader.criticalReader.Close()
		<-drainDone

		drops, err := loader.DropCount()
		if err != nil {
			t.Fatalf("DropCount: %v", err)
		}
		crit, err := loader.CriticalDropCount()
		if err != nil {
			t.Fatalf("CriticalDropCount: %v", err)
		}
		t.Logf("connect flood: drop_count=%d critical_drop_count=%d critical_events_drained=%d",
			drops, crit, criticalEvents)
		if drops == 0 {
			t.Skip("could not saturate routine 256KB ringbuf; run manually under heavier load")
		}
		if criticalConnects != 0 {
			t.Fatalf("connect events must not appear on critical ring, got %d", criticalConnects)
		}
		if crit != 0 {
			t.Fatalf("drained critical ring must not drop, got critical_drop_count=%d", crit)
		}
	})

	t.Run("write_flood_critical_only", func(t *testing.T) {
		loader, err := NewLoader(false)
		if err != nil {
			t.Fatalf("NewLoader: %v", err)
		}
		defer loader.Close()

		capture := 1024
		if err := loader.SetPayloadCaptureBytes(capture); err != nil {
			t.Fatalf("SetPayloadCaptureBytes: %v", err)
		}
		pid := os.Getpid()
		if err := loader.AddPID(pid); err != nil {
			t.Fatalf("AddPID: %v", err)
		}

		f, err := os.CreateTemp("", "interlock-ringbuf-write-*")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		defer os.Remove(f.Name())
		defer f.Close()

		payload := make([]byte, capture)
		for i := range payload {
			payload[i] = 'x'
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			for i := 0; i < 256; i++ {
				_, _ = f.Write(payload)
			}
		}

		drops, err := loader.DropCount()
		if err != nil {
			t.Fatalf("DropCount: %v", err)
		}
		crit, err := loader.CriticalDropCount()
		if err != nil {
			t.Fatalf("CriticalDropCount: %v", err)
		}
		t.Logf("write flood: drop_count=%d critical_drop_count=%d", drops, crit)
		if crit == 0 {
			t.Skip("could not saturate critical 256KB ringbuf; run manually under heavier load")
		}
		if drops != 0 {
			t.Fatalf("write-only flood must not increment routine drop_count, got %d", drops)
		}
	})

	for _, capture := range []int{256, 512, 1024} {
		t.Run(fmt.Sprintf("mixed_flood_capture_%d", capture), func(t *testing.T) {
			loader, err := NewLoader(false)
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
			crit, err := loader.CriticalDropCount()
			if err != nil {
				t.Fatalf("CriticalDropCount: %v", err)
			}
			t.Logf("capture=%d drop_count=%d critical_drop_count=%d under mixed flood", capture, drops, crit)
			if drops == 0 && crit == 0 {
				t.Skip("could not saturate either 256KB ringbuf in this environment; run manually under heavier load")
			}
		})
	}
}
