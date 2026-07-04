// Command ebpf-test is a throwaway CLI for verifying the compiled eBPF
// connect() probe in isolation (Rung 1). Run with sudo:
//
//	sudo go run ./cmd/ebpf-test
//
// Then in another terminal: curl http://example.com
// Output should show curl's PID, dest IP, dest port.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	interlockebpf "github.com/yxshwanth/Interlock/internal/ebpf"
)

func main() {
	logger := log.New(os.Stderr, "[ebpf-test] ", log.LstdFlags)
	logger.Println("loading BPF connect() probe...")

	loader, err := interlockebpf.NewLoader()
	if err != nil {
		logger.Fatalf("failed to load: %v", err)
	}
	defer loader.Close()

	selfPID := os.Getpid()
	logger.Printf("probe loaded. adding self PID %d to filter (any child will inherit).", selfPID)

	// In test mode, watch ALL pids by adding a wildcard approach:
	// add our own PID so we see at least our own outgoing connects,
	// or if the user passes a PID as an argument, watch that instead.
	pids := []int{selfPID}
	if len(os.Args) > 1 {
		var pid int
		_, err := fmt.Sscanf(os.Args[1], "%d", &pid)
		if err == nil {
			pids = append(pids, pid)
			logger.Printf("also watching PID %d", pid)
		}
	}

	if err := loader.UpdatePIDSet(pids); err != nil {
		logger.Fatalf("failed to set PID filter: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	logger.Println("listening for connect() events for 30 seconds...")
	logger.Println("  try: curl http://example.com (in another terminal)")
	logger.Println("")

	go func() {
		for {
			ev, err := loader.ReadEvent()
			if err != nil {
				return
			}
			fmt.Fprintf(os.Stderr, "  CONNECT: pid=%d tid=%d comm=%s dest=%s:%d ts=%d\n",
				ev.PID, ev.TID, ev.CommString(), ev.DestIPString(), ev.DestPort, ev.TSNs)
		}
	}()

	select {
	case <-sig:
		logger.Println("interrupted, shutting down")
	case <-timer.C:
		logger.Println("30 second timeout, shutting down")
	}
}
