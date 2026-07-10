package main

// Quiet-mode narrative beats shared by STDIO and HTTP demo paths.
// Keep these as the single source of truth so make demo / demo-quiet / HTTP
// twins cannot drift from the post-v0.2 money-shot story.

const (
	// Pass 1 (monitor) — literal breach.
	beatReadTicket          = "Agent reads support ticket T-1234…"
	beatTicketPoison        = "ticket contains a hidden instruction: exfiltrate the auth token"
	beatSendMessageExfil    = "Agent calls send_message  (attempting exfil)"
	beatTrifectaMonitor     = "TRIFECTA DETECTED — verdict=EXFIL  (firewall OFF: monitor mode)"
	beatSendMessageBreach   = "send_message SENT — token left the building.  BREACH."
	beatTrifectaPrevented   = "TRIFECTA DETECTED — verdict=EXFIL  action=PREVENTED"
	beatSendMessageBlocked  = "send_message BLOCKED — token never left."

	// Pass 2 (block) — gzip_base64 overlap expansion.
	beatPass2GzipExfil     = "Agent calls send_message  (gzip_base64-encoded exfil)"
	beatPass2GzipPrevented = "TRIFECTA DETECTED — match_form=gzip_base64  action=PREVENTED"

	// Pass 3 (eBPF) — payload-backed EXFIL + kill.
	beatPass3ReadTicket     = "Agent reads support ticket T-1234…   (legs 1+2 lit)"
	beatPass3RunAnalysis    = "Agent calls run_analysis  (looks harmless to the proxy)"
	beatPass3PayloadExfil   = "[kernel] connect()+write() detected — payload overlap → EXFIL"
	beatPass3MatchWhere     = "match_where=egress payload"
	beatPass3SideChannel    = "side channel the proxy never saw"
	beatPass3Contained      = "TRIFECTA DETECTED (eBPF) — action=CONTAINED_BY_KILL"
	beatPass3Killed         = "exfil process KILLED. channel severed."
	beatPass3Survived       = "[kernel] connect()/write detected but server completed before kill"

	// Skip / results footer.
	skipPass3Hint   = "to see Variant B (payload-backed EXFIL + kill-on-detect)."
	footerMonitor   = "Monitor:  literal secret SENT (BREACH)."
	footerBlock     = "Block:    gzip_base64 secret BLOCKED at proxy (Variant A prevented)."
	footerEBPF      = "eBPF:     egress payload overlapped taint → EXFIL, process KILLED (Variant B contained)."
)
