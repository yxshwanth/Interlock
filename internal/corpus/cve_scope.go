// SPDX-License-Identifier: Apache-2.0

package corpus

// OutOfScopeCVE documents a published CVE that was NOT reconstructed as a
// Scenario at all, because its mechanism has no faithful representation in
// model.InterceptedEvent / model.SyscallEvent — the inputs Interlock's
// proxy and eBPF sensor actually observe. Forcing these into a Step
// sequence that "fails" would misrepresent what was tested: these were
// never attempted, not attempted-and-missed.
type OutOfScopeCVE struct {
	ID            string
	Source        string
	RealWorld     string
	WhyOutOfScope string
}

// CVEOutOfScope lists disclosures excluded from the reconstructed corpus,
// grouped by shared root cause so a single architectural reason isn't
// repeated CVE-by-CVE.
func CVEOutOfScope() []OutOfScopeCVE {
	return []OutOfScopeCVE{
		{
			ID:            "CVE-2026-30623 (LiteLLM) / CVE-2026-30624 (Agent Zero) / CVE-2026-30618 (Fay) / CVE-2026-33224 (Bisheng) / CVE-2026-30617 (Langchain-Chatchat) / CVE-2026-30615 (Windsurf) / CVE-2026-30625 (Upsonic)",
			Source:        "https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/",
			RealWorld:     "OX Security's root architectural finding: a malicious `command` string reaches StdioServerParameters (via a UI form, config file, or — for Windsurf's zero-click case — attacker-controlled HTML) and executes unconditionally, before the SDK ever checks whether the subprocess is a valid MCP server. Upsonic's variant smuggles the payload through npx/npm arguments; the other six are the same root cause reached through different application UIs.",
			WhyOutOfScope: "When the malicious command is injected into the host application's own config/UI layer before Interlock is ever invoked, execution happens outside Interlock's spawn path — there is no session, PID attribution, or proxy channel yet. That pre-Interlock poisoning remains out of scope. When Interlock itself spawns children (proxy `StartServer`), declared `servers[].command` executables are now canonicalized and pinned at config load; spawn rejects traversal or mismatched binaries, and optional `sandbox.netns` pairs with zero-route isolation. That closes the subset where Interlock is the process doing `exec`, not host-app config injection upstream of it.",
		},
		{
			ID:            "CVE-2026-26015 (DocsGPT)",
			Source:        "https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/",
			RealWorld:     "MITM transport-type substitution during MCP connection establishment.",
			WhyOutOfScope: "A connection-establishment / transport-downgrade attack, not a tool-call sequence — there is no InterceptedEvent or SyscallEvent shape that represents 'the transport itself was substituted.'",
		},
		{
			ID:            "MCP registry / marketplace poisoning (OX Security: 9 of 11 tested registries accepted unreviewed submissions)",
			Source:        "https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/",
			RealWorld:     "A malicious MCP server package is published to a public registry and installed by a victim who trusted the listing.",
			WhyOutOfScope: "A supply-chain / distribution-trust problem resolved (or not) before any server ever runs. No runtime sensor — proxy or eBPF — observes a package registry.",
		},
		{
			ID:            "CVE-2026-22785 / CVE-2026-23947 (Orval)",
			Source:        "https://www.endorlabs.com/learn/classic-vulnerabilities-meet-ai-infrastructure-why-mcp-needs-appsec",
			RealWorld:     "OpenAPI `summary` / `x-enumDescriptions` fields inject attacker-controlled content into Orval's generated client code.",
			WhyOutOfScope: "A build-time code-generation vulnerability — the injection happens when a developer runs the generator, not when an agent calls an MCP tool. There is no agent runtime behavior to observe.",
		},
		{
			ID:            "CVE-2025-68144 (mcp-server-git argument injection, file-overwrite variant)",
			Source:        "https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html",
			RealWorld:     "The same git_diff/git_checkout argument-injection primitive used in cve_2025_68143_mcp_git_ssh_credential_exfil, but to overwrite an arbitrary file (e.g. plant a malicious hook) rather than move data out.",
			WhyOutOfScope: "No data leaves the host in this variant, so there is no trifecta shape (sensitive read -> untrusted content -> egress) for an exfiltration-focused detector to apply to. Interlock's threat model is data walking out, not arbitrary file writes / code-persistence — a real, serious bug class, just not this one's.",
		},
		{
			ID:            "CVE-2025-49596 (MCP Inspector)",
			Source:        "https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596",
			RealWorld:     "Anthropic MCP Inspector: no authentication between the Inspector's browser UI and its local stdio proxy, chained with the browser \"0.0.0.0 Day\" bug and a CSRF — visiting a malicious website launches arbitrary stdio commands via the developer's already-running Inspector.",
			WhyOutOfScope: "The attack reaches a local developer tool's unauthenticated proxy endpoint directly from a browser tab — it is not a tool call flowing through an agent's own MCP session at all, and it happens (if it happens) before any session Interlock would be attributing traffic to. Same family as the spawn-time root pattern above in spirit (execution outside the observed session), but via a browser vector rather than an application UI form.",
		},
		{
			ID:            "CVE-2025-58444 (MCP Inspector)",
			Source:        "https://www.sentinelone.com/vulnerability-database/cve-2025-58444/",
			RealWorld:     "Anthropic MCP Inspector: cross-site scripting escalating to RCE when the Inspector connects to an untrusted remote MCP server that supplies a malicious OAuth redirect URI.",
			WhyOutOfScope: "The vulnerable surface is the Inspector's own UI rendering a redirect URI from a server the developer chose to connect to for debugging — a browser-side XSS in a developer tool, not a tool-call sequence an agent's proxy or sensor observes at runtime.",
		},
	}
}
