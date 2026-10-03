# Live evidence tailing (design, not yet built)

Status: `Named` — see [`ROADMAP.md`](ROADMAP.md) §23. No engine code exists for this yet;
this document exists so the design isn't lost, not as evidence of a shipped feature.

## Problem

Today, evidence access is purely file/CLI based: `evidence.jsonl` / `evidence.db`, the
`evidence.json` "latest record" snapshot, `cmd/query-evidence`, and
[`web/viewer.html`](../web/viewer.html) (paste JSON / drag-and-drop a file, or a
pre-embedded `window.EVIDENCE_DATA`). There is no way to watch verdicts arrive as the
proxy runs — you find out after the fact by re-opening a file.

## Design

1. **Broadcaster hooks the existing observer interface, not the sink.**
   `internal/engine/evidence_async.go` already defines
   `EvidenceEmitObserver.OnEvidenceEmitted(rec model.EvidenceRecord)` and
   `AsyncEvidenceSink.SetEmitObserver`, fired once per successful `Emit` — the same funnel
   both the jsonl and sqlite backends go through. An SSE broadcaster is just another
   implementation of that interface, added to the existing `engine.MultiEmitObserver{...}`
   fan-out list built in `attachEmitObservers` (`cmd/interlock/main.go`). No changes to the
   sink, the hash chain, or the write path.
2. **Transport: SSE, not WebSocket.** The stream is one-way (server → browser); the
   `EventSource` client is built into every browser with automatic reconnect, so no client
   library is needed.
3. **Server: extend the existing observability server, don't add one.**
   `internal/observability/server.go` already owns a `net/http` mux gated by
   `ObservabilityConfig.Listen` (empty = disabled) serving `/metrics` and `/healthz`. The
   mux is currently built and discarded inside `Start(...)`; it would need a field/method
   (or a `routes ...func(*http.ServeMux)` param) so `/events` can be registered alongside
   the existing routes — no new listener, no new config key beyond what already exists.
4. **Client: extend `viewer.html`, don't add a page.** The viewer already has a
   `renderList` table (session_id / verdict / pod_name filtering) fed by
   `acceptPayload(data)`. A "Live" toggle opens `new EventSource(url)` and prepends each
   parsed message into that same table — reusing the existing rendering/filtering code
   rather than building a second UI.

## Security note (why "localhost only, no auth" was the answer, not a shortcut)

This is a tool whose entire premise is that secret bytes must not leave a boundary
uncontrolled. Streaming evidence records (`match_where`, payload previews) over HTTP is
exactly the kind of exposure Interlock exists to prevent elsewhere, so if this is ever
built: bind to `127.0.0.1` by default via the same `Listen` config already used for
metrics, and treat "reachable off-box" as a separate, explicitly-requested variant (bind
address + bearer token), not a default.

## Wiring sketch (for whoever picks this up)

- `internal/engine/evidence_async.go` — new `SSEBroadcaster` type implementing
  `EvidenceEmitObserver`; non-blocking fan-out to registered client channels (drop on a
  full channel — a slow browser tab must never back-pressure the proxy).
- `cmd/interlock/main.go` — construct the broadcaster before `attachEmitObservers` (line
  ~346) and `observability.Start` (line ~442) in `runProxyMode`, both already in the same
  function scope; append it to the `MultiEmitObserver{...}` literal at line ~521.
- `internal/observability/server.go` — expose the mux (field + `Handle` method, or extra
  `Start` params) so `/events` can be registered with the same `Content-Type:
  text/event-stream` + flush pattern; no new dependency.
- `web/viewer.html` — "Live" toggle → `EventSource` → prepend into the existing list view.

## Testing (if built)

- Unit test on the broadcaster: register a client channel, emit a record, assert it's
  received; assert a full/slow client channel doesn't block the emit path.
- Manual: `make demo`, open `viewer.html`, enable Live, confirm records stream in as the
  demo runs.
