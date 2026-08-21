# Security posture

## Threat model

- **Hostile input:** every message, attachment, and archive handed to this
  tool should be assumed attacker-controlled and crafted to escape analysis.
- **Benign local user:** the person at the keyboard is trusted; there is no
  multi-user or remote-access surface.
- **No persistence of attacker data beyond the session**, except when the
  analyst explicitly saves an attachment to disk.

The tool never fetches mail, never detonates attachments, and never sends
message content anywhere. The three deliberate exceptions, each behind an
explicit user action and logged to stderr:

1. **Re-verify now** (SPF/DKIM/DMARC) performs live DNS queries.
2. **Load remote content** re-renders one record with remote resources
   enabled, for the current session only.
3. **VirusTotal links** open in the default browser (link-out only; no API
   key, no automated lookups, no upload).

## Controls

**Rendering.** The HTML body is rendered inside `<iframe sandbox=""
referrerpolicy="no-referrer">` loaded via `srcdoc`: no scripts, no forms,
no popups, no top-level navigation, no same-origin access. On top of the
sandbox, bodies are sanitized with bleach (scripts, `on*` handlers,
`javascript:` URLs, `meta refresh`, and non-visual CSS all dropped) before
rendering.

**Remote content blocked by default.** `src`/`poster`/`background`
attributes and CSS `url(...)`/`@import` are rewritten to a local 1×1 data:
GIF before rendering, so the Rendered tab makes zero network requests until
the analyst clicks *Load remote content* (per record, per session, logged).

**Attachment handling.** Attachments are written to the session workspace
by SHA-256 (never by attacker-supplied filename), hashed (MD5/SHA-1/
SHA-256), and never executed, opened, or recursively extracted. Archives
embedded as attachments (RAR/7z/ZIP-in-ZIP) are flagged, not detonated.
Zip extraction is capped (200 MB per member, 500 MB per archive) to blunt
zip bombs, and never recurses more than one level.

**v2 content inspection is parse-only.** Office macro detection runs
oletools.olevba over the stored bytes — it parses VBA storage, never
executes anything, and macro source code is deliberately not rendered in
the UI (findings only). PDF anomaly markers are read from raw and
zlib-inflated streams. Magic-byte sniffing is pure byte-prefix matching.
URL unwrapping (SafeLinks, Proofpoint, Mimecast, Barracuda) is local
string decoding — the wrapper's redirect target is never fetched.
Suspicious-TLD and shortener lists are bundled static files refreshed per
release; the app never fetches list updates. GeoIP, when an mmdb is
present, is a local file lookup with no network. The only outbound
requests in v2 remain: live Re-verify DNS (on click), DKIM key-length
lookup (on click), Load-remote-content opt-in (on click), and VirusTotal
link-outs (opened in the user's browser).

**Network.** The HTTP server binds `127.0.0.1` only — never `0.0.0.0`, on
an OS-assigned port. Requests with a `Host` header other than
`127.0.0.1:<port>` / `localhost:<port>` are rejected (DNS-rebinding
defense). Every state-changing endpoint requires a per-session CSRF
synchronizer token. A restrictive CSP (`script-src 'self'`, no `object-src`,
`form-action 'none'`, images from `self` and `data:` only) covers both the
app shell and the sandboxed `srcdoc` pane.

**Workspace.** Per-launch directory under the OS cache dir; wiped on
graceful shutdown via `atexit` (SIGINT/SIGTERM unwind through uvicorn's
graceful exit). Workspaces orphaned by crashes or `kill -9` are removed on
next startup once older than 24 hours. `--keep-workspace` exists for
debugging.

**Downgrade path.** If sanitization and the sandbox both fail open due to a
browser bug, the CSP is the third layer; if all three fail, the iframe still
has no same-origin access to the app (unique origin, no network origin of
its own via `srcdoc`).

## Reporting

Internal tool — file an issue in the repository. Include the fixture
(redacted as needed) that triggered the problem.
