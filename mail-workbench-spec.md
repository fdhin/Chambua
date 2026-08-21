# Mail Analysis Workbench — Build Agent Brief

## 1. What you are building

A local desktop-class tool for a security analyst to inspect suspicious email messages one at a time. The user drops a message (or several) onto the app, the app parses it, and presents a two-pane inspector: metadata and analysis on the left, rendered content and source on the right. The reference UI is Sublime Security's message inspector — screenshots are attached to this brief and should be treated as the visual specification. Match the layout, tab structure, and information density.

The tool runs **locally**. No message data leaves the machine unless the user explicitly clicks a link that opens an external service in the browser (see §9).

**Distribution shape:** a single double-clickable binary per operating system. No Python installation required on the target machine, no venv, no pip. See §3 and §12.

## 2. Non-goals

Be strict about what this is not, because scope creep on analysis tools is a killer:

- **Not a triage system.** No case state, no verdicts, no notes, no "Resolve" workflow, no queue, no user accounts. The Sublime "Resolve" button in the screenshots does not exist in this tool. This is a viewer.
- **Not a mail server.** Does not fetch mail. Does not connect to IMAP/EWS/Graph. The only input is a file the user hands it.
- **Not a sandbox / detonator.** Does not execute attachments, does not fetch remote resources by default, does not run macros.
- **Not multi-user.** Single local user, single machine.
- **Not persistent by design.** State is per-session unless §5 says otherwise.

## 3. Tech stack

**Language:** Python 3.11+ (3.12 preferred).

**Runtime dependencies — all pure Python or wheels available for both Windows and macOS:**

| Purpose | Library |
|---|---|
| HTTP server | `fastapi` + `uvicorn[standard]` |
| `.msg` parsing | `extract-msg` |
| `.eml` parsing | stdlib `email` |
| AES-encrypted zips | `pyzipper` (stdlib `zipfile` cannot decrypt) |
| SPF verification | `pyspf` |
| DKIM verification | `dkimpy` |
| DMARC evaluation | `checkdmarc` |
| DNS | `dnspython` |
| HTML sanitization | `bleach` |
| Browser launch | stdlib `webbrowser` |

Pin exact versions in `requirements.txt` (or `pyproject.toml` with a lockfile). No compiled C extensions beyond what these libraries already vendor as wheels — this matters for PyInstaller.

**Frontend:** vanilla HTML + CSS + a small amount of JS. No framework. No build step. Served by FastAPI from an `app/static/` directory that gets bundled into the binary via PyInstaller's `--add-data`. At runtime, resolve the static-file directory via `sys._MEIPASS` when frozen and via `__file__` when running from source — this is the standard PyInstaller pattern and the build agent must not skip it, or the frozen binary will 404 on all assets.

**Local server:**

- Bind `127.0.0.1` on a random free port (let the OS pick via port 0, read the assigned port back).
- On startup, print the URL to stderr and open the user's default browser via `webbrowser.open(url)`.
- The browser tab is the UI. There is no separate window.

**Packaging:** **PyInstaller onefile mode**, one binary per OS.

- Windows target: `mail-workbench.exe` (Windows 10+, x64).
- macOS target: `mail-workbench` (universal2 if feasible; otherwise x86_64 and arm64 as two artifacts).
- Build via GitHub Actions with a matrix on `windows-latest` and `macos-latest` — you cannot cross-compile PyInstaller. Both jobs run `pyinstaller mail-workbench.spec` against the same source tree.
- Expected binary size: 40-80 MB per OS. Acceptable.
- Expected first-launch time: 2-4 seconds (PyInstaller bootloader unpacks to a temp dir). Acceptable for this workflow.

The build agent should not attempt Nuitka, py2app, py2exe, or Briefcase without cause. PyInstaller is the default and works for this dependency set.

## 4. Ingest pipeline

### 4.1 Accepted inputs

At the drop zone, the app accepts:

- `.msg` — Outlook compound OLE format
- `.eml` — RFC 5322 MIME (this is what M365 Defender's "Download email" produces)
- `.zip` — must be extracted once, contents routed back through ingest

Any other extension: show inline error "Unsupported file type: `<ext>`. Accepted: .msg, .eml, .zip" and skip. Do not attempt to guess by magic bytes for the first pass — extension is the contract.

### 4.2 Multi-drop

Multiple files may be dropped at once. Each becomes an independent analysis record. Show a session-scoped list of loaded messages in a sidebar or top bar so the user can switch between them. This list is the equivalent of the reference "Manual Uploads" table, minus the persistence and the columns that don't apply (Resolution, Classification, Uploaded by).

### 4.3 Zip handling

1. Try to open the zip with no password.
2. If it is password-protected, retry once with the password `infected` (industry sandbox convention).
3. If that also fails, mark the zip as `password-protected, unknown password` and skip its contents. Do not prompt the user for a password — out of scope.
4. **Single level only.** A zip inside a zip is not recursed. The inner zip appears as an extracted file and is flagged `nested archive — not extracted`.
5. Zip contents are routed back through §4.1. A zip containing three `.msg` files produces three analysis records, not one.
6. A zip containing files of unsupported types produces those as skipped-with-reason entries, not analysis records.

Use `pyzipper` for all zip operations — it handles both plain and AES-encrypted zips with the same API.

### 4.4 Attachment archives (RAR, 7z, nested zip)

Do **not** extract. Hash and display metadata only. Rationale: the user asked for one zip level at ingest; extending recursion into attachment archives without being asked is scope creep, and detonating attacker-controlled archives is exactly what analysts want to avoid.

### 4.5 Failure modes

Every ingest failure produces a visible record with the filename, the failure reason, and a `retry` affordance. Silent failures are forbidden. Log to stderr with structured fields (`{filename, stage, error}`) for later debugging.

## 5. Data model & persistence

Per-launch workspace at `<platformdirs.user_cache_dir("mail-workbench")>/session-<pid>/`. Use `platformdirs` rather than `$TMPDIR` so behaviour is predictable across OSes and doesn't collide with PyInstaller's own `_MEIxxxxxx` extraction temp dir.

One subdirectory per analysis record:

```
<cache-dir>/session-<pid>/
  <record-uuid>/
    original.<ext>       # exact bytes as dropped
    parsed.json          # normalized parse output (see below)
    attachments/
      <sha256>.bin       # each attachment written by SHA-256, not filename
      manifest.json      # filename ↔ sha256 map, plus MD5/SHA-1
    rendered.html        # sanitized HTML body for the iframe
    plaintext.txt        # text/plain part if present
```

Workspace is wiped on graceful shutdown (register with `atexit` and also handle `SIGINT`/`SIGTERM`). On startup, delete any orphaned `session-*` directories older than 24 hours to clean up after `kill -9` / force-quit / crashes.

Provide a `--keep-workspace` flag for debugging.

Attachments are stored by hash, not by attacker-supplied filename, to avoid path traversal, name collisions, and filesystem sensitivities to weird bytes.

### 5.1 `parsed.json` shape (target schema)

```jsonc
{
  "record_id": "uuid",
  "source_file": "RFQ_17112022.eml",
  "source_kind": "eml | msg",
  "extracted_from_zip": "phishing.zip | null",

  "details": {
    "from": { "address": "...", "display_name": "..." },
    "sender": "... | null",
    "to": ["..."],
    "cc": ["..."],
    "reply_to": "... | null",
    "in_reply_to": "... | null",
    "message_id": "...",
    "timestamp": "ISO-8601",
    "return_path": "... | null",
    "originating_ip": "... | null",
    "rdns": "... | null",
    "subject": "..."
  },

  "authentication": {
    "spf":   { "result": "pass|fail|neutral|softfail|none|temperror|permerror",
               "originating_ip": "...", "rdns": "...", "return_path_domain": "...", "record": "..." },
    "dkim":  { "result": "pass|fail|neutral|none",
               "signatures": [ { "selector": "...", "signing_domain": "...",
                                 "algorithm": "...", "verification": "..." } ] },
    "dmarc": { "result": "pass|fail|none",
               "from_domain": "...", "record": "..." }
  },

  "urls": [
    { "url": "http://...", "defanged": "hxxp://...[.]com",
      "domain": "...", "source": "html_href|html_src|plaintext|header:<name>",
      "anchor_text": "... | null",
      "anchor_mismatch": true|false,
      "differs_from_from_domain": true|false }
  ],

  "attachments": [
    { "filename": "...", "size_bytes": 123, "mime_type": "...",
      "extension": "...", "md5": "...", "sha1": "...", "sha256": "...",
      "is_archive": true|false, "notes": "nested archive — not extracted | ..." }
  ],

  "transmission": [
    { "hop": 1, "timestamp": "ISO-8601",
      "received_from": { "host": "...", "ip": "..." },
      "received_by":   { "host": "...", "ip": "..." },
      "protocol": "...", "tls": "...", "with": "...",
      "raw": "<exact Received: header line>" }
  ],

  "x_headers": [ { "name": "x-...", "value": "..." } ],

  "content": {
    "has_html": true|false,
    "has_plaintext": true|false,
    "html_path": "rendered.html",
    "plaintext_path": "plaintext.txt",
    "raw_source_path": "original.<ext>"
  }
}
```

This schema is the contract. The UI reads it. If a field is unavailable, use `null`, not an empty string, and do not omit the key.

## 6. UI specification

### 6.1 Overall layout

Two panes, roughly 40/60 split, resizable divider. Header bar at top with the message subject, a permalink icon (copies a `record://<uuid>` link that opens this record in the current session — no external routing), and a session-scoped file list toggle. **No "Resolve" button.**

Left pane has six tabs: **Details**, **Authentication**, **URLs**, **Attachments**, **Transmission**, **X-headers**.
Right pane has four tabs: **Rendered**, **HTML**, **Plaintext**, **Source**.

A tab is disabled (greyed) when the underlying data is absent (no HTML → HTML + Rendered disabled, no attachments → tab shows "No attachments" empty state rather than being hidden — hidden tabs make users think the feature is broken).

Tabs with warning conditions (e.g. DKIM neutral, SPF fail) show a coloured dot next to the label as in the reference UI: red for hard fail, yellow for neutral/soft, no dot for pass or N/A.

### 6.2 Left pane

**Details tab.** Two-column key/value grid. Fields in this order: From (with display name below as its own row), Sender, To, Cc, In-Reply-To, Timestamp, Reply-To, Message-ID, Return-Path, Originating IP, rDNS. Match the reference visual exactly.

**Authentication tab.** Three stacked sections (SPF, DKIM, DMARC), each with a status pill (PASS green, FAIL red, NEUTRAL red-orange, NONE grey). Fields per the reference screenshots:

- SPF: Originating IP, rDNS, Return-Path domain, SPF record.
- DKIM: Verification(s) summary line ("1 Signature — 1 NEUTRAL"), then per-signature: Selector, Signing domain, Algorithm, Verification.
- DMARC: From domain, DMARC record.

**Source of authentication data.** Parse the message's own `Authentication-Results` header (this is what the receiving MTA actually decided at delivery time, which is what an analyst usually wants). Do **not** re-verify live by default — DKIM keys rotate, the tool would need DNS egress, and the point of this app is to show what happened, not what would happen now. Add a small "Re-verify now" button per section that runs a live check on demand, clearly labelled with its timestamp. If `Authentication-Results` is absent, show "Not stamped by receiver — run Re-verify to check now" rather than fabricating results.

**URLs tab.** Filters dropdown (schemes, domain contains, dedupe on/off), then a list. Extraction sources: HTML `href` and `src`, plaintext body via a URL regex, and these headers: `Reply-To`, `Return-Path`, `List-Unsubscribe`. Per entry show: raw URL, defanged copy (one-click copy button), domain, source (where in the message it came from), and two phishing signals — **anchor-text mismatch** (visible link text is a different URL than the href) and **domain differs from From domain**. Include a "Look up on VirusTotal" link (see §9).

**Attachments tab.** Numbered list. Per attachment: File name, File size (human-readable, e.g. "513.90 KB"), File type (uppercase, e.g. "RAR"), MD5, SHA-1, SHA-256. Include a "Look up on VirusTotal" link per attachment. For archive-type attachments, add a note "nested archive — not extracted" per §4.4. Provide a "Save to disk" button that writes the file to a user-chosen path (default: `~/Downloads/`), with a confirmation dialog warning "This file came from a suspect message. Save anyway?".

**Transmission tab.** Vertical timeline matching the reference. One card per `Received:` hop, ordered **oldest → newest** (opposite of the raw header order, which is bottom-up). Per hop: hop number, timestamp, "Received from" line (host + IP), "Received by" line (host + IP), a `More ▾` expander (protocol, TLS cipher, id, `with` clause, any `for` clause), and a `Show raw ▾` toggle that reveals the exact `Received:` header line. Terminal node labeled "Recipient mailbox" with the delivery timestamp. Info tooltip (ⓘ) at top-right briefly explains the ordering inversion.

**X-headers tab.** Search box at top with live filtering across name and value. Result count and Clear link on the right. Below: two-column key/value list of every header starting with `X-` (case-insensitive), preserving original casing in display. Long values wrap. No truncation — analysts need the whole `X-Microsoft-Antispam-Message-Info` blob.

### 6.3 Right pane

**Rendered tab.** The HTML body rendered inside a **sandboxed iframe** — see §7.

**HTML tab.** Syntax-highlighted HTML source with line numbers, a search box, and a copy-all button.

**Plaintext tab.** `text/plain` part, monospace, preserving whitespace. Search box. Copy-all.

**Source tab.** Full raw MIME source with line numbers and a search box, matching the reference. This is the whole message including headers and MIME boundaries — copy-pasted straight from disk.

## 7. Security posture

Non-negotiable. This tool eats hostile input.

- **Rendered iframe** uses `sandbox=""` (empty attribute — maximally restrictive: no scripts, no forms, no top-level navigation, no popups, no same-origin). Set `referrerpolicy="no-referrer"`. Load via `srcdoc` so the iframe never has a network origin of its own.
- **Remote content blocked by default.** Rewrite `src=` attributes on `<img>`, `<video>`, `<audio>`, `<iframe>`, `<script>`, `<link rel="stylesheet">`, and CSS `url(...)` references to a local `about:blank` or a 1×1 placeholder. Do the same for `background` and `poster` attributes. Show a banner on the Rendered tab: "Remote content blocked. [Load remote content]". The button, when clicked, restores the original HTML for that record only, in the current session only, and logs an entry to stderr — no persistent opt-in.
- **HTML sanitization for rendering** via `bleach` with a permissive-but-safe tag list: strip `<script>`, event handlers (`on*`), `javascript:` URLs, and `<meta http-equiv="refresh">`. The unsanitized HTML remains available on the HTML tab as source text (not rendered).
- **Attachment extraction never executes.** Files are written to disk and hashed; nothing is opened, unpacked further, or previewed as anything other than raw bytes / hex.
- **HTTP server binds `127.0.0.1` only.** Never `0.0.0.0`. Never a LAN interface. Reject requests with a `Host` header that isn't `127.0.0.1:<port>` or `localhost:<port>` to defuse DNS rebinding.
- **CSRF token** on every state-changing endpoint (there aren't many — ingest, delete-record, save-attachment, re-verify). Simple synchroniser token per session is fine.

## 8. Auth verification details

When the user clicks "Re-verify now":

- **SPF:** evaluate the SPF record for the Return-Path domain against the originating IP. Use `pyspf`.
- **DKIM:** re-verify each signature against the current DNS TXT record at `<selector>._domainkey.<signing-domain>`. Use `dkimpy`. Note in the UI when the current key does not match the signature — this is common weeks later and is not necessarily a sign of forgery.
- **DMARC:** fetch the `_dmarc.<from-domain>` record and evaluate alignment. Use `checkdmarc`.

All three run in parallel with a 5-second timeout each. Show partial results if some time out. Live results are labelled with the wall-clock time they were fetched.

## 9. External integrations

**VirusTotal — link-out only.** No API key. No automated lookups. For each URL and each attachment, render a `Look up on VirusTotal` link:

- URLs → `https://www.virustotal.com/gui/search/<url-encoded-url>`
- Attachments → `https://www.virustotal.com/gui/file/<sha256>`

The link opens in the user's default browser. That is the entire integration. Do not show a "Configure" affordance for a key the user has said they will never provide.

## 10. Sample edge cases the build agent must handle

Include fixtures in a `tests/fixtures/` directory covering:

- `.eml` with only `text/plain`
- `.eml` with only `text/html`
- `.eml` with both parts (multipart/alternative)
- `.msg` from modern Outlook (Unicode)
- `.msg` from a very old Outlook (ANSI codepage)
- `.eml` with an attached `.eml` (forwarded phish — the inner should still be viewable but is out of scope for auto-recursion; render as an attachment with the standard hash card)
- `.zip` with password `infected`
- `.zip` with a different password (must fail cleanly)
- `.zip` containing another `.zip` (nested case — inner is not extracted)
- `.zip` containing a `.msg`, an `.eml`, and a `.pdf` (mixed — first two ingested, third skipped)
- `.eml` with no `Authentication-Results` header
- `.eml` with multiple DKIM signatures (some pass, some neutral)
- `.eml` with international / IDN domains (punycode display and decoded display side by side)
- `.eml` with a HTML body containing an `<img>` with a tracking pixel `src`
- `.eml` with anchor-mismatch phishing (`<a href="http://evil.com">https://microsoft.com</a>`)
- Malformed `.eml` (truncated MIME boundary — must fail gracefully with a visible error, must not crash the app)

## 11. Acceptance criteria

The build is done when:

1. Dragging any of the fixtures onto the drop zone produces the correct analysis record with no console errors.
2. All six left-pane tabs and all four right-pane tabs render correctly for each fixture, with proper disabling of tabs whose data is absent.
3. The Rendered tab does not make a single outbound network request without the user explicitly clicking "Load remote content" (verify with Wireshark, tcpdump, or the browser's Network tab).
4. The app binds only `127.0.0.1` (verify with `netstat -an` on Windows, `lsof -iTCP -sTCP:LISTEN` on macOS).
5. Dropping ten files at once produces ten records; UI remains responsive during ingest.
6. Graceful shutdown (closing the browser tab does **not** count as graceful — provide either a tray icon "Quit" option or a `/shutdown` endpoint bound to `127.0.0.1` and a small "Quit app" button in the UI header) wipes the workspace. Force-kill leaves the workspace behind; the next launch cleans up orphaned workspaces older than 24 hours on startup.
7. All hashes match `sha256sum` / `certutil -hashfile ... SHA256` computed independently on the attachment bytes.
8. The Transmission tab's hop order matches manual reading of the `Received:` chain.
9. `Authentication-Results` parsing matches what the header says for all fixtures; "Re-verify now" runs live and returns results within 5 seconds or a timeout notice.
10. No test fixture causes the app to hang, crash, or write outside its cache workspace.
11. **Frozen-binary launch test.** The PyInstaller-built binary launches on a clean Windows 10 or 11 machine with **no Python installed**, and on a clean macOS 13+ machine with **no Python installed**, opens the browser to the correct URL, and passes criteria 1-10 above. This is the acceptance test that fails most often — run it early, not last.
12. **Static asset loading in frozen mode.** All CSS, JS, and images in `app/static/` resolve correctly when the binary is run from a directory other than its own location (i.e. `cd /tmp && /path/to/mail-workbench.exe` works). This catches the `sys._MEIPASS` mistake.

## 12. Delivery expectations

- A single git repository.
- `pyproject.toml` with pinned dependencies and a `[project.scripts]` entry point (`mail-workbench = "mail_workbench.__main__:main"`) so it also runs via `pipx install .` for developers.
- `mail-workbench.spec` — the PyInstaller spec file, checked in, so builds are reproducible. Do not generate it fresh in CI.
- **GitHub Actions workflow** at `.github/workflows/release.yml` with a matrix on `windows-latest` and `macos-latest`. On tag push (`v*`), each job runs `pyinstaller mail-workbench.spec`, uploads the artifact, and attaches all artifacts to a GitHub Release. Roughly 50-80 lines of YAML.
- Release artifacts:
  - `mail-workbench-<version>-windows-x64.exe`
  - `mail-workbench-<version>-macos-universal2` (or separate `-x86_64` / `-arm64` binaries if universal2 build proves flaky)
- `README.md` with:
  - Windows install: download the `.exe`, double-click. First run may show a SmartScreen warning — click "More info" → "Run anyway".
  - macOS install: download the binary, `chmod +x`, first run needs `xattr -d com.apple.quarantine mail-workbench` or right-click → Open → Open. Because the binary is unsigned, macOS will complain. This is expected and documented.
  - One screenshot per tab.
- Tests runnable via `pytest`, hitting the fixtures listed in §10.
- `SECURITY.md` documenting the sandboxing posture in §7 and the threat model (hostile message content, benign local user).

## 13. What to ask before starting

If any of the following are unclear, ask before writing code. Do not guess:

- **Platforms in scope for v1** — Windows only, or Windows + macOS from day one? Affects CI matrix and whether the macOS-specific quarantine/signing rough edges need documentation immediately.
- **macOS signing** — ship unsigned with the `xattr` workaround documented, or set up Apple Developer notarization ($99/year, added CI complexity)? Default assumption is unsigned for internal use.
- **UI language** — Danish or English? Screenshots are English; assume English unless told otherwise.
- **Visual fidelity to Sublime reference** — pixel-strict colour/spacing match, or structurally faithful with sensible defaults? Default assumption is structurally faithful.

Everything else in this brief is settled.
