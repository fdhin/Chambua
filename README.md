# Chambua

**Chambua** is Swahili for *to analyze* — and that is exactly what this tool
does. It is a local, single-user desktop tool for security analysts to
inspect suspicious email messages one at a time. Drop a message (or several)
onto the app, and it parses and presents a two-pane inspector: metadata and
analysis on the left, rendered content and raw source on the right.

*(The project was built under the working title "Mail Analysis Workbench";
the original build brief is preserved in `mail-workbench-spec.md`.)*

**Nothing leaves the machine.** The only outbound requests the app can ever
make are ones you explicitly trigger: a "Re-verify now" live DNS check, a
"Load remote content" opt-in, or a VirusTotal link-out that opens in your
browser.

## What it accepts

- `.eml` — RFC 5322 MIME (what M365 Defender's "Download email" produces)
- `.msg` — Outlook OLE compound files, modern (Unicode) and legacy (ANSI)
- `.zip` — extracted once; password-protected archives retry with the
  sandbox-convention password `infected`. Nested archives are *not* recursed.

Multiple files can be dropped at once; each becomes an independent record in
the session list.

## Install

### macOS (primary target)

Download `chambua-<version>-macos`, then:

```sh
chmod +x chambua-<version>-macos
xattr -d com.apple.quarantine chambua-<version>-macos
./chambua-<version>-macos
```

The binary is **unsigned** (internal tool; no Apple Developer notarization),
so macOS Gatekeeper will complain on first run. Either run the `xattr` command
above, or right-click → Open → Open. This is expected and unavoidable without
a signing certificate. A console window appears alongside the browser tab;
that window shows the server log — close either to quit, or use the **Quit
app** button in the UI header.

### Windows

Download `chambua-<version>-windows-x64.exe` and double-click. First
run may show a SmartScreen warning — click **More info** → **Run anyway**
(the binary is unsigned). A console window appears with the log; the UI opens
in your default browser at `http://127.0.0.1:<random-port>/`.

First launch takes 2–4 seconds (the onefile bootloader unpacks to a temp
directory). Binary size is 40–80 MB.

## The inspector

Left pane (six tabs): **Details** (headers: From/Sender/To/Cc/timestamps/
Return-Path/originating IP/rDNS), **Authentication** (SPF/DKIM/DMARC as
stamped by the receiving MTA, with on-demand live re-verification), **URLs**
(defanged, with anchor-mismatch and differs-from-From-domain signals, filters
and VirusTotal lookups), **Attachments** (MD5/SHA-1/SHA-256, save-to-disk
with confirmation, VirusTotal by hash), **Transmission** (Received chain as
an oldest-first timeline), **X-headers** (searchable, full values, no
truncation).

Right pane (four tabs): **Rendered** (sandboxed iframe, remote content
blocked by default), **HTML** (syntax-highlighted source with search),
**Plaintext**, **Source** (raw message bytes).

Tabs grey out when the underlying data is absent; warning dots appear for
authentication failures (red = hard fail, yellow = neutral/soft signals).

## Running from source

```sh
python3.12 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt  # or: pip install -e ".[dev]"
python -m pytest tests/ -q       # 55 tests against the fixtures
python -m chambua                # opens the UI in your browser
```

Also installable as a console script: `pip install .` → `chambua`.

Developer flags: `--keep-workspace` (leave the session directory on disk for
debugging), `--no-browser` (don't auto-open the browser).

## Building the binaries

PyInstaller onefile, one binary per OS (you cannot cross-compile):

```sh
pip install -r requirements.txt   # includes pyinstaller
pyinstaller chambua.spec          # produces dist/chambua
```

Releases are built by `.github/workflows/release.yml` on `v*` tag push, with
a matrix on `macos-latest` (primary) and `windows-latest`, attaching
`chambua-<version>-<os>` artifacts and SHA-256 sums to a GitHub Release.

Fixtures for the test suite are generated deterministically:
`python tests/fixtures/generate_fixtures.py` (the generated files are
committed; re-run after editing the generator).

## Architecture

```
chambua/
  __main__.py     entry point: bind 127.0.0.1:0, open browser, wipe on exit
  server.py       FastAPI app, CSRF, Host-header check, CSP
  ingest.py       extension routing, zip handling, failure surfacing
  parse_eml.py    RFC 5322 → normalized parsed.json schema
  parse_msg.py    extract-msg (.msg) → same schema
  authresults.py  Authentication-Results (RFC 8601) parsing
  received.py     Received-chain → transmission timeline
  urls.py         URL extraction, defanging, IDN, phishing signals
  sanitize.py     bleach + CSS sanitizer + remote-content blocking
  reverify.py     live SPF (pyspf) / DKIM (dkimpy) / DMARC, 5 s timeouts
  workspace.py    per-launch session dirs under the OS cache dir
  static/         vanilla HTML/CSS/JS frontend (no build step)
```

Session state lives under `platformdirs.user_cache_dir("chambua")/
session-<pid>/` and is wiped on graceful shutdown; orphans older than 24 h
are cleaned on next launch.

## Documented deviations from the brief

- **Name:** the brief's "Mail Analysis Workbench" shipped as **Chambua**.
- **DMARC re-verify** uses `dnspython` directly (fetch `_dmarc` TXT +
  relaxed alignment + policy) rather than `checkdmarc`'s domain-health API,
  which evaluates whole domains rather than this message's alignment.
  `checkdmarc` remains pinned in the dependency set.
- Release CI builds both macOS and Windows, but macOS is the tested v1
  target per project decision; the Windows job ships as-is.

See `SECURITY.md` for the sandboxing posture and threat model.
