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

Left pane (seven tabs). **Signals** comes first: the TL;DR rollup of every
anomaly detected across the message, grouped by severity (High / Medium /
Low / Info), each with an evidence excerpt and a "Jump to source →" link
that switches to the relevant tab and highlights the item. "No anomalies
detected" means exactly that — never a verdict of "safe".

- **Details** — headers (From/Sender/To/Cc/timestamps/Return-Path/
  originating IP/rDNS) plus a **Consistency** subsection: Message-ID vs
  From, Reply-To vs From (classic BEC), Return-Path alignment, Sender,
  Date-vs-Received skew and future-dating, each shown as passed (✓) or
  flagged with severity.
- **Authentication** — SPF/DKIM/DMARC as stamped by the receiving MTA,
  on-demand live re-verification, and per-signature **DKIM depth**
  (h= coverage of critical headers, l= body-length limit, t=y test mode,
  SHA-1, canonicalization, expiry; key length via live DNS on demand).
- **URLs** — defanged with copy buttons, anchor-mismatch and
  differs-from-From-domain signals, filters (scheme, domain, dedupe,
  only-with-signals, group-by-domain) and VirusTotal lookups. Microsoft
  SafeLinks, Proofpoint URL Defense, Mimecast and Barracuda wrappers are
  unwrapped locally (nested chains shown), and signals evaluate against
  the real target. Deep inspection flags suspicious TLDs (bundled
  per-release list), URL shorteners, IDN homoglyphs (mixed-script
  hostnames), embedded credentials, IP-as-host, unusual ports, and
  data: URI payloads.
- **Attachments** — MD5/SHA-1/SHA-256, save-to-disk with confirmation,
  VirusTotal by hash, plus content inspection: magic-byte detected type
  vs extension (type mismatch), RTLO filenames with a
  renders-vs-actual-bytes view, double/executable extensions, Office
  macro detection via oletools.olevba (macros / AutoExec / suspicious
  keywords, with a macro-details expander — no macro source rendered
  inline), and PDF anomaly markers (JavaScript, OpenAction, embedded
  files, launch actions).
- **Transmission** — Received chain as an oldest-first timeline; with a
  bundled mmdb (not shipped in v2 builds), each hop gains country and
  ASN/organization context.
- **X-headers** — searchable, full values, no truncation, with a decoded
  **M365 anti-spam panel** for X-Forefront-Antispam-Report (SCL, SFV,
  SFTY, CAT, CTRY, PTR, H …), X-Microsoft-Antispam (BCL), and the
  X-MS-Exchange-Organization-* headers worth decoding.

Right pane (four tabs): **Rendered** (sandboxed iframe, remote content
blocked by default), **HTML** (syntax-highlighted source with search),
**Plaintext**, **Source** (raw message bytes).

Tabs grey out when the underlying data is absent; warning dots appear for
high/medium signals and authentication failures.

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
  urls.py         URL extraction, defanging, IDN, wrappers, deep flags
  sanitize.py     bleach + CSS sanitizer + remote-content blocking
  consistency.py  header-consistency checks (Details + Signals)
  m365.py         X-Forefront-Antispam-Report / M365 header decoding
  attach_inspect.py  magic bytes, filename anomalies, macros, PDF markers
  dkim_depth.py   DKIM h=/l=/t=/x= coverage analysis
  geo.py          optional mmdb-based per-hop country/ASN context
  signals.py      aggregated Signals rollup across all sources
  reverify.py     live SPF (pyspf) / DKIM (dkimpy) / DMARC, 5 s timeouts
  workspace.py    per-launch session dirs under the OS cache dir
  data/           bundled abuse-TLD and shortener lists (per release)
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
- **GeoIP database** is not bundled with v2 builds (decision, 2026-08):
  drop a MaxMind GeoLite2 or DB-IP Lite mmdb (`GeoLite2-City.mmdb` /
  `GeoLite2-ASN.mmdb` or `dbip-*-lite.mmdb`) next to the app's data files
  to enable per-hop country/ASN context — hops render normally without it.
- **PDF anomaly scan** is a local raw+inflated-stream marker scan
  (JavaScript / OpenAction / EmbeddedFile / Launch), since oletools 0.60
  no longer ships `pdfid`.
- Release CI builds both macOS and Windows, but macOS is the tested v1
  target per project decision; the Windows job ships as-is.

See `SECURITY.md` for the sandboxing posture and threat model.
