"""URL extraction from HTML bodies, plaintext bodies, and select headers.

Extracts, defangs, and annotates each URL with two phishing signals:
anchor-text mismatch and domain-differs-from-From-domain.
"""

from __future__ import annotations

import re
from html import unescape
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")
_URL_RE = re.compile(r"""(?:(?:https?|ftp)://|www\.)[^\s<>"'`\)\]]+""", re.IGNORECASE)
_URLISH_RE = re.compile(r"^\s*(?:(?:https?|ftp)://|www\.)\S+\s*$", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?'\")]}"
_DEFANG_SCHEMES = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}
_MAILTO_ADDR_RE = re.compile(r"[\w.+\-']+@[\w.\-]+\.\w+")

PUBLIC_SUFFIX_ROUGH = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "co.kr", "co.in", "co.za", "com.br", "com.mx",
    "com.cn", "com.tw", "com.hk", "com.sg", "co.il",
}


def registrable_domain(host: str | None) -> str | None:
    """Best-effort eTLD+1 without a bundled Public Suffix List.

    Correct for the overwhelming majority of real domains; the small set of
    multi-part public suffixes above is handled specially. A tiny chance of
    over-grouping unknown suffixes is acceptable for a heuristic signal.
    """
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        return host  # IPv6 literal
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in PUBLIC_SUFFIX_ROUGH:
        return ".".join(parts[-3:])
    return last_two


def same_registrable(a: str | None, b: str | None) -> bool:
    ra, rb = registrable_domain(a), registrable_domain(b)
    return bool(ra and rb and ra == rb)


def host_of(url: str) -> str | None:
    try:
        parts = urlsplit(url)
        netloc = parts.netloc or parts.path
        if not netloc or "@" not in netloc and "/" in (parts.path or "") and not parts.netloc:
            return None
        host = netloc.rpartition("@")[2].split(":")[0].strip("[]")
        return host or None
    except ValueError:
        return None


def defang(url: str) -> str:
    """Produce the analyst-shareable form: hxxps://evil[.]com/path."""
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://", url)
    if not m:
        return url
    scheme = m.group(1).lower()
    replaced = _DEFANG_SCHEMES.get(scheme)
    if replaced:
        url = replaced + url[m.end() - 3 :]  # keep "://" onward
    host = host_of(url)
    if host and "." in host and not (host.startswith("[") and host.endswith("]")):
        url = url.replace(host, host.replace(".", "[.]"), 1)
    return url


def idn_forms(domain: str) -> tuple[str, str | None]:
    """Return (decoded display, punycode) — punycode only when they differ."""
    display, puny = domain, None
    try:
        encoded = domain.encode("idna").decode("ascii")
        if encoded != domain:
            puny = encoded
    except (UnicodeError, ValueError):
        pass
    try:
        decoded = domain.encode("ascii").decode("idna")
        if decoded != domain:
            display = decoded
    except (UnicodeError, ValueError):
        pass
    return display, puny


def _norm_candidate(raw: str) -> str:
    url = raw.strip().strip(_TRAILING_PUNCT)
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def _is_url(candidate: str) -> bool:
    if not candidate or len(candidate) > 2048:
        return False
    return "://" in candidate and _SCHEME_RE.match(candidate) is not None


class _LinkExtractor(HTMLParser):
    """Collect hrefs, remote srcs, and the visible text of anchors."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[dict] = []
        self._anchors: list[dict] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a":
            href = (attrs.get("href") or "").strip()
            self._anchors.append({"href": unescape(href) if href else None, "text": []})
            return
        for attr in ("src", "href", "poster", "background", "data"):
            value = (attrs.get(attr) or "").strip()
            if value and _is_url(value):
                self.links.append(
                    {
                        "url": _norm_candidate(unescape(value)),
                        "source": f"html_{attr}",
                        "anchor_text": None,
                    }
                )
                return

    def handle_endtag(self, tag):
        if tag == "a" and self._anchors:
            anchor = self._anchors.pop()
            text = " ".join("".join(anchor["text"]).split())
            if anchor["href"]:
                href = _norm_candidate(anchor["href"])
                if _is_url(href):
                    self.links.append(
                        {
                            "url": href,
                            "source": "html_href",
                            "anchor_text": text or None,
                        }
                    )
            elif text and _URLISH_RE.match(text):
                self.links.append(
                    {"url": _norm_candidate(text), "source": "html_text", "anchor_text": None}
                )

    def handle_data(self, data):
        if self._anchors:
            self._anchors[-1]["text"].append(data)


def extract_from_html(html: str) -> list[dict]:
    """Collect hrefs, remote srcs, and anchor text; phishing signals are
    computed centrally in ``collect_urls`` (against the unwrapped URL)."""
    parser = _LinkExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    out: list[dict] = []
    for link in parser.links:
        if not _is_url(link["url"]):
            continue
        entry = dict(link)
        entry["anchor_mismatch"] = False
        out.append(entry)
    return out


def extract_from_plaintext(text: str) -> list[dict]:
    return [
        {"url": u, "source": "plaintext", "anchor_text": None, "anchor_mismatch": False}
        for u in (_norm_candidate(m.group(0)) for m in _URL_RE.finditer(text))
        if _is_url(u)
    ]


def extract_from_headers(headers: dict[str, str]) -> list[dict]:
    """Reply-To / Return-Path / List-Unsubscribe."""
    out: list[dict] = []
    for name, source in (
        ("reply-to", "header:Reply-To"),
        ("return-path", "header:Return-Path"),
    ):
        value = headers.get(name, "")
        if value:
            m = _MAILTO_ADDR_RE.search(value)
            if m:
                out.append(
                    {
                        "url": "mailto:" + m.group(0),
                        "source": source,
                        "anchor_text": None,
                        "anchor_mismatch": False,
                    }
                )
    for m in re.finditer(r"<(https?://[^>\s]+)>", headers.get("list-unsubscribe", "")):
        out.append(
            {
                "url": m.group(1),
                "source": "header:List-Unsubscribe",
                "anchor_text": None,
                "anchor_mismatch": False,
            }
        )
    return out


def _domain_of(url: str) -> str | None:
    if url.startswith("mailto:"):
        m = _MAILTO_ADDR_RE.search(url)
        if m:
            return m.group(0).rpartition("@")[2]
        return None
    return host_of(url)


# Microsoft SafeLinks wraps the real destination in a tracking URL:
#   https://eur06.safelinks.protection.outlook.com/?url=<encoded>&data=…&sdata=…
# The real target is recoverable by decoding the ``url`` query parameter —
# purely local string work, no network involved.
_SAFELINKS_HOST = re.compile(
    r"^(?:[a-z0-9-]+\.)?safelinks\.protection\.outlook\.com$", re.IGNORECASE
)


def unwrap_safelinks(url: str) -> str | None:
    """Return the encoded target of a SafeLinks URL, or None."""
    host = host_of(url)
    if not host or not _SAFELINKS_HOST.match(host):
        return None
    try:
        query = parse_qs(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return None
    target = (query.get("url") or [""])[0].strip()
    if not re.match(r"^https?://", target, re.IGNORECASE):
        return None
    return target


def collect_urls(
    html: str | None,
    plaintext: str | None,
    headers: dict[str, str],
    from_domain: str | None,
) -> list[dict]:
    """Merge all sources, dedupe, and annotate with defanged form + signals."""
    merged: list[dict] = []
    if html:
        merged += extract_from_html(html)
    if plaintext:
        merged += extract_from_plaintext(plaintext)
    merged += extract_from_headers(headers)

    seen: set[str] = set()
    out: list[dict] = []
    for entry in merged:
        key = entry["url"].rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        unwrapped = unwrap_safelinks(entry["url"])
        effective = unwrapped or entry["url"]
        domain = _domain_of(effective)
        is_mailto = effective.startswith("mailto:")

        # Anchor mismatch is evaluated against the effective (unwrapped)
        # target: SafeLinks makes every href host differ from its anchor
        # text, which would otherwise flag every rewritten link.
        mismatch = False
        anchor = entry.get("anchor_text")
        if anchor and _URLISH_RE.match(anchor):
            anchor_url = _norm_candidate(anchor)
            h1, h2 = host_of(effective), host_of(anchor_url)
            mismatch = bool(h1 and h2 and h1.lower() != h2.lower())

        out.append(
            {
                "url": entry["url"],
                "defanged": defang(entry["url"]),
                "unwrapped": unwrapped,
                "unwrapped_defanged": defang(unwrapped) if unwrapped else None,
                "domain": domain,
                "source": entry["source"],
                "anchor_text": entry.get("anchor_text"),
                "anchor_mismatch": mismatch,
                "differs_from_from_domain": bool(
                    domain and from_domain and not is_mailto
                    and not same_registrable(domain, from_domain)
                ),
            }
        )
    return out
