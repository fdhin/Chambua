"""Parse RFC 5321 ``Received:`` trace headers into structured hop data.

The raw header order is bottom-up (newest first). ``parse_transmission``
returns hops ordered oldest → newest for the timeline UI.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

_NOSUCHHOST = re.compile(r"\bnosuchhost\b", re.IGNORECASE)


def _split_tokens(body: str) -> list[str]:
    """Split a Received clause on whitespace, keeping (parenthesised) groups."""
    tokens: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in body:
        if ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch.isspace() and depth == 0:
            if cur:
                tokens.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        tokens.append("".join(cur))
    return tokens


def _strip_quotes(token: str) -> str:
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1]
    return token


def _extract_ip(tokens: list[str], start: int) -> tuple[str | None, str | None]:
    """From the tokens after ``from HOST`` / ``by HOST``, pull the host's
    claimed rDNS name and any IP literal found in parenthesised comments."""
    rdns: str | None = None
    ip: str | None = None
    for tok in tokens[start:]:
        inner = tok.strip("()[]")
        if not inner:
            continue
        for piece in re.findall(r"[^\s\[\]()]+", inner):
            try:
                ipaddress.ip_address(piece)
                if ip is None:
                    ip = piece
                continue
            except ValueError:
                pass
            if rdns is None and "." in piece and not piece[0].isdigit():
                rdns = piece
    return ip, rdns


def parse_received(value: str, hop: int) -> dict:
    """Structure one ``Received:`` header value."""
    raw = value.strip()
    body, timestamp = raw, None
    idx = raw.rfind(";")
    if idx != -1:
        date_part = raw[idx + 1 :].strip()
        body = raw[:idx]
        try:
            ts = parsedate_to_datetime(date_part)
            if ts is not None:
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                timestamp = ts.isoformat()
        except (TypeError, ValueError, IndexError):
            timestamp = None

    tokens = _split_tokens(body)
    KEYWORDS = {"from", "by", "with", "id", "for"}
    received_from = {"host": None, "ip": None, "rdns": None}
    received_by = {"host": None, "ip": None, "rdns": None}
    protocol = None
    with_ = None
    ident = None
    for_addr = None
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        lower = tok.lower()
        if lower in ("from", "by"):
            # The host token follows; parenthesised comments may precede it.
            j = i + 1
            while j < len(tokens) and tokens[j].startswith("("):
                j += 1
            if j < len(tokens):
                host = _strip_quotes(tokens[j]).strip("[]()")
                if lower == "from":
                    received_from["host"] = host or None
                    ip, rdns = _extract_ip(tokens, i + 1)
                    received_from["ip"] = ip
                    received_from["rdns"] = rdns
                else:
                    received_by["host"] = host or None
                    ip, rdns = _extract_ip(tokens, i + 1)
                    received_by["ip"] = ip
                    received_by["rdns"] = rdns
                i = j + 1
                continue
        elif lower == "with":
            j = i + 1
            span: list[str] = []
            while j < len(tokens) and tokens[j].lower() not in KEYWORDS:
                span.append(_strip_quotes(tokens[j]))
                j += 1
            if span:
                protocol = span[0]
                with_ = " ".join(span)
            i = j if j > i + 1 else i + 1
            continue
        elif lower == "id" and i + 1 < len(tokens):
            ident = _strip_quotes(tokens[i + 1])
            i += 2
            continue
        elif lower == "for" and i + 1 < len(tokens):
            for_addr = _strip_quotes(tokens[i + 1]).strip("<>")
            i += 2
            continue
        i += 1

    tls = None
    for tok in tokens:
        if tok.startswith("(") and re.search(
            r"using\s+TLS|version=TLS|cipher=|STARTTLS", tok, re.IGNORECASE
        ):
            tls = tok[1:-1].strip()
            break

    def clean_ep(ep: dict) -> dict:
        host = ep.get("host")
        if host and _NOSUCHHOST.search(host):
            host = None
        return {
            "host": host,
            "ip": ep.get("ip"),
            "rdns": ep.get("rdns"),
        }

    return {
        "hop": hop,
        "timestamp": timestamp,
        "received_from": clean_ep(received_from),
        "received_by": clean_ep(received_by),
        "protocol": protocol,
        "tls": tls,
        "id": ident,
        "for": for_addr,
        "with": with_,
        "raw": raw,
    }


def parse_transmission(received_values: list[str]) -> list[dict]:
    """Return hops oldest → newest (raw header order is newest → oldest)."""
    hops = [
        parse_received(v, hop=n) for n, v in enumerate(reversed(received_values), start=1)
    ]
    return hops
