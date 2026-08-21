"""Parse an RFC 5322 ``.eml`` file into the normalized record schema.

Writes ``rendered.html``, ``plaintext.txt`` and ``attachments/`` into the
record directory and returns the ``parsed.json`` dict. Uses the stdlib
``email`` module with the compat32 policy — hostile input must never raise
out of header access; where it would, we degrade to null fields.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import timezone
from email import message_from_bytes
from email.header import decode_header, make_header
from email.policy import compat32
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path

from .authresults import parse_authentication_results
from .attach_inspect import inspect_attachment
from .dkim_depth import attach_depth
from .received import parse_transmission
from .sanitize import sanitize_html
from .signals import compute_signals
from .urls import collect_urls

log = logging.getLogger("chambua.parse")

ARCHIVE_EXTENSIONS = {
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "arj", "iso",
    "tgz", "tbz2", "txz",
}

_IP_RE_CACHE = None


def decode_value(value: str | None) -> str | None:
    """RFC 2047-decode a header value; never raise."""
    if value is None:
        return None
    try:
        parts = decode_header(value)
        if any(isinstance(p, bytes) for p in parts) or any(p[1] for p in parts):
            return str(make_header(parts))
        return value
    except Exception:
        return value


def _address_field(raw: str | None) -> list[str]:
    if not raw:
        return []
    decoded = decode_value(raw) or ""
    return [f"{name} <{addr}>" if name else addr for name, addr in getaddresses([decoded]) if addr]


def _first_external_ip(transmission: list[dict], x_originating: str | None) -> tuple[str | None, str | None]:
    """Oldest-hop origin IP, plus the rDNS name claimed beside it.

    Excludes only loopback/link-local (documentation ranges like TEST-NET
    are still reported — analysts see them in captured samples).
    """
    if x_originating:
        ip = x_originating.strip().strip("[]")
        if ip:
            return ip, None
    import ipaddress

    for hop in transmission:  # already oldest → newest
        endpoint = hop.get("received_from") or {}
        ip = endpoint.get("ip")
        if not ip:
            continue
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if parsed.is_loopback or parsed.is_link_local or parsed.is_multicast:
            continue
        return ip, endpoint.get("rdns")
    return None, None


def _write_attachment(record_dir: Path, filename: str, data: bytes, mime: str) -> dict:
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    att_dir = record_dir / "attachments"
    att_dir.mkdir(exist_ok=True)
    (att_dir / f"{sha256}.bin").write_bytes(data)
    ext = filename.rpartition(".")[2].lower() if "." in filename else ""
    is_archive = ext in ARCHIVE_EXTENSIONS
    return {
        "filename": filename or "unnamed",
        "size_bytes": len(data),
        "mime_type": mime,
        "extension": ext,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "is_archive": is_archive,
        "notes": "nested archive — not extracted" if is_archive else None,
    }


def _decode_part(part) -> tuple[bytes | None, str]:
    payload = part.get_payload(decode=True)
    if payload is None:
        payload = part.get_payload()
        if isinstance(payload, str):
            return payload.encode("utf-8", errors="replace"), "utf-8"
        return None, "utf-8"
    charset = part.get_content_charset() or "utf-8"
    try:
        payload.decode(charset)
    except (LookupError, UnicodeDecodeError):
        charset = "latin-1"
    return payload, charset


def _iter_leaf_parts(msg):
    """Yield leaf parts, treating embedded messages (message/rfc822) as
    attachment leaves rather than descending into them (§4.4: no recursion
    into attached content)."""
    if not msg.is_multipart():
        yield msg
        return
    for part in msg.get_payload():
        if part.get_content_type() == "message/rfc822":
            yield part
        elif part.is_multipart():
            yield from _iter_leaf_parts(part)
        else:
            yield part


def extract_html_body(data: bytes) -> str | None:
    """Pull the raw (unsanitized) text/html part back out of an .eml —
    used by the HTML tab and the explicit load-remote-content opt-in."""
    msg = message_from_bytes(data, policy=compat32)
    for part in _iter_leaf_parts(msg):
        if part.get_content_type() != "text/html":
            continue
        disposition = (part.get("Content-Disposition") or "").lower()
        if disposition.startswith("attachment"):
            continue
        payload, charset = _decode_part(part)
        if payload is not None:
            return payload.decode(charset, errors="replace")
    return None


def parse_eml(
    data: bytes,
    record_id: str,
    source_file: str,
    extracted_from_zip: str | None,
    record_dir: Path,
) -> dict:
    msg = message_from_bytes(data, policy=compat32)

    def h(name: str, default=None):
        v = msg.get(name, default)
        if v is None:
            return default
        if not isinstance(v, str):
            # 8-bit raw headers under compat32 can surface as Header objects.
            try:
                v = str(v)
            except Exception:
                return default
        return decode_value(v)

    from_raw = decode_value(h("From"))
    from_name, from_addr = parseaddr(from_raw or "")
    from_domain = from_addr.rpartition("@")[2].lower() or None if from_addr else None

    received_values = [decode_value(v) or "" for v in (msg.get_all("Received") or [])]
    transmission = parse_transmission(received_values)

    x_orig = h("X-Originating-IP") or h("X-Originator-IP")
    originating_ip, rdns = _first_external_ip(transmission, x_orig)

    date_raw = h("Date")
    timestamp = None
    if date_raw:
        try:
            ts = parsedate_to_datetime(decode_value(date_raw) or date_raw)
            if ts is not None:
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                timestamp = ts.isoformat()
        except (TypeError, ValueError, IndexError):
            timestamp = None

    return_path = h("Return-Path")
    if return_path:
        return_path = return_path.strip().strip("<>")

    details = {
        "from": {"address": from_addr or None, "display_name": from_name or None},
        "sender": (parseaddr(decode_value(h("Sender")) or "")[1] or None),
        "to": _address_field(h("To")),
        "cc": _address_field(h("Cc")),
        "reply_to": (parseaddr(decode_value(h("Reply-To")) or "")[1] or None),
        "in_reply_to": h("In-Reply-To"),
        "message_id": h("Message-ID"),
        "timestamp": timestamp,
        "return_path": return_path,
        "originating_ip": originating_ip,
        "rdns": rdns,
        "subject": decode_value(h("Subject")) or "(no subject)",
    }

    auth_values = [decode_value(v) or "" for v in (msg.get_all("Authentication-Results") or [])]
    authentication = parse_authentication_results(auth_values or None)
    if authentication["spf"]["originating_ip"] is None:
        authentication["spf"]["originating_ip"] = originating_ip
    if authentication["spf"]["rdns"] is None:
        authentication["spf"]["rdns"] = rdns
    if authentication["spf"]["return_path_domain"] is None and return_path:
        authentication["spf"]["return_path_domain"] = return_path.rpartition("@")[2] or None

    # --- body parts -----------------------------------------------------
    html_body: str | None = None
    plaintext: str | None = None
    attachments: list[dict] = []
    warnings: list[str] = []

    for part in _iter_leaf_parts(msg):
        ctype = part.get_content_type()
        disposition = str(part.get("Content-Disposition") or "").lower()
        filename = part.get_filename()
        if filename:
            filename = decode_value(filename) or filename
        is_attachment = disposition.startswith("attachment") or (
            filename is not None and ctype not in ("text/plain", "text/html")
        )
        if ctype == "message/rfc822" or (filename and filename.lower().endswith(".eml")):
            is_attachment = True
        if is_attachment:
            payload = part.get_payload(decode=True)
            if payload is None:
                nested = part.get_payload()
                payload = nested.as_bytes() if hasattr(nested, "as_bytes") else str(nested).encode("utf-8", "replace")
            record = _write_attachment(
                record_dir, filename or f"message-{len(attachments)}.eml", payload, ctype
            )
            record.update(inspect_attachment(payload, record["filename"], record["extension"]))
            attachments.append(record)
            continue
        if ctype == "text/html" and html_body is None:
            payload, charset = _decode_part(part)
            if payload is not None:
                html_body = payload.decode(charset, errors="replace")
        elif ctype == "text/plain" and plaintext is None:
            payload, charset = _decode_part(part)
            if payload is not None:
                plaintext = payload.decode(charset, errors="replace")

    for defect in getattr(msg, "defects", []):
        warnings.append(type(defect).__name__)

    rendered = sanitize_html(html_body) if html_body else None
    if rendered is not None:
        (record_dir / "rendered.html").write_text(rendered, encoding="utf-8")
    if plaintext is not None:
        (record_dir / "plaintext.txt").write_text(plaintext, encoding="utf-8")

    manifest = [
        {k: a[k] for k in ("filename", "sha256", "md5", "sha1", "size_bytes")}
        for a in attachments
    ]
    if attachments:
        (record_dir / "attachments").mkdir(exist_ok=True)
        (record_dir / "attachments" / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

    headers_for_urls = {
        "reply-to": h("Reply-To") or "",
        "return-path": h("Return-Path") or "",
        "list-unsubscribe": h("List-Unsubscribe") or "",
    }
    urls = collect_urls(html_body, plaintext, headers_for_urls, from_domain)

    x_headers = [
        {"name": name, "value": decode_value(value) or ""}
        for name, value in msg.raw_items()
        if name.lower().startswith("x-")
    ]

    parsed = {
        "record_id": record_id,
        "source_file": source_file,
        "source_kind": "eml",
        "extracted_from_zip": extracted_from_zip,
        "details": details,
        "authentication": authentication,
        "urls": urls,
        "attachments": attachments,
        "transmission": transmission,
        "x_headers": x_headers,
        "content": {
            "has_html": html_body is not None,
            "has_plaintext": plaintext is not None,
            "html_path": "rendered.html" if html_body is not None else None,
            "plaintext_path": "plaintext.txt" if plaintext is not None else None,
            "raw_source_path": "original.eml",
        },
        "parse_warnings": warnings or None,
    }

    attach_depth(
        authentication,
        [decode_value(v) or "" for v in (msg.get_all("DKIM-Signature") or [])],
    )
    compute_signals(parsed)

    (record_dir / "parsed.json").write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    return parsed
