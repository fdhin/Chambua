"""Parse an Outlook ``.msg`` (OLE compound) file into the record schema.

extract-msg handles the compound-file plumbing. When the message carries
its ``PidTagTransportMessageHeaders`` blob we parse that as an RFC 5322
header block — the richest source for Received / Authentication-Results —
and fill any gaps from the structured MAPI properties.
"""

from __future__ import annotations

import hashlib
import json
import logging
import email.message
from email import message_from_string
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path

from .authresults import parse_authentication_results
from .parse_eml import _address_field, _first_external_ip, _write_attachment, decode_value
from .received import parse_transmission
from .sanitize import sanitize_html
from .urls import collect_urls

log = logging.getLogger("mail-workbench.parse_msg")


def _decode_html_body(raw: bytes | None) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, memoryview):
        raw = raw.tobytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def _strip_nuls(s: str | None) -> str | None:
    """Property strings read from padded streams may carry trailing NULs."""
    if s is None:
        return None
    return s.rstrip("\x00").strip() or None


def parse_msg(
    data: bytes,
    record_id: str,
    source_file: str,
    extracted_from_zip: str | None,
    record_dir: Path,
) -> dict:
    import extract_msg
    from extract_msg.enums import ErrorBehavior

    # Hostile / hand-rolled .msg files routinely violate MS-OXMSG in ways
    # extract-msg treats as fatal by default; degrade instead of crashing.
    msg = extract_msg.openMsg(data, errorBehavior=ErrorBehavior.SUPPRESS_ALL)

    # extract-msg ≥0.5x exposes transport headers as a parsed Message, with
    # property-based fallback generation when the 007D stream is absent.
    header_obj = None
    try:
        header_obj = msg.header
    except Exception:
        header_obj = None
    header_msg = header_obj if isinstance(header_obj, email.message.Message) else None

    def hh(name: str, default=None):
        if header_msg is not None:
            v = header_msg.get(name, default)
            if v is not None:
                return v
        return default

    from_raw = decode_value(hh("From")) or ""
    if not from_raw:
        sender = _strip_nuls(getattr(msg, "sender", None))
        if sender:
            from_raw = sender
    from_name, from_addr = parseaddr(from_raw or "")

    to_list = _address_field(hh("To"))
    if not to_list:
        to_list = [t for t in (_strip_nuls(x) for x in (getattr(msg, "to", None) or [])) if t]
    cc_list = _address_field(hh("Cc"))
    if not cc_list:
        cc_list = [c for c in (_strip_nuls(x) for x in (getattr(msg, "cc", None) or [])) if c]

    timestamp = None
    date_raw = hh("Date")
    if date_raw:
        try:
            ts = parsedate_to_datetime(decode_value(date_raw) or date_raw)
            if ts is not None:
                timestamp = ts.isoformat()
        except (TypeError, ValueError, IndexError):
            timestamp = None
    if timestamp is None:
        msg_date = getattr(msg, "date", None)
        if msg_date is not None:
            timestamp = msg_date.isoformat()

    received_values = []
    if header_msg is not None:
        received_values = [decode_value(v) or "" for v in (header_msg.get_all("Received") or [])]
    transmission = parse_transmission(received_values)

    return_path = hh("Return-Path")
    if return_path:
        return_path = return_path.strip().strip("<>")

    x_orig = hh("X-Originating-IP")
    originating_ip, rdns = _first_external_ip(transmission, x_orig)

    details = {
        "from": {"address": from_addr or None, "display_name": from_name or None},
        "sender": (parseaddr(decode_value(hh("Sender")) or "")[1] or None),
        "to": to_list,
        "cc": cc_list,
        "reply_to": (parseaddr(decode_value(hh("Reply-To")) or "")[1] or None),
        "in_reply_to": hh("In-Reply-To") or getattr(msg, "inReplyTo", None),
        "message_id": hh("Message-ID") or getattr(msg, "messageId", None),
        "timestamp": timestamp,
        "return_path": return_path,
        "originating_ip": originating_ip,
        "rdns": rdns,
        "subject": decode_value(hh("Subject")) or _strip_nuls(getattr(msg, "subject", None)) or "(no subject)",
    }

    auth_values = []
    if header_msg is not None:
        auth_values = [decode_value(v) or "" for v in (header_msg.get_all("Authentication-Results") or [])]
    authentication = parse_authentication_results(auth_values or None)
    if authentication["spf"]["originating_ip"] is None:
        authentication["spf"]["originating_ip"] = originating_ip
    if authentication["spf"]["rdns"] is None:
        authentication["spf"]["rdns"] = rdns
    if authentication["spf"]["return_path_domain"] is None and return_path:
        authentication["spf"]["return_path_domain"] = return_path.rpartition("@")[2] or None

    plaintext = None
    try:
        plaintext = _strip_nuls(msg.body)
    except Exception:
        plaintext = None
    html_body = _decode_html_body(getattr(msg, "htmlBody", None))

    attachments: list[dict] = []
    try:
        msg_attachments = list(msg.attachments or [])
    except Exception:
        msg_attachments = []
    for att in msg_attachments:
        try:
            filename = None
            for prop in ("longFilename", "shortFilename", "filename"):
                filename = _strip_nuls(getattr(att, prop, None))
                if filename:
                    break
            data = getattr(att, "data", None)
            if data is None:
                continue
            if isinstance(data, memoryview):
                data = data.tobytes()
            if not isinstance(data, bytes):
                data = str(data).encode("utf-8", "replace")
            ctype = getattr(att, "mimeType", None) or "application/octet-stream"
            attachments.append(_write_attachment(record_dir, filename or "unnamed", data, ctype))
        except Exception as exc:
            log.warning("failed to read attachment: %s", exc)

    rendered = sanitize_html(html_body) if html_body else None
    if rendered is not None:
        (record_dir / "rendered.html").write_text(rendered, encoding="utf-8")
    if plaintext is not None:
        (record_dir / "plaintext.txt").write_text(plaintext, encoding="utf-8")
    if attachments:
        att_dir = record_dir / "attachments"
        att_dir.mkdir(exist_ok=True)
        manifest = [
            {k: a[k] for k in ("filename", "sha256", "md5", "sha1", "size_bytes")}
            for a in attachments
        ]
        (att_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    from_domain = from_addr.rpartition("@")[2].lower() or None if from_addr else None
    headers_for_urls = {
        "reply-to": hh("Reply-To") or "",
        "return-path": hh("Return-Path") or "",
        "list-unsubscribe": hh("List-Unsubscribe") or "",
    }
    urls = collect_urls(html_body, plaintext, headers_for_urls, from_domain)

    x_headers = []
    if header_msg is not None:
        x_headers = [
            {"name": name, "value": decode_value(value) or ""}
            for name, value in header_msg.raw_items()
            if name.lower().startswith("x-")
        ]

    parsed = {
        "record_id": record_id,
        "source_file": source_file,
        "source_kind": "msg",
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
            "raw_source_path": "original.msg",
        },
        "parse_warnings": None,
    }

    (record_dir / "parsed.json").write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    return parsed
