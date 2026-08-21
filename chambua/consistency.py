"""Header consistency checks (v2 spec §4).

Pure string/time comparisons, no external calls. Each check reports
{status: passed|flagged, severity, name, explanation} so the Details tab
can show green checks for what ran clean and the Signals tab can roll up
what fired.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from .urls import registrable_domain

_ADDR_RE = re.compile(r"[@<]?\s*[\w.+\-']+@([\w.\-]+\.\w+)")


def _domain_of_address(value: str | None) -> str | None:
    if not value:
        return None
    m = _ADDR_RE.search(value)
    return m.group(1).lower().rstrip(".") if m else None


def _aligned(a: str | None, b: str | None) -> bool:
    """Relaxed alignment, as DMARC uses it."""
    if not a or not b:
        return False
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _parse_dt(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def consistency_checks(details: dict, transmission: list[dict] | None = None) -> list[dict]:
    d = details or {}
    from_domain = _domain_of_address(d.get("from", {}).get("address"))
    checks: list[dict] = []

    def add(name, flagged, severity, explanation, ok_explanation):
        checks.append(
            {
                "name": name,
                "status": "flagged" if flagged else "passed",
                "severity": severity,
                "explanation": explanation if flagged else ok_explanation,
            }
        )

    # Message-ID vs From domain (registrable, not exact host).
    mid_host = None
    message_id = d.get("message_id") or ""
    m = re.search(r"@([\w.\-]+\.\w+)", message_id)
    if m:
        mid_host = m.group(1).lower()
    mid_flag = bool(
        mid_host
        and from_domain
        and registrable_domain(mid_host) != registrable_domain(from_domain)
    )
    add(
        "Message-ID vs From domain",
        mid_flag,
        "medium",
        f"Message-ID host {mid_host} does not share a registrable domain "
        f"with From ({from_domain})",
        "Message-ID host aligns with the From domain",
    )

    # Reply-To vs From — classic BEC.
    reply_domain = _domain_of_address(d.get("reply_to"))
    reply_flag = bool(reply_domain and from_domain and reply_domain != from_domain)
    add(
        "Reply-To vs From",
        reply_flag,
        "high",
        f"Reply-To ({reply_domain}) differs from From ({from_domain}) — "
        "classic business-email-compromise pattern",
        "Reply-To aligns with From",
    )

    # Return-Path vs From — relaxed alignment as DMARC uses.
    rp_domain = _domain_of_address(d.get("return_path"))
    rp_flag = bool(rp_domain and from_domain and not _aligned(rp_domain, from_domain))
    add(
        "Return-Path vs From",
        rp_flag,
        "medium",
        f"Return-Path domain ({rp_domain}) is not aligned with From "
        f"({from_domain})",
        "Return-Path aligns with From (relaxed)",
    )

    # Sender vs From.
    sender = d.get("sender")
    sender_flag = bool(sender and from_domain and sender.lower() != (d.get("from", {}).get("address") or "").lower())
    add(
        "Sender vs From",
        sender_flag,
        "low",
        f"Sender header ({sender}) differs from From",
        "Sender matches From (or absent)",
    )

    # Date vs first Received (oldest hop).
    date = _parse_dt(d.get("timestamp"))
    hops_ts = None
    for hop in transmission or []:
        hops_ts = _parse_dt(hop.get("timestamp"))
        if hops_ts:
            break
    skew_flag = False
    skew_detail = "Date header and first Received hop agree"
    if date and hops_ts:
        delta = abs(date - hops_ts)
        if delta > timedelta(hours=24):
            skew_flag = True
            skew_detail = (
                f"Date header is {delta.days}d{delta.seconds // 3600}h from the "
                "first Received timestamp (possible replay; more often clock skew)"
            )
    add("Date vs first Received", skew_flag, "low", skew_detail, skew_detail)

    # Date in the future relative to receipt.
    future_flag = False
    future_detail = "Date is not in the future"
    if date and hops_ts:
        if date > hops_ts + timedelta(minutes=5):
            future_flag = True
            future_detail = (
                f"Date header is {(date - hops_ts).total_seconds() / 60:.0f} min "
                "after the first Received timestamp"
            )
    add("Date in future", future_flag, "medium", future_detail, future_detail)

    return checks
