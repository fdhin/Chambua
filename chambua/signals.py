"""Aggregate every detected anomaly into the Signals list (v2 spec §2).

The Signals tab is the TL;DR view: one row per signal with severity,
name, evidence, and a jump-to-source anchor. Wording deliberately avoids
verdicts — "No anomalies detected" means exactly that, not "safe".
"""

from __future__ import annotations

import re

from .consistency import consistency_checks
from .dkim_depth import dkim_depth_signals
from .geo import enrich_transmission, geo_signals
from .m365 import decode_m365, m365_signals

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _url_signals(urls: list[dict]) -> list[dict]:
    signals: list[dict] = []
    for i, u in enumerate(urls):
        evidence = u.get("unwrapped") or u.get("url") or ""
        for flag in u.get("flags") or []:
            signals.append({
                "severity": flag["severity"],
                "name": flag["label"] + (
                    " in URL" if flag["kind"] == "suspicious_tld" else ""
                ),
                "evidence": f"{evidence} — {flag['detail']}",
                "tab": "urls",
                "anchor": f"url-{i}",
            })
        if u.get("anchor_mismatch"):
            signals.append({
                "severity": "high",
                "name": "Anchor text mismatch",
                "evidence": f"{evidence} — visible text is "
                f"{u.get('anchor_text')}",
                "tab": "urls",
                "anchor": f"url-{i}",
            })
        elif u.get("differs_from_from_domain"):
            signals.append({
                "severity": "low",
                "name": "Link domain differs from From domain",
                "evidence": evidence,
                "tab": "urls",
                "anchor": f"url-{i}",
            })
    return signals


def _attachment_signals(attachments: list[dict]) -> list[dict]:
    signals: list[dict] = []
    for i, att in enumerate(attachments):
        for flag in att.get("flags") or []:
            signals.append({
                "severity": flag["severity"],
                "name": f"{flag['label']} — {att['filename']}",
                "evidence": f"{att['filename']}: {flag['detail']}",
                "tab": "attachments",
                "anchor": f"att-{i}",
            })
    return signals


def _consistency_signals(checks: list[dict]) -> list[dict]:
    signals: list[dict] = []
    for check in checks:
        if check["status"] != "flagged":
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", check["name"].lower()).strip("-")
        signals.append({
            "severity": check["severity"],
            "name": check["name"],
            "evidence": check["explanation"],
            "tab": "details",
            "anchor": f"check-{slug}",
        })
    return signals


def _dkim_signals(auth: dict) -> list[dict]:
    signals: list[dict] = []
    for i, sig in enumerate(auth.get("dkim", {}).get("signatures") or []):
        depth = sig.get("depth")
        if not depth:
            continue
        for s in dkim_depth_signals(depth, sig.get("selector"), sig.get("signing_domain")):
            s["anchor"] = f"sig-{i}"
            signals.append(s)
    return signals


def compute_signals(parsed: dict) -> list[dict]:
    """Run every signal source over the parsed record. Also performs the
    in-place enrichment (consistency checks, M365 decode, transmission
    geo) that the individual tabs render."""
    details = parsed.get("details", {})
    parsed["consistency"] = consistency_checks(details, parsed.get("transmission"))
    parsed["m365_decoded"] = decode_m365(parsed.get("x_headers") or [])

    from_domain = None
    addr = details.get("from", {}).get("address")
    if addr and "@" in addr:
        from_domain = addr.rpartition("@")[2]

    enrich_transmission(parsed.get("transmission") or [])

    signals: list[dict] = []
    signals += _url_signals(parsed.get("urls") or [])
    signals += _consistency_signals(parsed.get("consistency"))
    signals += _attachment_signals(parsed.get("attachments") or [])
    signals += m365_signals(parsed.get("m365_decoded"), from_domain)
    signals += _dkim_signals(parsed.get("authentication") or {})
    signals += geo_signals(parsed.get("transmission") or [], from_domain)

    signals.sort(key=lambda s: SEVERITY_ORDER.get(s.get("severity"), 9))
    parsed["signals"] = signals
    return signals
