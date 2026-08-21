"""DKIM signing-depth analysis (v2 spec §8).

Tag-level analysis of each DKIM-Signature header at parse time (h=, l=,
t=, x=, a=, c= — no DNS). Key length requires live DNS and is fetched
only inside the on-demand re-verify (see reverify.py).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

CRITICAL_HEADERS = ("from", "subject", "to", "date", "message-id")

_TAG_RE = re.compile(r"([a-z]+)\s*=\s*([^;]+)", re.IGNORECASE)


def parse_signature_tags(value: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for m in _TAG_RE.finditer(value):
        key = m.group(1).lower()
        if key not in tags:
            tags[key] = m.group(2).strip()
    return tags


def analyze_signature(value: str, now: datetime | None = None) -> dict:
    """Depth analysis for one DKIM-Signature header value."""
    tags = parse_signature_tags(value)
    h_list = [h.strip().lower() for h in (tags.get("h", "") or "").split(":") if h.strip()]
    missing_critical = [h for h in CRITICAL_HEADERS if h not in h_list]

    depth: dict = {
        "h": h_list,
        "missing_critical": missing_critical or None,
        "l": int(tags["l"]) if tags.get("l", "").isdigit() else None,
        "t": tags.get("t"),
        "a": tags.get("a"),
        "c": tags.get("c", "simple/simple"),
        "x": None,
        "x_expired": None,
    }
    if tags.get("x", "").isdigit():
        expiry = datetime.fromtimestamp(int(tags["x"]), tz=timezone.utc)
        depth["x"] = expiry.isoformat()
        now = now or datetime.now(timezone.utc)
        depth["x_expired"] = expiry < now

    depth["warnings"] = []
    if "from" in missing_critical:
        depth["warnings"].append(
            "Signature does not cover the From header — an attacker can "
            "replace the visible sender while the signature stays valid"
        )
    if "subject" in missing_critical:
        depth["warnings"].append("Subject header is not signed")
    if depth["l"] is not None:
        depth["warnings"].append(
            f"Only the first {depth['l']} body bytes are signed — content "
            "could be appended below the signed region"
        )
    if (depth["a"] or "").lower() == "rsa-sha1":
        depth["warnings"].append("SHA-1 signature — deprecated but still valid")
    if "y" in [f.strip().lower() for f in (depth["t"] or "").split("|")]:
        depth["warnings"].append(
            "Test mode (t=y) — sender asks verifiers not to enforce"
        )
    if depth["x_expired"]:
        depth["warnings"].append("Signature has expired (x= in the past)")
    return depth


def attach_depth(authentication: dict, dkim_values: list[str]) -> None:
    """Attach depth analysis to the Authentication-Results signature
    entries (matched by selector+domain). When the receiver stamped no
    DKIM results but the message carries signatures, synthesize entries
    with result None so the depth is still inspectable."""
    depths = [
        (parse_signature_tags(v), analyze_signature(v))
        for v in dkim_values
        if v and v.strip()
    ]
    if not depths:
        return
    sigs = authentication.setdefault("dkim", {}).setdefault("signatures", [])
    used: set[int] = set()
    for sig in sigs:
        for idx, (tags, depth) in enumerate(depths):
            if idx in used:
                continue
            if tags.get("s") == sig.get("selector") and tags.get("d") == sig.get("signing_domain"):
                sig["depth"] = depth
                used.add(idx)
                break
    if not sigs:
        authentication["dkim"]["signatures"] = [
            {
                "selector": tags.get("s"),
                "signing_domain": tags.get("d"),
                "algorithm": tags.get("a"),
                "verification": None,
                "result": None,
                "depth": depth,
            }
            for tags, depth in depths
        ]


def dkim_depth_signals(depth: dict, selector: str | None, domain: str | None) -> list[dict]:
    """Signals per §8: missing From → high, missing Subject/l= → medium,
    t=y → info, sha1 → info."""
    where = f"{selector or '?'}._domainkey.{domain or '?'}"
    signals: list[dict] = []
    missing = depth.get("missing_critical") or []
    if "from" in missing:
        signals.append({
            "severity": "high",
            "name": "DKIM signature does not cover From header",
            "evidence": f"Signature {where}: From absent from h=",
            "tab": "auth",
        })
    if "subject" in missing:
        signals.append({
            "severity": "medium",
            "name": "DKIM signature does not cover Subject",
            "evidence": f"Signature {where}: Subject absent from h=",
            "tab": "auth",
        })
    if depth.get("l") is not None:
        signals.append({
            "severity": "medium",
            "name": "DKIM body length limit set",
            "evidence": f"Signature {where}: l={depth['l']} — attacker could "
            "append unsigned content",
            "tab": "auth",
        })
    if "y" in [f.strip().lower() for f in (depth.get("t") or "").split("|")]:
        signals.append({
            "severity": "info", "name": "DKIM signature in test mode",
            "evidence": f"Signature {where}: t=y", "tab": "auth",
        })
    if (depth.get("a") or "").lower() == "rsa-sha1":
        signals.append({
            "severity": "info", "name": "DKIM uses SHA-1",
            "evidence": f"Signature {where}: a=rsa-sha1", "tab": "auth",
        })
    return signals
