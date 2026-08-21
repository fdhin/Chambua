"""Decode Microsoft 365 / Exchange Online anti-spam headers (v2 spec §5).

X-Forefront-Antispam-Report, X-Microsoft-Antispam, and the three
X-MS-Exchange-Organization-* headers worth decoding. Everything else in
the X-MS-Exchange-* family is left raw on purpose — Microsoft's own docs
are incomplete.
"""

from __future__ import annotations

import re

SCL_MEANING = {
    -1: "trusted sender (bypassed filtering)",
    0: "clean", 1: "clean",
    2: "low suspicion", 3: "low suspicion", 4: "low suspicion",
    5: "spam", 6: "spam",
    7: "high-confidence spam", 8: "high-confidence spam",
    9: "high-confidence spam",
}

SFV_MEANING = {
    "SPM": "message marked as spam",
    "SKS": "message marked as spam by server-side rule",
    "SKI": "message skipped filtering (tenant allow-list)",
    "SKN": "message skipped filtering (allow-listed sender/domain)",
    "SKQ": "message released from quarantine",
    "BLK": "message from blocked sender",
    "NSPM": "message not marked as spam",
    "NSTS": "message not marked as spam by STMP-authenticated sender",
}

SFTY_MEANING = {
    "9.11": "phishing (invalid sender / not authenticated)",
    "9.19": "high-confidence phishing",
    "9.20": "user/domain impersonation",
    "9.25": "spoof — DMARC failure",
    "9.27": "spoof — DMARC failure, intra-org",
    "9.28": "spoof — unauthenticated external sender",
}
SFTY_PHISH_PREFIX = "9.1"
SFTY_PHISH_PREFIX_2 = "9.2"

CAT_MEANING = {
    "SPM": "spam", "PHSH": "phishing", "MALW": "malware",
    "HPHSH": "high-confidence phishing", "HSPM": "high-confidence spam",
    "HBLK": "blocked sender", "HFULL": "full-file quarantine",
    "BULK": "bulk mail", "NONE": "no category",
}

IPV_MEANING = {"CAL": "allowed by IP allow-list", "NLI": "not on any IP list"}

DIR_MEANING = {"INB": "inbound", "OUT": "outbound"}

AUTHAS_MEANING = {
    "Anonymous": "unauthenticated external sender",
    "Internal": "authenticated internal sender",
    "Partner": "authenticated partner (trusted)",
}

AUTHMECH_MEANING = {
    "04": "SMTP AUTH (client submission)",
    "05": "SMTP AUTH over TLS",
    "06": "trusted partner (organizational)",
    "07": "anonymous (external relay)",
    "08": "resolved exchange server",
    "10": "resolved alternate source",
    "11": "resolved send-connector",
}

BCL_MEANING = {0: "no complaints", 1: "low", 2: "low", 3: "low",
               4: "medium", 5: "medium", 6: "medium", 7: "medium",
               8: "high", 9: "high"}

# ISO 3166 subset used to expand CTRY (falls back to the raw code).
_COUNTRY_NAMES = {
    "DK": "Denmark", "SE": "Sweden", "NO": "Norway", "FI": "Finland",
    "DE": "Germany", "NL": "Netherlands", "FR": "France", "GB": "United Kingdom",
    "US": "United States", "CA": "Canada", "IE": "Ireland", "PL": "Poland",
    "CN": "China", "RU": "Russia", "UA": "Ukraine", "IN": "India",
    "BR": "Brazil", "NG": "Nigeria", "TR": "Türkiye", "VN": "Vietnam",
    "ID": "Indonesia", "PH": "Philippines", "ZA": "South Africa",
    "AU": "Australia", "JP": "Japan", "KR": "South Korea", "SG": "Singapore",
    "HK": "Hong Kong", "TW": "Taiwan", "ES": "Spain", "IT": "Italy",
    "CH": "Switzerland", "AT": "Austria", "BE": "Belgium", "CZ": "Czechia",
    "LT": "Lithuania", "LV": "Latvia", "EE": "Estonia", "IS": "Iceland",
    "RO": "Romania", "BG": "Bulgaria", "MD": "Moldova", "SC": "Seychelles",
    "PA": "Panama", "BZ": "Belize", "KY": "Cayman Islands",
}


def country_name(code: str | None) -> str | None:
    if not code:
        return None
    return _COUNTRY_NAMES.get(code.upper(), code.upper())


def _parse_fields(value: str) -> dict[str, str]:
    """Forefront/Antispam fields are `KEY:VALUE` separated by ';'
    (some tenants emit `KEY=VALUE`; accept both)."""
    fields: dict[str, str] = {}
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if "=" in chunk:
            k, v = chunk.split("=", 1)
        elif ":" in chunk:
            k, v = chunk.split(":", 1)
        else:
            continue
        k = k.strip()
        if k and k not in fields:  # first occurrence wins
            fields[k] = v.strip()
    return fields


def decode_forefront(value: str) -> dict:
    """Decode X-Forefront-Antispam-Report into labeled fields."""
    raw = _parse_fields(value)
    scl_raw = raw.get("SCL")
    scl = int(scl_raw) if scl_raw and scl_raw.lstrip("-").isdigit() else None
    sfv = raw.get("SFV")
    sfty = raw.get("SFTY")
    cat = raw.get("CAT")
    ipv = raw.get("IPV")
    dir_ = raw.get("DIR")

    sfty_meaning = None
    if sfty:
        sfty_meaning = SFTY_MEANING.get(sfty)
        if not sfty_meaning and sfty.startswith((SFTY_PHISH_PREFIX, SFTY_PHISH_PREFIX_2)):
            sfty_meaning = "safety / phishing family"

    return {
        "CIP": {"label": "Connecting IP", "value": raw.get("CIP")},
        "CTRY": {
            "label": "Country of source IP",
            "value": raw.get("CTRY"),
            "expand": country_name(raw.get("CTRY")),
        },
        "LANG": {"label": "Detected language", "value": raw.get("LANG")},
        "SCL": {
            "label": "Spam Confidence Level",
            "value": scl_raw,
            "expand": SCL_MEANING.get(scl) if scl is not None else None,
            "scl": scl,
        },
        "SFV": {
            "label": "Spam Filter Verdict",
            "value": sfv,
            "expand": SFV_MEANING.get(sfv) if sfv else None,
        },
        "IPV": {
            "label": "IP filter verdict",
            "value": ipv,
            "expand": IPV_MEANING.get(ipv) if ipv else None,
        },
        "SFTY": {
            "label": "Safety verdict",
            "value": sfty,
            "expand": sfty_meaning,
        },
        "SFS": {"label": "Spam filter rules matched", "value": raw.get("SFS")},
        "CAT": {
            "label": "Category",
            "value": cat,
            "expand": CAT_MEANING.get(cat) if cat else None,
        },
        "DIR": {
            "label": "Direction",
            "value": dir_,
            "expand": DIR_MEANING.get(dir_) if dir_ else None,
        },
        "PTR": {"label": "Reverse DNS (as EOP saw it)", "value": raw.get("PTR")},
        "H": {"label": "HELO string at SMTP", "value": raw.get("H")},
        "SRV": {"label": "Server rules", "value": raw.get("SRV")},
        "_raw": value,
    }


def decode_ms_antispam(value: str) -> dict:
    """Decode X-Microsoft-Antispam — BCL is the interesting part."""
    raw = _parse_fields(value)
    bcl_raw = raw.get("BCL")
    bcl = int(bcl_raw) if bcl_raw and bcl_raw.isdigit() else None
    return {
        "BCL": {
            "label": "Bulk Complaint Level",
            "value": bcl_raw,
            "expand": BCL_MEANING.get(bcl) if bcl is not None else None,
            "bcl": bcl,
        },
        "_raw": value,
    }


def decode_exchange_org(x_headers: list[dict]) -> dict:
    """The three X-MS-Exchange-Organization-* headers worth decoding."""
    lookup = {h["name"].lower(): h["value"] for h in x_headers}
    out: dict[str, dict] = {}
    auth_as = lookup.get("x-ms-exchange-organization-authas")
    if auth_as:
        out["AuthAs"] = {
            "label": "Authentication as",
            "value": auth_as,
            "expand": AUTHAS_MEANING.get(auth_as, "unknown"),
        }
    auth_mech = lookup.get("x-ms-exchange-organization-authmechanism")
    if auth_mech:
        out["AuthMechanism"] = {
            "label": "Authentication mechanism",
            "value": auth_mech,
            "expand": AUTHMECH_MEANING.get(auth_mech, "unknown"),
        }
    scl2 = lookup.get("x-ms-exchange-organization-scl")
    if scl2:
        out["SCL"] = {
            "label": "Organization SCL",
            "value": scl2,
            "expand": SCL_MEANING.get(int(scl2)) if scl2.lstrip("-").isdigit() else None,
        }
    return out


def decode_m365(x_headers: list[dict]) -> dict | None:
    """Full decoded panel for the X-headers tab; None when no M365 headers."""
    lookup = {h["name"].lower(): h["value"] for h in x_headers}
    forefront = lookup.get("x-forefront-antispam-report")
    antispam = lookup.get("x-microsoft-antispam")
    org = decode_exchange_org(x_headers)
    if not (forefront or antispam or org):
        return None
    return {
        "forefront": decode_forefront(forefront) if forefront else None,
        "antispam": decode_ms_antispam(antispam) if antispam else None,
        "exchange_org": org or None,
    }


def m365_signals(decoded: dict | None, from_domain: str | None) -> list[dict]:
    """Signals contributed by the decoded M365 headers (v2 spec §5)."""
    if not decoded:
        return []
    signals: list[dict] = []
    ff = decoded.get("forefront") or {}
    sfty = ff.get("SFTY", {})
    if sfty.get("value") and str(sfty["value"]).startswith(("9.1", "9.2")):
        signals.append({
            "severity": "high", "name": "M365 flagged as phishing",
            "evidence": f"SFTY={sfty['value']} ({sfty.get('expand') or 'safety verdict'})",
            "tab": "xheaders", "anchor": "m365-decoded",
        })
    scl = ff.get("SCL", {}).get("scl")
    if scl is not None and scl >= 5:
        signals.append({
            "severity": "medium", "name": "M365 spam confidence high",
            "evidence": f"SCL={scl} ({SCL_MEANING.get(scl)})",
            "tab": "xheaders", "anchor": "m365-decoded",
        })
    cat = ff.get("CAT", {}).get("value")
    if cat in {"PHSH", "MALW", "HPHSH"}:
        signals.append({
            "severity": "high", "name": "M365 category: "
            + CAT_MEANING.get(cat, cat),
            "evidence": f"CAT={cat}",
            "tab": "xheaders", "anchor": "m365-decoded",
        })
    bcl = (decoded.get("antispam") or {}).get("BCL", {}).get("bcl")
    if bcl is not None and bcl >= 6:
        signals.append({
            "severity": "info", "name": "Bulk sender (high complaint level)",
            "evidence": f"BCL={bcl}",
            "tab": "xheaders", "anchor": "m365-decoded",
        })
    ctry = ff.get("CTRY", {})
    if ctry.get("value") and from_domain:
        cc = from_domain.rsplit(".", 1)[-1].upper()
        if len(cc) == 2 and cc.isalpha() and cc != ctry["value"].upper() and cc in _COUNTRY_NAMES:
            signals.append({
                "severity": "info", "name": "Origin country unexpected for sender domain",
                "evidence": f"CTRY={ctry['value']} "
                f"({ctry.get('expand') or ctry['value']}), From domain is .{cc.lower()}",
                "tab": "xheaders", "anchor": "m365-decoded",
            })
    return signals
