"""Parse ``Authentication-Results:`` headers (RFC 8601, loosely).

This reads what the receiving MTA decided at delivery time — the source of
truth for the Authentication tab. Missing header → all-None sections and the
UI prompts the user to run a live re-verify instead of fabricating results.
"""

from __future__ import annotations

import re

_COMMENT = re.compile(r"\([^()]*\)")
_IP_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SPF_RESULTS = {"pass", "fail", "neutral", "softfail", "none", "temperror", "permerror"}
DKIM_RESULTS = {"pass", "fail", "neutral", "none", "temperror", "permerror"}
DMARC_RESULTS = {"pass", "fail", "none", "temperror", "permerror"}


def _split_clauses(value: str) -> list[str]:
    """Split on ';' that are outside parenthesised comments."""
    clauses: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in value:
        if ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == ";" and depth == 0:
            clauses.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        clauses.append("".join(cur))
    return clauses


def _clause_comment(clause: str) -> str:
    return " ".join(m.strip("()").strip() for m in _COMMENT.findall(clause)).strip()


def _empty_authentication() -> dict:
    return {
        "spf": {
            "result": None,
            "originating_ip": None,
            "rdns": None,
            "return_path_domain": None,
            "record": None,
        },
        "dkim": {"result": None, "signatures": []},
        "dmarc": {"result": None, "from_domain": None, "record": None},
        "extras": [],
        "source": None,
    }


def parse_authentication_results(values: list[str] | None) -> dict:
    """Parse one or more Authentication-Results headers into the schema."""
    auth = _empty_authentication()
    if not values:
        return auth

    for header_value in values:
        for clause in _split_clauses(header_value):
            tokens = _COMMENT.sub(" ", clause).split()
            if not tokens or "=" not in tokens[0]:
                # Leading authserv-id token, e.g. "spf.protection.outlook.com"
                continue
            method, result = tokens[0].split("=", 1)
            method = method.lower()
            props = _parse_props(tokens[1:])
            comment_text = _clause_comment(clause)
            if method == "spf":
                auth["spf"]["result"] = result.lower()
                mailfrom = props.get("smtp.mailfrom")
                if mailfrom:
                    domain = mailfrom.strip("<>").rpartition("@")[2] or mailfrom
                    auth["spf"]["return_path_domain"] = domain
                ip = props.get("smtp.remote-ip") or props.get("ip")
                if not ip:
                    m = _IP_IN_TEXT.search(comment_text)
                    ip = m.group(0) if m else None
                auth["spf"]["originating_ip"] = ip
                rdns = props.get("smtp.rdns") or props.get("helo")
                auth["spf"]["rdns"] = rdns
                auth["spf"]["_comment"] = comment_text or None
            elif method == "dkim":
                sig = {
                    "selector": props.get("header.s"),
                    "signing_domain": props.get("header.d"),
                    "algorithm": None,
                    "verification": comment_text or None,
                    "result": result.lower(),
                }
                auth["dkim"]["signatures"].append(sig)
            elif method == "dmarc":
                auth["dmarc"]["result"] = result.lower()
                auth["dmarc"]["from_domain"] = props.get("header.from")
                auth["dmarc"]["_comment"] = comment_text or None
            else:
                auth["extras"].append(
                    {"method": method, "result": result, "properties": props or None}
                )

    if auth["dkim"]["signatures"]:
        results = {s["result"] for s in auth["dkim"]["signatures"]}
        if len(results) == 1:
            auth["dkim"]["result"] = results.pop()
        elif "fail" in results:
            auth["dkim"]["result"] = "fail"
        elif "neutral" in results or "temperror" in results or "permerror" in results:
            auth["dkim"]["result"] = "neutral"
        else:
            auth["dkim"]["result"] = "neutral"
    auth["source"] = "header"
    return auth


def _parse_props(tokens: list[str]) -> dict:
    props: dict[str, str] = {}
    for tok in tokens:
        if "=" in tok:
            k, v = tok.split("=", 1)
            props[k.lower()] = v.strip("<>")
    return props


def summarize_dkim(signatures: list[dict]) -> str:
    """One-line summary like '2 Signatures — 1 PASS, 1 NEUTRAL'."""
    n = len(signatures)
    if n == 0:
        return "No signatures"
    counts: dict[str, int] = {}
    for s in signatures:
        counts[s.get("result") or "unknown"] = counts.get(s.get("result") or "unknown", 0) + 1
    label = "Signature" if n == 1 else "Signatures"
    parts = ", ".join(f"{v} {k.upper()}" for k, v in counts.items())
    return f"{n} {label} — {parts}"
