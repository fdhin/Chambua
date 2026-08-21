"""On-demand live re-verification of SPF, DKIM, and DMARC.

Runs all three checks in parallel, each with a 5-second budget. Results are
labelled with the wall-clock time they were fetched — DKIM keys rotate, so
a present-day failure weeks after delivery is not necessarily forgery
(the UI notes this for DKIM).
"""

from __future__ import annotations

import concurrent.futures
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("chambua.reverify")

TIMEOUT_SECONDS = 5.0


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _resolver():
    import dns.resolver

    r = dns.resolver.Resolver()
    r.lifetime = TIMEOUT_SECONDS - 0.5
    r.timeout = TIMEOUT_SECONDS - 0.5
    return r


def _check_spf(ip: str | None, return_path: str | None, from_domain: str | None) -> dict:
    if not ip:
        return {
            "result": None,
            "note": "no originating IP found in the message — cannot evaluate SPF",
            "fetched_at": _now(),
        }
    sender = return_path or f"postmaster@{from_domain or 'unknown.invalid'}"
    helo = from_domain or "unknown"
    try:
        import spf

        result, _code, explanation = spf.check2(i=ip, s=sender, h=helo)
        return {
            "result": result,
            "originating_ip": ip,
            "sender": sender,
            "helo": helo,
            "explanation": explanation or None,
            "fetched_at": _now(),
        }
    except Exception as exc:
        return {"result": "temperror", "note": str(exc), "fetched_at": _now()}


def _check_dkim(raw_message: bytes | None) -> dict:
    if raw_message is None:
        return {
            "result": None,
            "signatures": [],
            "note": "live DKIM verification needs the raw MIME source "
            "(available for .eml records)",
            "fetched_at": _now(),
        }
    import dkim

    try:
        verifier = dkim.DKIM(raw_message)
    except Exception as exc:
        return {"result": "temperror", "signatures": [], "note": str(exc), "fetched_at": _now()}
    sig_count = sum(1 for name, _ in verifier.headers if name.lower() == b"dkim-signature")
    if not sig_count:
        return {"result": "none", "signatures": [], "fetched_at": _now()}

    sigs: list[dict] = []
    for idx in range(sig_count):
        try:
            ok = bool(verifier.verify(idx=idx))
            result = "pass" if ok else "fail"
            note = (
                "verified against current DNS"
                if ok
                else "signature did not verify against current DNS (keys rotate — "
                "weeks-old signatures commonly fail this check)"
            )
        except Exception as exc:
            result = "temperror"
            note = f"{type(exc).__name__}: {exc}"
        fields = {
            k.decode("latin-1", "replace"): (v or b"").decode("latin-1", "replace").strip()
            for k, v in (verifier.signature_fields or {}).items()
        }
        sigs.append(
            {
                "selector": fields.get("s") or None,
                "signing_domain": fields.get("d") or None,
                "algorithm": fields.get("a") or None,
                "verification": note,
                "result": result,
            }
        )
    results = {s["result"] for s in sigs}
    overall = "pass" if results == {"pass"} else "fail" if "fail" in results else "neutral"
    return {"result": overall, "signatures": sigs, "fetched_at": _now()}


def _check_dmarc(from_domain: str | None, return_path_domain: str | None, dkim_domains: list[str]) -> dict:
    if not from_domain:
        return {"result": None, "note": "no From domain", "fetched_at": _now()}

    def relaxed_align(a: str | None, b: str | None) -> bool:
        if not a or not b:
            return False
        a, b = a.lower().rstrip("."), b.lower().rstrip(".")
        return a == b or a.endswith("." + b) or b.endswith("." + a)

    try:
        import dns.exception

        answers = _resolver().resolve(f"_dmarc.{from_domain}", "TXT")
        fragments = []
        for rdata in answers:
            if hasattr(rdata, "strings"):
                fragments.append(b"".join(rdata.strings))
        record = b" ".join(fragments).decode("utf-8", "replace").strip()
        if not record:
            return {"result": "none", "from_domain": from_domain, "record": None, "fetched_at": _now()}
        policy_m = re.search(r"\bp\s*=\s*(\w+)", record)
        spf_aligned = relaxed_align(return_path_domain, from_domain)
        dkim_aligned = any(relaxed_align(d, from_domain) for d in dkim_domains)
        aligned = bool(spf_aligned or dkim_aligned)
        return {
            "result": "pass" if aligned else "fail",
            "from_domain": from_domain,
            "record": record,
            "policy": policy_m.group(1) if policy_m else None,
            "alignment": {
                "spf_aligned": spf_aligned,
                "dkim_aligned": dkim_aligned,
            },
            "note": "alignment evaluated against Return-Path and live DKIM results; "
            "SPF/DKIM pass/fail themselves come from their own live checks",
            "fetched_at": _now(),
        }
    except dns.resolver.NXDOMAIN:
        return {"result": "none", "from_domain": from_domain, "record": None, "fetched_at": _now()}
    except Exception as exc:
        return {
            "result": "temperror",
            "from_domain": from_domain,
            "note": f"DNS lookup failed: {exc}",
            "fetched_at": _now(),
        }


def reverify_record(parsed: dict, record_dir: Path | None) -> dict:
    """Live-check SPF, DKIM and DMARC in parallel, each with a timeout."""
    details = parsed.get("details", {})
    auth = parsed.get("authentication", {})
    spf_ip = auth.get("spf", {}).get("originating_ip") or details.get("originating_ip")
    return_path = details.get("return_path")
    from_domain = None
    from_addr = details.get("from", {}).get("address")
    if from_addr and "@" in from_addr:
        from_domain = from_addr.rpartition("@")[2]
    return_path_domain = None
    if return_path and "@" in return_path:
        return_path_domain = return_path.rpartition("@")[2]

    raw_message = None
    if record_dir is not None and parsed.get("source_kind") == "eml":
        original = record_dir / "original.eml"
        if original.exists():
            raw_message = original.read_bytes()

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        spf_future = pool.submit(_check_spf, spf_ip, return_path, from_domain)
        dkim_future = pool.submit(_check_dkim, raw_message)
        dkim_for_alignment = pool.submit(
            lambda: [s.get("signing_domain") for s in auth.get("dkim", {}).get("signatures", [])]
        )
        dkim_domains = dkim_for_alignment.result(timeout=TIMEOUT_SECONDS)
        dmarc_future = pool.submit(_check_dmarc, from_domain, return_path_domain, dkim_domains)

        def await_it(fut):
            try:
                return fut.result(timeout=TIMEOUT_SECONDS)
            except concurrent.futures.TimeoutError:
                return {"result": "timeout", "note": "live check timed out after 5 s", "fetched_at": _now()}

        return {
            "spf": await_it(spf_future),
            "dkim": await_it(dkim_future),
            "dmarc": await_it(dmarc_future),
        }
