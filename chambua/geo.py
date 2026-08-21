"""GeoIP + ASN enrichment for Received-chain hops (v2 spec §9).

No database is bundled with v2 builds (decision, 2026-08): the reader
lazily looks for chambua/data/GeoLite2-City.mmdb + GeoLite2-ASN.mmdb (or
the DB-IP Lite equivalents, which use the same mmdb format) and the
enrichment degrades to None when they are absent — hops then render
exactly as in v1. Dropping a compatible mmdb into app data enables geo
on the next launch, no rebuild.
"""

from __future__ import annotations

import logging
import threading

from .paths import data_dir

log = logging.getLogger("chambua.geo")

_lock = threading.Lock()
_city_reader = None
_asn_reader = None
_tried = False

CITY_DB_NAMES = ("GeoLite2-City.mmdb", "dbip-city-lite.mmdb")
ASN_DB_NAMES = ("GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb")


def _find(names: tuple[str, ...]):
    for name in names:
        candidate = data_dir() / name
        if candidate.exists():
            return candidate
    return None


def _load_readers():
    global _tried, _city_reader, _asn_reader
    if _tried:
        return
    with _lock:
        if _tried:
            return
        _tried = True
        try:
            import geoip2.database

            city_path = _find(CITY_DB_NAMES)
            asn_path = _find(ASN_DB_NAMES)
            if city_path:
                _city_reader = geoip2.database.Reader(str(city_path))
            if asn_path:
                _asn_reader = geoip2.database.Reader(str(asn_path))
            if _city_reader or _asn_reader:
                log.info("GeoIP loaded (city=%s, asn=%s)",
                         bool(_city_reader), bool(_asn_reader))
        except Exception as exc:
            log.info("GeoIP unavailable: %s", exc)
            _city_reader = None
            _asn_reader = None


def lookup(ip: str | None) -> dict | None:
    """Country + ASN info for one IP, or None when no DB / not an IP.

    Never raises, never hits the network — the mmdb is pure local lookup.
    """
    if not ip:
        return None
    import ipaddress

    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
        return {"private": True, "ip": ip}

    _load_readers()
    result: dict = {"ip": ip}
    try:
        if _city_reader is not None:
            city = _city_reader.city(ip)
            result["country_code"] = city.country.iso_code
            result["country_name"] = city.country.name
        if _asn_reader is not None:
            asn = _asn_reader.asn(ip)
            result["asn"] = f"AS{asn.autonomous_system_number}"
            result["asn_org"] = asn.autonomous_system_organization
    except Exception as exc:
        log.debug("geo lookup failed for %s: %s", ip, exc)
        return None
    if "country_code" not in result and "asn" not in result:
        return None
    return result


def available() -> bool:
    _load_readers()
    return _city_reader is not None or _asn_reader is not None


def enrich_transmission(transmission: list[dict]) -> None:
    """Add geo info to each hop's endpoints, in place, when possible."""
    if not available():
        return
    for hop in transmission:
        for side in ("received_from", "received_by"):
            endpoint = hop.get(side) or {}
            ip = endpoint.get("ip")
            if ip:
                endpoint["geo"] = lookup(ip)


def geo_signals(transmission: list[dict], from_domain: str | None) -> list[dict]:
    """§9 anomaly checks; only meaningful when geo data is present."""
    signals: list[dict] = []
    if not available() or not transmission:
        return signals

    # Sender's claimed country: ccTLD of the From domain, when it is one.
    expected_cc = None
    if from_domain and len((cc := from_domain.rsplit(".", 1)[-1])) == 2 and cc.isalpha():
        expected_cc = cc.upper()

    seen_countries: set[str] = set()
    for hop in transmission:
        geo = (hop.get("received_from") or {}).get("geo") or {}
        cc = geo.get("country_code")
        if cc:
            seen_countries.add(cc)

    unexpected = [
        c for c in sorted(seen_countries)
        if expected_cc and c != expected_cc and c not in {"US", "NL", "DE", "GB", "IE"}
    ]
    # The allow-list covers the major transit hubs; only genuinely odd
    # origins get flagged, and only as Info (ESP transit makes this noisy).
    for country in unexpected:
        signals.append({
            "severity": "info",
            "name": "Unexpected origin geography",
            "evidence": f"Hop passes through {country}; sender domain claims "
            f"{expected_cc}",
            "tab": "transmission", "anchor": "hop-1",
        })
        break  # one signal is enough to prompt a look at the timeline
    return signals
