"""v2 acceptance tests (v2 spec §10): Signals rollup, TLD flagging,
consistency checks, M365 decoding, attachment inspection, URL deep
inspection, DKIM depth, GeoIP degradation."""

from __future__ import annotations

from conftest import FIXTURES

from chambua.attach_inspect import detect_magic, filename_anomalies, inspect_attachment
from chambua.consistency import consistency_checks
from chambua.geo import geo_signals, lookup, enrich_transmission
from chambua.lists import abuse_tlds, url_shorteners
from chambua.m365 import decode_m365, m365_signals
from chambua.parse_eml import parse_eml
from chambua.reverify import _rsa_key_bits
from chambua.urls import (
    collect_urls,
    idn_homoglyph,
    inspect_url_flags,
    wrapper_chain,
)


def parse(ws, name: str):
    import uuid

    rid = f"t2-{uuid.uuid4()}"
    record_dir = ws.new_record_dir(rid)
    return parse_eml((FIXTURES / name).read_bytes(), rid, name, None, record_dir)


def by_flag(urls):
    out = {}
    for u in urls:
        for f in u.get("flags") or []:
            out.setdefault(f["kind"], []).append(u)
    return out


# ---------------------------------------------------------------- §10.1


def test_signals_rollup_orders_and_anchors(ws):
    parsed = parse(ws, "attachment_anomalies.eml")
    signals = parsed["signals"]
    assert signals, "expected signals on the anomaly fixture"
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    ranks = [order[s["severity"]] for s in signals]
    assert ranks == sorted(ranks)
    for s in signals:
        assert s["name"] and s["evidence"]
        assert s["tab"] in {"details", "auth", "urls", "attachments", "transmission", "xheaders"}
        assert "anchor" in s
    # An anomaly detected in the attachments tab appears in Signals.
    assert any(s["tab"] == "attachments" for s in signals)
    # URL-sourced signals roll up on a URL-heavy fixture.
    deep = parse(ws, "deep_urls.eml")
    assert any(s["tab"] == "urls" for s in deep["signals"])


# ---------------------------------------------------------------- §10.2


def test_suspicious_tlds_flagged_and_clean_not(ws):
    parsed = parse(ws, "abuse_tlds.eml")
    flagged = by_flag(parsed["urls"]).get("suspicious_tld", [])
    flagged_domains = {u["domain"] for u in flagged}
    assert flagged_domains == {
        "shop-deals.top", "secure-login.xyz", "backup-archive.zip",
    }
    clean = [u for u in parsed["urls"] if u["domain"] in
             {"www.brand.example", "safe.example.dk", "safe.example.no"}]
    assert clean and not any(u.get("flags") for u in clean)


# ---------------------------------------------------------------- §10.3


def test_consistency_checks_fire(ws):
    parsed = parse(ws, "consistency_m365.eml")
    by_name = {c["name"]: c for c in parsed["consistency"]}
    assert by_name["Message-ID vs From domain"]["status"] == "flagged"
    assert by_name["Message-ID vs From domain"]["severity"] == "medium"
    assert by_name["Date vs first Received"]["status"] == "flagged"
    assert by_name["Date vs first Received"]["severity"] == "low"
    assert by_name["Reply-To vs From"]["status"] == "passed"
    severities = {s["name"]: s["severity"] for s in parsed["signals"]}
    assert severities["Message-ID vs From domain"] == "medium"
    assert severities["Date vs first Received"] == "low"


def test_consistency_replyto_differs_high():
    checks = consistency_checks({
        "from": {"address": "ceo@corp.example"},
        "reply_to": "ceo.gmail.attacker.example@mail.example",
    })
    by_name = {c["name"]: c for c in checks}
    assert by_name["Reply-To vs From"]["status"] == "flagged"
    assert by_name["Reply-To vs From"]["severity"] == "high"


# ---------------------------------------------------------------- §10.4


def test_m365_decoding(ws):
    parsed = parse(ws, "consistency_m365.eml")
    decoded = parsed["m365_decoded"]
    assert decoded, "M365 headers present, panel must decode"
    ff = decoded["forefront"]
    assert ff["CIP"]["value"] == "192.0.2.10"
    assert ff["CTRY"]["expand"] == "United States"
    assert ff["SCL"]["scl"] == 5
    assert ff["SCL"]["expand"] == "spam"
    assert ff["SFTY"]["value"] == "9.11"
    assert "phishing" in ff["SFTY"]["expand"]
    assert ff["CAT"]["value"] == "SPM"
    assert ff["DIR"]["expand"] == "inbound"
    assert decoded["antispam"]["BCL"]["bcl"] == 7
    assert decoded["antispam"]["BCL"]["expand"] == "medium"
    assert decoded["exchange_org"]["AuthAs"]["expand"].startswith("unauthenticated")
    assert decoded["exchange_org"]["AuthMechanism"]["value"] == "07"


def test_m365_signals():
    decoded = decode_m365([
        {"name": "X-Forefront-Antispam-Report",
         "value": "CIP:1.2.3.4;CTRY:NG;SCL:9;SFV:SPM;SFTY:9.19;CAT:PHSH;DIR:INB"},
        {"name": "X-Microsoft-Antispam", "value": "BCL:8"},
    ])
    signals = m365_signals(decoded, "supplier.example.dk")
    names = [s["name"] for s in signals]
    assert "M365 flagged as phishing" in names
    assert "M365 spam confidence high" in names
    assert "M365 category: phishing" in names
    assert "Bulk sender (high complaint level)" in names
    assert "Origin country unexpected for sender domain" in names
    assert all(s["tab"] == "xheaders" for s in signals)


def test_m365_absent_hides_panel(ws):
    parsed = parse(ws, "plaintext_only.eml")
    assert parsed["m365_decoded"] is None


# ---------------------------------------------------------------- §10.5/6


def test_attachment_anomalies(ws):
    parsed = parse(ws, "attachment_anomalies.eml")
    by_name = {a["filename"]: a for a in parsed["attachments"]}
    kinds = {name: [f["kind"] for f in (a.get("flags") or [])]
             for name, a in by_name.items()}

    rtlo = "invoice\u202efdp.exe"
    assert "rtlo" in kinds[rtlo]
    assert "executable_ext" in kinds[rtlo]

    docm = by_name["notes.docm"]
    assert docm["detected_type"] == "docm-like (Office w/ macros)"
    docm_kinds = [f["kind"] for f in docm["flags"]]
    assert "macros" in docm_kinds
    assert "autoexec" in docm_kinds
    assert any(f["kind"] == "autoexec" and f["severity"] == "high" for f in docm["flags"])
    assert docm["macro_details"]["findings"]

    clean = by_name["clean.docx"]
    assert clean["detected_type"] == "docx-like (Office)"
    assert not clean.get("flags")

    fake_pdf = by_name["statement.pdf"]
    assert "type_mismatch" in [f["kind"] for f in fake_pdf["flags"]]
    assert fake_pdf["detected_type"] == "exe/dll (Windows PE)"

    real_pdf = by_name["report.pdf"]
    pdf_kinds = [f["kind"] for f in real_pdf["flags"]]
    assert "pdf_openaction" in pdf_kinds
    assert "pdf_javascript" in pdf_kinds

    # Corresponding signals exist at matching severity.
    sig_names = {s["name"] for s in parsed["signals"]}
    assert any("RTLO" in n for n in sig_names)
    assert any("AutoExec" in n for n in sig_names)


# ---------------------------------------------------------------- §10.7


def test_url_deep_inspection(ws):
    parsed = parse(ws, "deep_urls.eml")
    flags = by_flag(parsed["urls"])
    assert {u["domain"] for u in flags["shortener"]} == {"bit.ly"}
    homoglyph_domains = {u["domain"] for u in flags["idn_homoglyph"]}
    assert "xn--pple-43d.com" in homoglyph_domains
    assert {u["domain"] for u in flags["credentials"]} == {"portal.brand.example"}
    assert {u["domain"] for u in flags["ip_host"]} == {"198.51.100.7"}
    assert {u["domain"] for u in flags["unusual_port"]} == {"portal.brand.example"}
    assert flags["data_uri"]


def test_homoglyph_unit():
    assert idn_homoglyph("xn--pple-43d.com") is True
    assert idn_homoglyph("apple.com") is False
    assert idn_homoglyph("b\u00fccher-beispiel.de") is False  # one script


def test_proofpoint_unwrap():
    from urllib.parse import quote

    target = "https://portal.brand.example/login"
    wrapped = (
        "https://urldefense.proofpoint.com/v2/url?u="
        + quote(target, safe="").replace(".", "%2E")
        + "&d=DwIGaQ&c=x&r=y&m=z&s=t"
    )
    assert wrapper_chain(wrapped) == [wrapped, target]


# ---------------------------------------------------------------- §10.8


def test_dkim_depth_signals(ws):
    parsed = parse(ws, "dkim_depth.eml")
    sigs = parsed["authentication"]["dkim"]["signatures"]
    # No Authentication-Results header: the signature is synthesized from
    # the DKIM-Signature header, result None, depth inspectable.
    assert len(sigs) == 1
    sig = sigs[0]
    assert sig["result"] is None
    depth = sig["depth"]
    assert depth["missing_critical"] == ["from"]
    assert "subject" in depth["h"]
    assert depth["l"] == 200
    assert depth["t"] == "y"
    assert depth["a"] == "rsa-sha1"
    severities = {s["name"]: s["severity"] for s in parsed["signals"]}
    assert severities["DKIM signature does not cover From header"] == "high"
    assert severities["DKIM body length limit set"] == "medium"
    assert severities["DKIM signature in test mode"] == "info"
    assert severities["DKIM uses SHA-1"] == "info"


# ---------------------------------------------------------------- §10.9


def test_geo_degrades_without_db():
    # No mmdb bundled: lookups return None (public) / private marker, and
    # hops render unchanged.
    assert lookup("93.184.216.34") is None
    priv = lookup("10.0.0.5")
    assert priv and priv.get("private") is True
    hops = [{"received_from": {"ip": "203.0.113.66"}}]
    enrich_transmission(hops)
    assert "geo" not in hops[0]["received_from"]
    assert geo_signals(hops, "example.com") == []


def test_rsa_key_bits():
    # Raw RSAPublicKey DER (what DKIM p= carries): 1024-bit modulus.
    der = bytes.fromhex("3081890281810 0".replace(" ", "") + "aa" * 128 + "0203010001")
    assert _rsa_key_bits(der) == 1024


# ---------------------------------------------------------------- misc


def test_static_lists_load():
    assert "top" in abuse_tlds() and "xyz" in abuse_tlds()
    assert "bit.ly" in url_shorteners()


def test_detect_magic_samples():
    assert detect_magic(b"%PDF-1.7") == "pdf"
    assert detect_magic(b"MZ\x90\x00" + b"\x00" * 64) == "exe/dll (Windows PE)"
    assert detect_magic(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") == "ole2 (legacy Office or .msg)"
    assert detect_magic(b"just text") is None


def test_filename_anomalies_double_extension():
    kinds = [f["kind"] for f in filename_anomalies("invoice.pdf.exe")]
    assert "double_extension" in kinds and "executable_ext" in kinds
    assert filename_anomalies("report.pdf") == []
