"""Parsing of the .eml fixtures into the normalized schema."""

from __future__ import annotations

import json

from conftest import FIXTURES

from mail_workbench.parse_eml import parse_eml


def parse(ws, name: str):
    record_dir = ws.new_record_dir("test-record")
    data = (FIXTURES / name).read_bytes()
    return parse_eml(data, "test-record", name, None, record_dir), record_dir


def test_multipart_both(ws):
    parsed, _ = parse(ws, "multipart_both.eml")
    assert parsed["content"]["has_html"] is True
    assert parsed["content"]["has_plaintext"] is True
    d = parsed["details"]
    assert d["from"] == {
        "address": "billing@evil-example.com",
        "display_name": "Microsoft Billing",
    }
    assert d["reply_to"] == "support@phish-collection.example"
    assert d["to"] == ["alice@corp.example"]
    assert d["originating_ip"] == "203.0.113.66"
    assert d["rdns"] == "vps-attacker.host"
    assert d["timestamp"] == "2025-11-17T09:14:55+01:00"
    auth = parsed["authentication"]
    assert auth["source"] == "header"
    assert auth["spf"]["result"] == "fail"
    assert auth["spf"]["originating_ip"] == "203.0.113.66"
    assert auth["spf"]["return_path_domain"] == "evil-example.com"
    assert auth["dmarc"]["result"] == "fail"
    assert auth["dmarc"]["from_domain"] == "evil-example.com"
    assert any(e["method"] == "compauth" for e in auth["extras"])


def test_transmission_order_oldest_first(ws):
    parsed, _ = parse(ws, "multipart_both.eml")
    hops = parsed["transmission"]
    assert len(hops) == 2
    assert hops[0]["hop"] == 1
    assert hops[0]["received_from"]["host"] == "vps-attacker.host"
    assert hops[0]["received_from"]["ip"] == "203.0.113.66"
    assert hops[0]["received_by"]["host"] == "mx.receiver.example"
    assert hops[1]["received_by"]["host"] == "mail.corp.example"
    assert hops[0]["raw"].startswith("from vps-attacker.host")


def test_url_signals(ws):
    parsed, _ = parse(ws, "multipart_both.eml")
    by_url = {u["url"]: u for u in parsed["urls"]}
    login = by_url["http://evil-example.com/login?ref=99"]
    assert login["anchor_mismatch"] is True
    assert login["anchor_text"] == "https://login.microsoftonline.com"
    assert login["defanged"] == "hxxp://evil-example[.]com/login?ref=99"
    # Same registrable domain as From → no differs flag.
    assert login["differs_from_from_domain"] is False
    pixel = by_url["https://tracker.example/pixel.gif"]
    assert pixel["source"] == "html_src"
    assert pixel["differs_from_from_domain"] is True
    # Dedupe: same URL in plaintext and html is one entry.
    assert len([u for u in parsed["urls"] if "evil-example.com/login" in u["url"]]) == 1
    # Header-derived URLs present.
    assert any(u["url"] == "mailto:support@phish-collection.example" for u in parsed["urls"])


def test_plaintext_only(ws):
    parsed, _ = parse(ws, "plaintext_only.eml")
    assert parsed["content"]["has_plaintext"] is True
    assert parsed["content"]["has_html"] is False


def test_html_only(ws):
    parsed, _ = parse(ws, "html_only.eml")
    assert parsed["content"]["has_html"] is True
    assert parsed["content"]["has_plaintext"] is False


def test_forwarded_eml_attachment(ws):
    parsed, _ = parse(ws, "forwarded_inner.eml")
    atts = parsed["attachments"]
    assert len(atts) == 1
    att = atts[0]
    assert att["filename"].endswith(".eml")
    assert len(att["sha256"]) == 64
    assert att["is_archive"] is False


def test_no_auth_results(ws):
    parsed, _ = parse(ws, "no_auth_results.eml")
    auth = parsed["authentication"]
    assert auth["source"] is None
    assert auth["spf"]["result"] is None
    assert auth["dkim"]["result"] is None
    assert auth["dmarc"]["result"] is None


def test_multiple_dkim_signatures(ws):
    parsed, _ = parse(ws, "multi_dkim.eml")
    sigs = parsed["authentication"]["dkim"]["signatures"]
    assert len(sigs) == 2
    results = {s["selector"]: s["result"] for s in sigs}
    assert results == {"sel1": "pass", "x2013": "neutral"}
    domains = {s["selector"]: s["signing_domain"] for s in sigs}
    assert domains == {"sel1": "corp.example", "x2013": "evil-example.com"}


def test_idn_domains(ws):
    parsed, _ = parse(ws, "idn_domains.eml")
    from mail_workbench.urls import idn_forms
    puny = "b\u00fccher-beispiel.de".encode("idna").decode("ascii")
    display, decoded_puny = idn_forms("b\u00fccher-beispiel.de")
    assert decoded_puny == puny
    urls = [u["url"] for u in parsed["urls"]]
    assert any("b\u00fccher-beispiel.de" in u for u in urls)
    assert any(puny in u for u in urls)


def test_tracking_pixel(ws):
    parsed, _ = parse(ws, "tracking_pixel.eml")
    assert any(
        u["url"] == "https://click.marketing.example/open.gif?u=alice"
        and u["source"] == "html_src"
        for u in parsed["urls"]
    )


def test_anchor_mismatch_phish(ws):
    parsed, _ = parse(ws, "anchor_mismatch.eml")
    (m,) = [u for u in parsed["urls"] if u["anchor_mismatch"]]
    assert m["url"] == "http://evil-example.com/verify"
    assert m["anchor_text"] == "https://login.microsoft.com/verify"
    assert m["differs_from_from_domain"] is True


def test_malformed_eml_fails_gracefully(ws):
    parsed, _ = parse(ws, "malformed.eml")
    # No crash: a record exists with headers, and the truncation is surfaced.
    assert parsed["details"]["subject"] == "Broken message"
    assert parsed.get("parse_warnings")


def test_parsed_json_is_complete_schema(ws, tmp_path):
    parsed, record_dir = parse(ws, "multipart_both.eml")
    on_disk = json.loads((record_dir / "parsed.json").read_text())
    for key in (
        "record_id", "source_file", "source_kind", "extracted_from_zip",
        "details", "authentication", "urls", "attachments", "transmission",
        "x_headers", "content",
    ):
        assert key in on_disk, key
    for key in (
        "from", "sender", "to", "cc", "reply_to", "in_reply_to", "message_id",
        "timestamp", "return_path", "originating_ip", "rdns", "subject",
    ):
        assert key in on_disk["details"], key
    assert on_disk == parsed
