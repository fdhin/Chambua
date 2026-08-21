"""Parsing of the generated .msg fixtures (Unicode and legacy ANSI)."""

from __future__ import annotations

from conftest import FIXTURES

from mail_workbench.parse_msg import parse_msg


def parse(ws, name: str):
    record_dir = ws.new_record_dir("test-record")
    data = (FIXTURES / name).read_bytes()
    return parse_msg(data, "test-record", name, None, record_dir)


def test_unicode_msg(ws):
    parsed = parse(ws, "msg_unicode.msg")
    assert parsed["source_kind"] == "msg"
    d = parsed["details"]
    assert d["subject"] == "Invoice for November"
    assert d["from"]["address"] == "billing@evil-example.com"
    assert d["from"]["display_name"] == "Microsoft Billing"
    assert d["to"] == ["alice@corp.example"]
    assert d["originating_ip"] == "203.0.113.66"
    assert d["timestamp"] == "2025-11-17T09:14:55+01:00"
    auth = parsed["authentication"]
    assert auth["spf"]["result"] == "fail"
    assert auth["dmarc"]["result"] == "fail"
    assert len(parsed["transmission"]) == 2
    assert parsed["content"]["has_html"] is True
    assert parsed["content"]["has_plaintext"] is True
    (att,) = parsed["attachments"]
    assert att["filename"] == "rechnung.pdf"
    assert att["extension"] == "pdf"
    assert att["size_bytes"] > 0
    assert any(u["anchor_mismatch"] for u in parsed["urls"])


def test_ansi_msg(ws):
    parsed = parse(ws, "msg_ansi.msg")
    assert parsed["details"]["subject"] == "Invoice für November"
    assert parsed["details"]["from"]["address"] == "billing@evil-example.com"
    assert parsed["content"]["has_html"] is True
    assert len(parsed["attachments"]) == 1


def test_msg_via_zip(ws, fx):
    from mail_workbench.ingest import IngestResult, ingest_bytes

    result = IngestResult()
    ingest_bytes(ws, (fx / "zip_mixed.zip").read_bytes(), "zip_mixed.zip", result)
    msg_records = [r for r in result.records if r["source_kind"] == "msg"]
    assert len(msg_records) == 1
    assert msg_records[0]["extracted_from_zip"] == "zip_mixed.zip"
