"""Ingest pipeline: extension routing, zip handling, failure modes."""

from __future__ import annotations

from mail_workbench.ingest import IngestResult, ingest_bytes


def run(ws, data: bytes, filename: str):
    result = IngestResult()
    ingest_bytes(ws, data, filename, result)
    return result


def test_unsupported_extension(ws):
    result = run(ws, b"hello", "notes.txt")
    assert len(result.records) == 0
    assert result.issues[0]["reason"].startswith("Unsupported file type: .txt")
    assert "Accepted: .msg, .eml, .zip" in result.issues[0]["reason"]


def test_zip_infected_password(ws, fx):
    result = run(ws, (fx / "zip_infected.zip").read_bytes(), "zip_infected.zip")
    assert len(result.records) == 1
    assert result.records[0]["source_kind"] == "eml"
    assert result.records[0]["extracted_from_zip"] == "zip_infected.zip"
    assert result.issues == []


def test_zip_wrong_password_fails_cleanly(ws, fx):
    result = run(ws, (fx / "zip_wrongpass.zip").read_bytes(), "zip_wrongpass.zip")
    assert len(result.records) == 0
    assert any("password-protected, unknown password" in i["reason"] for i in result.issues)


def test_nested_zip_not_extracted(ws, fx):
    result = run(ws, (fx / "zip_nested.zip").read_bytes(), "zip_nested.zip")
    assert len(result.records) == 0
    assert any("nested archive — not extracted" in i["reason"] for i in result.issues)


def test_mixed_zip(ws, fx):
    result = run(ws, (fx / "zip_mixed.zip").read_bytes(), "zip_mixed.zip")
    kinds = sorted(r["source_kind"] for r in result.records)
    assert kinds == ["eml", "msg"]
    assert any(".pdf" in i["reason"] for i in result.issues)


def test_parse_failure_is_visible(ws):
    result = run(ws, b"\x00\x01\x02garbage-not-a-msg", "broken.msg")
    assert len(result.records) == 0
    assert result.issues and result.issues[0]["stage"] == "parse"
    assert result.issues[0]["retryable"] is True


def test_workspace_layout(ws, fx):
    result = run(ws, (fx / "multipart_both.eml").read_bytes(), "multipart_both.eml")
    record = result.records[0]
    record_dir = ws.record_dir(record["record_id"])
    assert (record_dir / "original.eml").exists()
    assert (record_dir / "parsed.json").exists()
    assert (record_dir / "rendered.html").exists()
    assert (record_dir / "plaintext.txt").exists()
