"""HTTP API: security posture (host check, CSRF), ingest, content endpoints,
attachment download hashes, delete, shutdown."""

from __future__ import annotations

import hashlib
import json
import types

from conftest import FIXTURES, upload


def test_index_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Mail Analysis Workbench" in r.text


def test_host_header_rejected(client):
    r = client.get("/api/session", headers={"host": "rebind.evil.example"})
    assert r.status_code == 403
    r = client.get("/", headers={"host": "127.0.0.1:61234"})
    assert r.status_code == 403


def test_csrf_required_on_state_changing(client):
    r = client.post(
        "/api/records",
        files={"files": ("x.eml", b"", "application/octet-stream")},  # no token
    )
    assert r.status_code == 403
    r = client.delete("/api/records/xyz")  # no token
    assert r.status_code == 403


def test_ingest_and_detail(client):
    r = upload(client, FIXTURES / "multipart_both.eml")
    assert r.status_code == 200
    body = r.json()
    assert len(body["records"]) == 1
    rid = body["records"][0]["record_id"]
    detail = client.get(f"/api/records/{rid}").json()
    assert detail["details"]["subject"] == "Your invoice is ready"
    assert detail["authentication"]["spf"]["result"] == "fail"


def test_render_is_sanitized_and_remote_blocked(client):
    upload(client, FIXTURES / "multipart_both.eml")
    rid = client.get("/api/records").json()["records"][0]["record_id"]
    r = client.get(f"/api/records/{rid}/render")
    assert r.status_code == 200
    assert "tracker.example" not in r.text
    assert "data:image/gif;base64" in r.text
    # Original (unsanitized) HTML is still available for the HTML tab.
    html = client.get(f"/api/records/{rid}/html").text
    assert "tracker.example/pixel.gif" in html


def test_plaintext_and_source(client):
    upload(client, FIXTURES / "multipart_both.eml")
    rid = client.get("/api/records").json()["records"][0]["record_id"]
    pt = client.get(f"/api/records/{rid}/plaintext")
    assert pt.status_code == 200
    assert "evil-example.com/login" in pt.text
    src = client.get(f"/api/records/{rid}/source")
    assert "Return-Path:" in src.text
    assert "BOUND1" in src.text


def test_attachment_download_hash_matches(client):
    upload(client, FIXTURES / "forwarded_inner.eml")
    rid = client.get("/api/records").json()["records"][0]["record_id"]
    parsed = client.get(f"/api/records/{rid}").json()
    att = parsed["attachments"][0]
    r = client.get(f"/api/records/{rid}/attachments/{att['sha256']}")
    assert r.status_code == 200
    assert r.headers["content-disposition"].startswith("attachment")
    data = r.content
    assert hashlib.sha256(data).hexdigest() == att["sha256"]
    assert hashlib.md5(data).hexdigest() == att["md5"]
    assert hashlib.sha1(data).hexdigest() == att["sha1"]
    # Bad hashes are rejected.
    assert client.get(f"/api/records/{rid}/attachments/{'0' * 64}").status_code == 404
    assert client.get(f"/api/records/{rid}/attachments/../../etc/passwd").status_code in (400, 404)


def test_delete_record(client):
    upload(client, FIXTURES / "plaintext_only.eml")
    rid = client.get("/api/records").json()["records"][0]["record_id"]
    r = client.delete(f"/api/records/{rid}", headers={"X-CSRF-Token": client.csrf})
    assert r.status_code == 200
    assert client.get(f"/api/records/{rid}").status_code == 404
    assert client.get("/api/records").json()["records"] == []


def test_issues_surfaced(client):
    r = upload(client, FIXTURES / "zip_wrongpass.zip")
    body = r.json()
    assert body["records"] == []
    assert any("password-protected" in i["reason"] for i in body["issues"])


def test_shutdown_sets_exit_flag(client):
    client.app.state.server = types.SimpleNamespace(should_exit=False)
    r = client.post("/api/shutdown", headers={"X-CSRF-Token": client.csrf})
    assert r.status_code == 200
    assert client.app.state.server.should_exit is True


def test_load_remote_content_flag_logs_and_returns_original(client, capsys):
    upload(client, FIXTURES / "html_only.eml")
    rid = client.get("/api/records").json()["records"][0]["record_id"]
    r = client.get(f"/api/records/{rid}/render?remote=1")
    assert r.status_code == 200
    assert "tracker.example/pixel.gif" in r.text  # remote kept, per opt-in
    err = capsys.readouterr().err
    assert json.dumps({"event": "load-remote-content", "record": rid}) in err
