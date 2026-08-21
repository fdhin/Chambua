"""FastAPI application: record ingest, per-record content endpoints,
live re-verify, and shutdown. Binds 127.0.0.1 only; state-changing
endpoints require the CSRF token; every response carries a CSP that keeps
the sandboxed render pane free of scripts and remote fetches."""

from __future__ import annotations

import json
import logging
import shutil
import sys
import threading
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .ingest import IngestResult, ingest_bytes, load_parsed
from .parse_eml import extract_html_body
from .paths import static_dir
from .reverify import reverify_record
from .sanitize import sanitize_html
from .security import CsrfGuard, HostCheckMiddleware

log = logging.getLogger("mail-workbench.server")

MAX_UPLOAD_BYTES = 200 * 1024 * 1024

CSP = (
    "default-src 'self'; img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; script-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'none'"
)


def create_app(workspace, guard: CsrfGuard, allowed_hosts: set[str]) -> FastAPI:
    app = FastAPI(title="Mail Analysis Workbench", version=__version__, docs_url=None, redoc_url=None)
    app.add_middleware(HostCheckMiddleware, allowed_hosts=allowed_hosts)
    app.state.workspace = workspace
    app.state.records: dict[str, dict] = {}
    app.state.issues: list[dict] = []
    app.state.lock = threading.Lock()
    app.state.reverify_cache: dict[str, dict] = {}

    @app.middleware("http")
    async def csp_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def get_record(rid: str) -> dict:
        with app.state.lock:
            rec = app.state.records.get(rid)
        if rec is None:
            raise HTTPException(status_code=404, detail="unknown record")
        return rec

    @app.get("/")
    def index():
        return FileResponse(static_dir() / "index.html")

    @app.get("/api/session")
    def session_info():
        return {"csrf_token": guard.issue(), "version": __version__}

    @app.post("/api/records", dependencies=[Depends(guard.require_header)])
    def create_records(files: list[UploadFile] = File(...)):
        result = IngestResult()
        for upload in files:
            name = Path(upload.filename or "unnamed").name
            data = upload.file.read(MAX_UPLOAD_BYTES + 1)
            upload.file.close()
            if len(data) > MAX_UPLOAD_BYTES:
                result.add_issue(name, "file too large (over 200 MB)", stage="upload")
                continue
            ingest_bytes(app.state.workspace, data, name, result)
        with app.state.lock:
            for rec in result.records:
                app.state.records[rec["record_id"]] = rec
            app.state.issues.extend(result.issues)
        return {"records": result.records, "issues": result.issues}

    @app.get("/api/records")
    def list_records():
        with app.state.lock:
            records = list(app.state.records.values())
            issues = list(app.state.issues)
        return {"records": records, "issues": issues}

    @app.get("/api/records/{rid}")
    def get_record_detail(rid: str):
        get_record(rid)
        parsed = load_parsed(app.state.workspace, rid)
        if parsed is None:
            raise HTTPException(status_code=410, detail="record data missing")
        with app.state.lock:
            reverified = app.state.reverify_cache.get(rid)
        if reverified:
            parsed["live_verification"] = reverified
        return parsed

    @app.delete("/api/records/{rid}", dependencies=[Depends(guard.require_header)])
    def delete_record(rid: str):
        get_record(rid)
        with app.state.lock:
            app.state.records.pop(rid, None)
            app.state.reverify_cache.pop(rid, None)
        record_dir = app.state.workspace.record_dir(rid)
        if record_dir is not None:
            shutil.rmtree(record_dir, ignore_errors=True)
        return {"ok": True}

    def _original_bytes(rid: str) -> bytes | None:
        record_dir = app.state.workspace.record_dir(rid)
        if record_dir is None:
            return None
        for ext in (".eml", ".msg"):
            p = record_dir / f"original{ext}"
            if p.exists():
                return p.read_bytes()
        return None

    @app.get("/api/records/{rid}/render")
    def get_render(rid: str, remote: bool = False):
        get_record(rid)
        parsed = load_parsed(app.state.workspace, rid)
        if parsed is None or not parsed["content"]["has_html"]:
            raise HTTPException(status_code=404, detail="no HTML body")
        if remote:
            # Explicit, per-record, per-session opt-in — logged to stderr.
            print(
                json.dumps({"event": "load-remote-content", "record": rid}),
                file=sys.stderr,
            )
            raw_html = extract_html_body(_original_bytes(rid) or b"") or ""
            html = sanitize_html(raw_html, block_remote=False)
        else:
            record_dir = app.state.workspace.record_dir(rid)
            html = (record_dir / "rendered.html").read_text(encoding="utf-8")
        return Response(content=html, media_type="text/html; charset=utf-8")

    @app.get("/api/records/{rid}/html")
    def get_html_source(rid: str):
        get_record(rid)
        parsed = load_parsed(app.state.workspace, rid)
        if parsed is None or not parsed["content"]["has_html"]:
            raise HTTPException(status_code=404, detail="no HTML body")
        raw_html = extract_html_body(_original_bytes(rid) or b"") or ""
        return Response(content=raw_html, media_type="text/plain; charset=utf-8")

    @app.get("/api/records/{rid}/plaintext")
    def get_plaintext(rid: str):
        get_record(rid)
        parsed = load_parsed(app.state.workspace, rid)
        if parsed is None or not parsed["content"]["has_plaintext"]:
            raise HTTPException(status_code=404, detail="no plaintext part")
        record_dir = app.state.workspace.record_dir(rid)
        text = (record_dir / "plaintext.txt").read_text(encoding="utf-8", errors="replace")
        return Response(content=text, media_type="text/plain; charset=utf-8")

    @app.get("/api/records/{rid}/source")
    def get_source(rid: str):
        get_record(rid)
        data = _original_bytes(rid)
        if data is None:
            raise HTTPException(status_code=410, detail="original source missing")
        return Response(content=data, media_type="text/plain; charset=utf-8")

    @app.get("/api/records/{rid}/attachments/{sha256}")
    def download_attachment(rid: str, sha256: str):
        get_record(rid)
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise HTTPException(status_code=400, detail="bad hash")
        record_dir = app.state.workspace.record_dir(rid)
        blob = record_dir / "attachments" / f"{sha256}.bin" if record_dir else None
        if blob is None or not blob.exists():
            raise HTTPException(status_code=404, detail="attachment not found")
        parsed = load_parsed(app.state.workspace, rid) or {}
        display = "attachment.bin"
        for att in parsed.get("attachments", []):
            if att.get("sha256") == sha256:
                display = Path(att.get("filename") or display).name
                break
        quoted = display.replace('"', "'")
        return Response(
            content=blob.read_bytes(),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{quoted}"; '
                    f"filename*=UTF-8''{_quote_filename(display)}"
                )
            },
        )

    @app.post("/api/records/{rid}/reverify", dependencies=[Depends(guard.require_header)])
    def reverify(rid: str):
        get_record(rid)
        parsed = load_parsed(app.state.workspace, rid)
        if parsed is None:
            raise HTTPException(status_code=410, detail="record data missing")
        record_dir = app.state.workspace.record_dir(rid)
        result = reverify_record(parsed, record_dir)
        with app.state.lock:
            app.state.reverify_cache[rid] = result
        return result

    @app.post("/api/shutdown", dependencies=[Depends(guard.require_header)])
    def shutdown():
        server = getattr(app.state, "server", None)
        if server is not None:
            server.should_exit = True
        return {"ok": True}

    app.mount("/static", StaticFiles(directory=str(static_dir())), name="static")
    return app


def _quote_filename(name: str) -> str:
    from urllib.parse import quote

    return quote(name, safe="")
