"""Ingest pipeline: route dropped files to parsers, handle zips.

Extension is the contract (§4.1 — no magic-byte sniffing in v1):

    .eml → parse_eml
    .msg → parse_msg
    .zip → extract once (no password, then the sandbox-convention password
           ``infected``), route contents back through ingest

Every failure or skip is surfaced as a visible entry — silent failure is
forbidden. Zip bombs are capped: 200 MB uncompressed per entry, 500 MB per
archive.
"""

from __future__ import annotations

import io
import logging
import uuid
from pathlib import Path

from .parse_eml import parse_eml
from .parse_msg import parse_msg
from .workspace import Workspace

log = logging.getLogger("chambua.ingest")

SUPPORTED_EXTENSIONS = {".eml", ".msg", ".zip"}
ZIP_CONVENTION_PASSWORD = b"infected"
MAX_ZIP_MEMBER_BYTES = 200 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 500 * 1024 * 1024


class IngestResult:
    def __init__(self):
        self.records: list[dict] = []
        self.issues: list[dict] = []

    def add_issue(self, filename: str, reason: str, *, retryable: bool = False, stage: str = "ingest"):
        entry = {"filename": filename, "reason": reason, "retryable": retryable, "stage": stage}
        self.issues.append(entry)
        log.info(
            "ingest issue {filename=%s, stage=%s, reason=%s}", filename, stage, reason
        )


def _ext(name: str) -> str:
    return Path(name).suffix.lower()


def ingest_bytes(
    workspace: Workspace,
    data: bytes,
    filename: str,
    result: IngestResult,
    extracted_from_zip: str | None = None,
) -> None:
    """Route one file (already in memory) through the pipeline."""
    ext = _ext(filename)
    if ext not in SUPPORTED_EXTENSIONS:
        result.add_issue(
            filename,
            f"Unsupported file type: {ext or '(none)'}. Accepted: .msg, .eml, .zip",
            stage="route",
        )
        return

    if ext == ".zip":
        _ingest_zip(workspace, data, filename, result)
        return

    record_id = str(uuid.uuid4())
    record_dir = workspace.new_record_dir(record_id)
    try:
        (record_dir / f"original{ext}").write_bytes(data)
        if ext == ".eml":
            parsed = parse_eml(data, record_id, filename, extracted_from_zip, record_dir)
        else:
            parsed = parse_msg(data, record_id, filename, extracted_from_zip, record_dir)
    except Exception as exc:
        log.exception("parse failed for %s", filename)
        result.add_issue(
            filename, f"{type(exc).__name__}: {exc}", retryable=True, stage="parse"
        )
        return
    result.records.append(_summary(parsed, record_dir))


def _ingest_zip(workspace: Workspace, data: bytes, filename: str, result: IngestResult) -> None:
    import pyzipper

    zf = None
    password_used = None
    try:
        zf = pyzipper.AESZipFile(io.BytesIO(data))
        names = zf.namelist()
        # Probe read to check for encryption.
        if names:
            try:
                zf.read(names[0])
            except RuntimeError:
                zf.close()
                zf = pyzipper.AESZipFile(io.BytesIO(data))
                zf.setpassword(ZIP_CONVENTION_PASSWORD)
                try:
                    zf.read(names[0])
                    password_used = "infected"
                except RuntimeError:
                    result.add_issue(
                        filename,
                        "password-protected, unknown password",
                        stage="zip-open",
                    )
                    return
    except Exception as exc:
        result.add_issue(filename, f"could not open zip: {exc}", retryable=True, stage="zip-open")
        return

    try:
        total = 0
        for name in names:
            if name.endswith("/"):
                continue
            base = name.rsplit("/", 1)[-1]
            if not base:
                continue
            inner_ext = _ext(base)
            if inner_ext == ".zip":
                result.add_issue(base, "nested archive — not extracted", stage="zip-member")
                continue
            if inner_ext not in SUPPORTED_EXTENSIONS:
                result.add_issue(
                    base,
                    f"Unsupported file type: {inner_ext or '(none)'}. "
                    "Accepted: .msg, .eml, .zip",
                    stage="zip-member",
                )
                continue
            info = zf.getinfo(name)
            if info.file_size > MAX_ZIP_MEMBER_BYTES:
                result.add_issue(base, "zip member too large (over 200 MB)", stage="zip-member")
                continue
            total += info.file_size
            if total > MAX_ZIP_TOTAL_BYTES:
                result.add_issue(filename, "zip total uncompressed size too large (over 500 MB)", stage="zip-member")
                return
            try:
                member_data = zf.read(name)
            except RuntimeError:
                result.add_issue(base, "password-protected member", stage="zip-member")
                continue
            except Exception as exc:
                result.add_issue(base, f"could not read member: {exc}", stage="zip-member")
                continue
            ingest_bytes(workspace, member_data, base, result, extracted_from_zip=filename)
    finally:
        zf.close()


def _summary(parsed: dict, record_dir: Path) -> dict:
    details = parsed["details"]
    return {
        "record_id": parsed["record_id"],
        "source_file": parsed["source_file"],
        "source_kind": parsed["source_kind"],
        "extracted_from_zip": parsed["extracted_from_zip"],
        "subject": details.get("subject"),
        "from": details.get("from", {}).get("address"),
        "timestamp": details.get("timestamp"),
        "attachment_count": len(parsed.get("attachments", [])),
        "url_count": len(parsed.get("urls", [])),
        "has_html": parsed["content"]["has_html"],
        "has_plaintext": parsed["content"]["has_plaintext"],
        "parse_warnings": parsed.get("parse_warnings"),
        "record_dir": str(record_dir),
    }


def load_parsed(workspace: Workspace, record_id: str) -> dict | None:
    record_dir = workspace.record_dir(record_id)
    if record_dir is None:
        return None
    import json

    parsed_path = record_dir / "parsed.json"
    if not parsed_path.exists():
        return None
    try:
        return json.loads(parsed_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
