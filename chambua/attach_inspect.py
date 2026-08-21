"""Attachment content inspection (v2 spec §6).

Magic-byte type detection vs declared extension, filename anomalies
(RTLO, double extension, executable extensions), Office macro detection
via oletools.olevba, and PDF anomaly markers (JavaScript / OpenAction /
embedded files / launch actions) scanned from raw and zlib-inflated
streams — oletools 0.60 no longer ships pdfid, so that scan is local.

Nothing is ever executed or extracted; olevba parses VBA storage bytes
only. Files over 20 MB skip the deep Office scan (oletools cost);
magic-byte and filename checks always run.
"""

from __future__ import annotations

import io
import logging
import re
import zipfile

log = logging.getLogger("chambua.attach_inspect")

RTLO = "\u202e"

EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "js", "jse", "hta",
    "msi", "ps1", "lnk", "iso", "img", "wsf", "vbe", "sh", "jar",
}

DOUBLE_EXTENSION_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|txt|jpg|jpeg|png|zip|html?)\."
    r"(exe|scr|bat|cmd|com|pif|vbs|js|jse|hta|msi|ps1|lnk|iso|img|wsf|vbe|jar|zip)$",
    re.IGNORECASE,
)

OFFICE_FOR_MACRO_SCAN = {"doc", "docm", "xls", "xlsm", "ppt", "pptm", "dotm", "xltm"}
MAX_DEEP_SCAN_BYTES = 20 * 1024 * 1024

_AUTOEXEC_TRIGGERS = (
    "autoopen", "workbook_open", "document_open", "auto_close",
    "autoexit", "document_beforeclose", "document_beforesave",
    "class_initialize", "workbook_open",
)


def detect_magic(data: bytes) -> str | None:
    """Best-effort magic-byte sniffing (pure Python, no libmagic)."""
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = set(zf.namelist())
                if "[Content_Types].xml" in names or "word/document.xml" in names:
                    if any(n.startswith("word/vbaProject.bin") for n in names):
                        return "docm-like (Office w/ macros)"
                    if any(n.startswith("xl/") for n in names):
                        return "xlsx-like (Office)"
                    if any(n.startswith("ppt/") for n in names):
                        return "pptx-like (Office)"
                    return "docx-like (Office)"
                if "mimetype" in names:
                    return "epub/odf container"
        except Exception:
            pass
        return "zip"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole2 (legacy Office or .msg)"
    if data.startswith(b"MZ"):
        return "exe/dll (Windows PE)"
        # note: an .msg file never starts with MZ; OLE .msg handled above.
    if data.startswith(b"\x7fELF"):
        return "elf executable"
    if data.startswith(b"Rar!\x1a\x07"):
        return "rar archive"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z archive"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"ustar") or data[257:262] == b"ustar":
        return "tar"
    if data.startswith(b"\x89PNG"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"GIF8"):
        return "gif"
    if data[:6] in (b"II*\x00\x08\x00", b"MM\x00*\x00\x08") or data.startswith(b"II*\x00"):
        return "tiff"
    if data.startswith(b"BM"):
        return "bmp"
    if data.startswith(b"{\\rtf"):
        return "rtf"
    if data.startswith(b"SQLite format 3"):
        return "sqlite database"
    return None


def filename_anomalies(filename: str) -> list[dict]:
    """RTLO, double extension, executable extension."""
    flags: list[dict] = []
    if RTLO in filename:
        flags.append({
            "kind": "rtlo", "severity": "high",
            "label": "RTLO in filename",
            "detail": "Right-to-Left Override character reverses the visible "
                      "extension in most file listings",
        })
    if DOUBLE_EXTENSION_RE.search(filename):
        flags.append({
            "kind": "double_extension", "severity": "medium",
            "label": "Double extension",
            "detail": "Extension pair suggests a disguised executable",
        })
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in EXECUTABLE_EXTENSIONS:
        flags.append({
            "kind": "executable_ext", "severity": "high",
            "label": "Executable",
            "detail": f".{ext} files execute code when opened",
        })
    return flags


def office_macro_scan(data: bytes, filename: str) -> dict | None:
    """olevba scan; returns None when not applicable or too large."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in OFFICE_FOR_MACRO_SCAN:
        return None
    if len(data) > MAX_DEEP_SCAN_BYTES:
        return {"skipped": "file too large for macro scan (>20 MB)"}
    findings: list[dict] = []
    has_macros = False
    autoexec = False
    suspicious = False
    try:
        from oletools.olevba import VBA_Parser

        # ftguess needs a filename + raw bytes; file objects are rejected.
        parser = VBA_Parser(filename or "attachment", data=data)
        try:
            if parser.detect_vba_macros():
                has_macros = True
                for (_fname, _stream, vba_filename, code) in parser.extract_macros():
                    lowered = (code or "").lower()
                    triggers = [t for t in _AUTOEXEC_TRIGGERS if t in lowered]
                    if triggers:
                        autoexec = True
                        findings.append({
                            "where": vba_filename or "(module)",
                            "kind": "autoexec",
                            "detail": "Auto-exec trigger: " + ", ".join(sorted(set(triggers))),
                        })
                    for keyword in (
                        "shell", "createobject", "urldownloadtofile",
                        "powershell", "wscript.shell", "auto_open",
                        "environ(", "chr(",
                    ):
                        if keyword in lowered:
                            suspicious = True
                            findings.append({
                                "where": vba_filename or "(module)",
                                "kind": "suspicious",
                                "detail": f"Suspicious keyword: {keyword}",
                            })
        finally:
            parser.close()
    except Exception as exc:  # olevba raises a zoo of exceptions on odd files
        log.info("olevba scan failed for %s: %s", filename, exc)
        return {"skipped": f"macro scan failed: {type(exc).__name__}"}
    return {
        "has_macros": has_macros,
        "autoexec": autoexec,
        "suspicious": suspicious,
        "findings": findings,
    }


_PDF_MARKERS = {
    "JavaScript": rb"/JavaScript\b",
    "OpenAction": rb"/OpenAction\b|/AA\b",
    "embedded file": rb"/EmbeddedFile\b",
    "launch action": rb"/Launch\b",
}


def _pdf_marker_scan(data: bytes) -> list[str]:
    """Scan raw bytes plus every zlib-inflated stream for the marker names
    that matter. Most object dictionaries sit in the clear; compressed
    object streams are inflated and rescanned."""
    text = data
    inflated: list[bytes] = []
    for m in re.finditer(rb"stream\r?\n", data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end == -1:
            continue
        try:
            import zlib

            inflated.append(zlib.decompress(data[start:end]))
        except Exception:
            continue
    if inflated:
        text = data + b"".join(inflated)
    found = []
    for label, pattern in _PDF_MARKERS.items():
        if re.search(pattern, text):
            found.append(label)
    return found


def pdf_anomaly_scan(data: bytes, filename: str) -> dict | None:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext != "pdf":
        return None
    if len(data) > MAX_DEEP_SCAN_BYTES or not data.startswith(b"%PDF"):
        return {"anomalies": []}
    return {"anomalies": _pdf_marker_scan(data)}


def inspect_attachment(data: bytes, filename: str, extension: str) -> dict:
    """Full inspection for one attachment; merged into parsed.json."""
    detected = detect_magic(data)
    flags: list[dict] = []

    declared = (extension or "").lower()
    # Expected detected family for a declared extension.
    family = {
        "pdf": "pdf", "zip": "zip", "doc": "ole2", "xls": "ole2", "ppt": "ole2",
        "docx": "docx-like", "xlsx": "xlsx-like", "pptx": "pptx-like",
        "docm": "docm-like", "xlsm": "xlsx-like",
        "png": "png", "jpg": "jpeg", "jpeg": "jpeg", "gif": "gif",
        "exe": "exe/dll", "js": None, "txt": None, "eml": None,
    }.get(declared)
    if detected and family and not detected.startswith(family) and family not in detected:
        flags.append({
            "kind": "type_mismatch", "severity": "medium",
            "label": "Type mismatch",
            "detail": f"Extension says .{declared} but magic bytes say "
                      f"{detected}",
        })

    flags.extend(filename_anomalies(filename))

    macros = office_macro_scan(data, filename)
    if macros and macros.get("has_macros"):
        flags.append({
            "kind": "macros", "severity": "medium",
            "label": "Contains macros",
            "detail": "VBA macro project present",
        })
        if macros.get("autoexec"):
            flags.append({
                "kind": "autoexec", "severity": "high",
                "label": "Contains AutoExec",
                "detail": "Macro runs automatically on open",
            })
        if macros.get("suspicious"):
            flags.append({
                "kind": "suspicious_vba", "severity": "high",
                "label": "Suspicious VBA",
                "detail": "Macro code uses suspicious keywords "
                          "(Shell, CreateObject, …)",
            })

    pdf = pdf_anomaly_scan(data, filename)
    if pdf:
        for anomaly in pdf.get("anomalies", []):
            flags.append({
                "kind": "pdf_" + anomaly.replace(" ", "_").lower(),
                "severity": "high" if anomaly == "launch action" else "medium",
                "label": f"Contains {anomaly}" if not anomaly.startswith("embedded")
                else "Contains embedded file",
                "detail": f"PDF declares {anomaly}",
            })

    return {
        "detected_type": detected,
        "flags": flags or None,
        "macro_details": (macros if macros and macros.get("findings") else None),
        "pdf_anomalies": (pdf.get("anomalies") if pdf else None) or None,
    }
