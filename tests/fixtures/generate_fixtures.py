"""Generate the deterministic test fixtures for the chambua suite.

Run:  .venv/bin/python tests/fixtures/generate_fixtures.py

The .msg fixtures are built with extract-msg's own OleWriter against a
hand-rolled minimal property stream, so the bytes are spec-shaped
(MS-OXMSG) and readable by extract-msg itself.
"""

from __future__ import annotations

import io
import struct
from pathlib import Path

import pyzipper

FIXTURES = Path(__file__).resolve().parent

# ----------------------------------------------------------------------
# shared message content


def rfc822_headers(overrides: dict | None = None) -> str:
    base = {
        "return_path": "<billing@evil-example.com>",
        "received": (
            "Received: from mx.receiver.example (mx.receiver.example [198.51.100.9])\n"
            "\tby mail.corp.example with ESMTPS id abc123; Mon, 17 Nov 2025 09:15:02 +0100\n"
            "Received: from vps-attacker.host (vps-attacker.host [203.0.113.66])\n"
            "\tby mx.receiver.example with ESMTP id def456; Mon, 17 Nov 2025 09:15:01 +0100"
        ),
        "auth_results": (
            "Authentication-Results: spf.protection.outlook.com;\n"
            "\tspf=fail (sender IP is 203.0.113.66) smtp.mailfrom=evil-example.com;\n"
            "\tdkim=none (message not signed) header.d=none;\n"
            "\tdmarc=fail action=quarantine header.from=evil-example.com; compauth=fail"
        ),
        "from": '"Microsoft Billing" <billing@evil-example.com>',
        "reply_to": "support@phish-collection.example",
        "to": "alice@corp.example",
        "subject": "Your invoice is ready",
        "date": "Mon, 17 Nov 2025 09:14:55 +0100",
        "message_id": "<CAF123@evil-example.com>",
        "x_headers": "X-Microsoft-Antispam-Mailbox-Delivery: grhf:1|jaj:0\nX-Sender-IP: 203.0.113.66",
    }
    if overrides:
        base.update(overrides)
    parts = []
    if base.get("return_path"):
        parts.append(f"Return-Path: {base['return_path']}")
    if base.get("received"):
        parts.append(base["received"])
    if base.get("auth_results"):
        parts.append(base["auth_results"])
    parts.append(f"From: {base['from']}")
    if base.get("reply_to"):
        parts.append(f"Reply-To: {base['reply_to']}")
    parts.append(f"To: {base['to']}")
    parts.append(f"Subject: {base['subject']}")
    parts.append(f"Date: {base['date']}")
    parts.append(f"Message-ID: {base['message_id']}")
    if base.get("x_headers"):
        parts.append(base["x_headers"])
    return "\n".join(parts) + "\n"


PLAINTEXT_BODY = (
    "View your invoice at http://evil-example.com/login?ref=99 "
    "or https://portal-microsoft-example.com/pay\n"
)

HTML_BODY = """<html><body>
<p>Dear customer,</p>
<p><a href="http://evil-example.com/login?ref=99">https://login.microsoftonline.com</a></p>
<img src="https://tracker.example/pixel.gif" width="1" height="1">
</body></html>
"""

# ----------------------------------------------------------------------


def write_eml(name: str, headers: str, body: str, *, mime: str = "text/plain") -> None:
    if mime == "text/plain":
        content = (
            f"{headers}MIME-Version: 1.0\n"
            f"Content-Type: text/plain; charset=utf-8\n\n"
            f"{body}"
        )
    elif mime == "text/html":
        content = (
            f"{headers}MIME-Version: 1.0\n"
            f"Content-Type: text/html; charset=utf-8\n\n"
            f"{body}"
        )
    else:
        raise ValueError(mime)
    (FIXTURES / name).write_text(content, encoding="utf-8")


def multipart_eml(name: str, headers: str, plaintext: str, html: str) -> None:
    b = "BOUND1"
    content = (
        f"{headers}MIME-Version: 1.0\n"
        f'Content-Type: multipart/alternative; boundary="{b}"\n\n'
        f"--{b}\nContent-Type: text/plain; charset=utf-8\n\n{plaintext}\n"
        f"--{b}\nContent-Type: text/html; charset=utf-8\n\n{html}\n"
        f"--{b}--\n"
    )
    (FIXTURES / name).write_text(content, encoding="utf-8")


# ----------------------------------------------------------------------


def build_all() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)

    # 1. plaintext-only
    write_eml(
        "plaintext_only.eml",
        rfc822_headers(),
        PLAINTEXT_BODY,
        mime="text/plain",
    )

    # 2. html-only
    write_eml(
        "html_only.eml",
        rfc822_headers(),
        HTML_BODY,
        mime="text/html",
    )

    # 3. multipart/alternative with both parts
    multipart_eml("multipart_both.eml", rfc822_headers(), PLAINTEXT_BODY, HTML_BODY)

    # 4. forwarded phish: attached .eml (message/rfc822)
    inner = (
        "From: ceo@spoofed-boss.example\n"
        "To: alice@corp.example\n"
        "Subject: FW: urgent wire transfer\n"
        "Date: Mon, 17 Nov 2025 08:00:00 +0100\n"
        "Message-ID: <INNER9@spoofed-boss.example>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "Please process this immediately.\n"
    )
    forwarded = (
        rfc822_headers({"subject": "FW: FW: urgent wire transfer"})
        + "MIME-Version: 1.0\n"
        + 'Content-Type: multipart/mixed; boundary="MIX9"\n\n'
        + "--MIX9\n"
        + "Content-Type: text/plain; charset=utf-8\n\n"
        + "See forwarded message below.\n"
        + "--MIX9\n"
        + 'Content-Type: message/rfc822; name="urgent.eml"\n'
        + 'Content-Disposition: attachment; filename="urgent.eml"\n\n'
        + inner
        + "\n--MIX9--\n"
    )
    (FIXTURES / "forwarded_inner.eml").write_text(forwarded, encoding="utf-8")

    # 5. no Authentication-Results
    write_eml(
        "no_auth_results.eml",
        rfc822_headers({"auth_results": None}),
        "Plain message with no stamped auth results.\n",
    )

    # 6. multiple DKIM signatures (one pass, one neutral)
    multi_dkim = (
        "Authentication-Results: mx.receiver.example;\n"
        "\tdkim=pass (2048-bit key) header.d=corp.example header.s=sel1 header.b=AAAAB;\n"
        "\tdkim=neutral (bad signature) header.d=evil-example.com header.s=x2013 header.b=CCCCD;\n"
        "\tspf=pass (sender IP is 198.51.100.9) smtp.mailfrom=corp.example;\n"
        "\tdmarc=pass action=none header.from=corp.example"
    )
    write_eml(
        "multi_dkim.eml",
        rfc822_headers(
            {
                "auth_results": multi_dkim,
                "from": "IT Helpdesk <helpdesk@corp.example>",
                "return_path": "<bounce@corp.example>",
                "subject": "Weekly IT bulletin",
            }
        ),
        "Body of the multi-dkim fixture.\nSee https://intranet.corp.example/news\n",
    )

    # 7. international / IDN domains (unicode + punycode side by side)
    puny_idn = "b\u00fccher-beispiel.de".encode("idna").decode("ascii")
    idn_headers = (
        "Return-Path: <rechnung@b\u00fccher-beispiel.de>\n"
        f"Received: from mx.b\u00fccher-beispiel.de (mx.{puny_idn} [192.0.2.77])\n"
        "\tby mail.corp.example with ESMTP; Mon, 17 Nov 2025 10:00:00 +0100\n"
        "Authentication-Results: mx.corp.example; spf=none smtp.mailfrom=b\u00fccher-beispiel.de\n"
        "From: \"B\u00fccher Beispiel\" <rechnung@b\u00fccher-beispiel.de>\n"
        "To: alice@corp.example\n"
        "Subject: =?utf-8?q?Rechnung?=\n"
        "Date: Mon, 17 Nov 2025 09:59:00 +0100\n"
        f"Message-ID: <IDN1@{puny_idn}>\n"
        "MIME-Version: 1.0\n"
    )
    (FIXTURES / "idn_domains.eml").write_text(
        idn_headers + "Content-Type: text/plain; charset=utf-8\n\n"
        "Buchen Sie hier: https://b\u00fccher-beispiel.de/anmelden "
        f"oder http://{puny_idn}/anmelden\n",
        encoding="utf-8",
    )

    # 8. tracking pixel
    pixel_headers = rfc822_headers({
        "subject": "Newsletter",
        "from": "News <news@marketing.example>",
        "auth_results": None,
    })
    write_eml(
        "tracking_pixel.eml",
        pixel_headers,
        '<html><body><p>Our November deals!</p>'
        '<img src="https://click.marketing.example/open.gif?u=alice" width="1" height="1">'
        "</body></html>",
        mime="text/html",
    )

    # 9. anchor mismatch phish
    mismatch_headers = rfc822_headers({
        "subject": "Action required",
        "from": "Security Team <security@microsoft-verify-example.com>",
    })
    write_eml(
        "anchor_mismatch.eml",
        mismatch_headers,
        '<html><body><p>Verify your account:</p>'
        '<a href="http://evil-example.com/verify">https://login.microsoft.com/verify</a>'
        "</body></html>",
        mime="text/html",
    )

    # 10. malformed: declared multipart, truncated before any boundary
    malformed = (
        rfc822_headers({"subject": "Broken message"})
        + "MIME-Version: 1.0\n"
        + 'Content-Type: multipart/alternative; boundary="MISSING"\n\n'
        + "This body never reaches a boundary\u2014 the message was truncated "
        "mid-t\u00e9l\u00e9chargement an"
    )
    (FIXTURES / "malformed.eml").write_text(malformed, encoding="utf-8")

    # 11/12. .msg fixtures (Unicode + old ANSI codepage)
    _write_msg_fixture("msg_unicode.msg", unicode_=True)
    _write_msg_fixture("msg_ansi.msg", unicode_=False)

    # 13. zip, password "infected"
    with pyzipper.AESZipFile(FIXTURES / "zip_infected.zip", "w") as zf:
        zf.setpassword(b"infected")
        zf.setencryption(pyzipper.WZ_AES)
        zf.writestr("payload.eml", (FIXTURES / "plaintext_only.eml").read_text())

    # 14. zip with a different (unknown) password
    with pyzipper.AESZipFile(FIXTURES / "zip_wrongpass.zip", "w") as zf:
        zf.setpassword(b"hunter2")
        zf.setencryption(pyzipper.WZ_AES)
        zf.writestr("payload.eml", (FIXTURES / "plaintext_only.eml").read_text())

    # 15. zip containing another zip (nested — must not recurse)
    inner_zip = io.BytesIO()
    with pyzipper.AESZipFile(inner_zip, "w") as zf:
        zf.writestr("deeper.zip", b"not really a zip, we never get there")
    with pyzipper.AESZipFile(FIXTURES / "zip_nested.zip", "w") as zf:
        zf.writestr("inner.zip", inner_zip.getvalue())

    # 16. mixed zip: .msg + .eml + .pdf
    with pyzipper.AESZipFile(FIXTURES / "zip_mixed.zip", "w") as zf:
        zf.write(FIXTURES / "msg_unicode.msg", "report.msg")
        zf.write(FIXTURES / "multipart_both.eml", "letter.eml")
        zf.writestr("brochure.pdf", b"%PDF-1.4 dummy pdf bytes for fixture\n%%EOF\n")

    print(f"fixtures written to {FIXTURES}")


# ----------------------------------------------------------------------
# .msg builder


def _prop(prop_id: int, prop_type: int, length: int) -> bytes:
    """One 16-byte MS-OXMSG property record for a variable-length property."""
    return struct.pack("<2HI2I", prop_type, prop_id, 0, length, 0)


def _msg_streams(unicode_: bool) -> list[tuple[str, bytes | None]]:
    """Streams (path, data) for a synthetic .msg. None ⇒ storage."""
    tstr = "001F" if unicode_ else "001E"  # string property type

    def enc(s: str) -> bytes:
        if unicode_:
            return s.encode("utf-16-le") + b"\x00\x00"
        return s.encode("cp1252") + b"\x00"

    subject = "Invoice für November" if not unicode_ else "Invoice for November"
    body = "Please review the attached invoice.\n"
    html = (
        "<html><body><p>Please review the attached invoice.</p>"
        '<a href="http://evil-example.com/pay">https://invoice.microsoft.com</a>'
        "</body></html>"
    )
    to_display = "Alice Example <alice@corp.example>"
    pdf_bytes = (
        b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R"
        b"/MediaBox[0 0 200 100]>>endobj\nxref\n0 4\ntrailer<</Size 4/Root 1 0 R>>\n%%EOF"
    )
    transport_headers = (
        "Return-Path: <billing@evil-example.com>\n"
        "Received: from mail.corp.example (mail.corp.example [198.51.100.9])\n"
        "\tby mailbox.corp.example with ESMTPS id xyz789; Mon, 17 Nov 2025 09:15:02 +0100\n"
        "Received: from vps-attacker.host (vps-attacker.host [203.0.113.66])\n"
        "\tby mail.corp.example with ESMTP id def456; Mon, 17 Nov 2025 09:15:01 +0100\n"
        "Authentication-Results: mail.corp.example;\n"
        "\tspf=fail (sender IP is 203.0.113.66) smtp.mailfrom=evil-example.com;\n"
        "\tdkim=none (message not signed);\n"
        "\tdmarc=fail action=quarantine header.from=evil-example.com\n"
        'From: "Microsoft Billing" <billing@evil-example.com>\n'
        "To: alice@corp.example\n"
        f"Subject: {subject}\n"
        "Date: Mon, 17 Nov 2025 09:14:55 +0100\n"
        "Message-ID: <MSGFIX1@evil-example.com>\n"
        "X-Microsoft-Antispam-Mailbox-Delivery: grhf:1|jaj:0"
    )

    streams: list[tuple[str, bytes | None]] = [
        ("__nameid_version1.0", None),
        ("__nameid_version1.0/__substg1.0_00020102", b""),
        ("__nameid_version1.0/__substg1.0_00030102", b""),
        ("__nameid_version1.0/__substg1.0_00040102", b""),
        ("__substg1.0_001A" + tstr, enc("IPM.Note")),
        ("__substg1.0_0037" + tstr, enc(subject)),
        ("__substg1.0_007D" + tstr, enc(transport_headers)),
        ("__substg1.0_1000" + tstr, enc(body)),
        ("__substg1.0_10130102", html.encode("utf-8") if unicode_ else html.encode("cp1252")),
        ("__substg1.0_0E04" + tstr, enc(to_display)),
        ("__attach_version1.0_#00000000", None),
        ("__attach_version1.0_#00000000/__properties_version1.0",
         b"\x00" * 8 + _prop(0x3707, int(tstr, 16), len(enc("rechnung.pdf")))),
        ("__attach_version1.0_#00000000/__substg1.0_3707" + tstr, enc("rechnung.pdf")),
        ("__attach_version1.0_#00000000/__substg1.0_37010102", pdf_bytes),
    ]

    props = b"\x00" * 8 + struct.pack("<4I", 0, 1, 0, 1) + b"\x00" * 8
    for pid, data in (
        (0x001A, enc("IPM.Note")),
        (0x0037, enc(subject)),
        (0x007D, enc(transport_headers)),
        (0x1000, enc(body)),
        (0x0E04, enc(to_display)),
        (0x1013, streams[8][1]),
    ):
        props += _prop(pid, int(tstr, 16), len(data))
    streams.insert(0, ("__properties_version1.0", props))
    return streams


def _write_msg_fixture(name: str, *, unicode_: bool) -> None:
    from extract_msg.ole_writer import OleWriter

    writer = OleWriter()
    for path, data in _msg_streams(unicode_):
        writer.addEntry(path, data=data, storage=data is None)
    writer.write(FIXTURES / name)


if __name__ == "__main__":
    build_all()
