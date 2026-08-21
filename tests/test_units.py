"""Unit tests: URL helpers, Received chain, Authentication-Results, sanitizer."""

from __future__ import annotations

import pytest

from mail_workbench.authresults import parse_authentication_results, summarize_dkim
from mail_workbench.received import parse_transmission
from mail_workbench.sanitize import PLACEHOLDER_IMG, sanitize_html
from mail_workbench.urls import (
    collect_urls,
    defang,
    extract_from_plaintext,
    idn_forms,
    registrable_domain,
    same_registrable,
)

# ---------------------------------------------------------------- URLs


def test_defang():
    assert defang("https://evil.example.com/login") == "hxxps://evil[.]example[.]com/login"
    assert defang("http://a.b.c/") == "hxxp://a[.]b[.]c/"
    assert defang("ftp://x.net/f") == "fxp://x[.]net/f"
    assert defang("mailto:a@b.com") == "mailto:a@b.com"


def test_registrable_domain():
    assert registrable_domain("sub.microsoft.com") == "microsoft.com"
    assert registrable_domain("microsoft.com") == "microsoft.com"
    assert registrable_domain("a.b.co.uk") == "b.co.uk"
    assert registrable_domain("deep.a.example.co.jp") == "example.co.jp"
    assert same_registrable("login.microsoft.com", "microsoft.com")
    assert not same_registrable("evil-example.com", "microsoft.com")


def test_idn_forms():
    expected_puny = "b\u00fccher-beispiel.de".encode("idna").decode("ascii")
    display, puny = idn_forms("b\u00fccher-beispiel.de")
    assert puny == expected_puny
    display, puny = idn_forms(expected_puny)
    assert display == "b\u00fccher-beispiel.de"
    assert idn_forms("plain.example") == ("plain.example", None)


def test_plaintext_url_extraction():
    urls = extract_from_plaintext(
        "Go to https://example.com/a, or http://example.com/b.\nwww.bare.example ends here."
    )
    found = {u["url"] for u in urls}
    assert "https://example.com/a" in found
    assert "http://example.com/b" in found
    assert "http://www.bare.example" in found


def test_collect_urls_signals():
    urls = collect_urls(
        '<a href="http://phish.example/x">http://real.example/y</a>'
        '<a href="https://corp.example/z">safe words</a>',
        None,
        {},
        "corp.example",
    )
    by_url = {u["url"]: u for u in urls}
    assert by_url["http://phish.example/x"]["anchor_mismatch"] is True
    assert by_url["https://corp.example/z"]["anchor_mismatch"] is False
    assert by_url["http://phish.example/x"]["differs_from_from_domain"] is True
    assert by_url["https://corp.example/z"]["differs_from_from_domain"] is False


# ---------------------------------------------------------------- Received


def test_received_chain_inverts_to_oldest_first():
    newest = (
        "from mx2 (mx2.example.net [198.51.100.9]) by vault.corp.example "
        'with ESMTPS (version=TLS1_2 cipher=ECDHE) id Q1; Tue, 18 Nov 2025 16:04:05 +0000'
    )
    oldest = "from spammer.vps ([203.0.113.7]) by mx2.example.net with SMTP id Z9; Tue, 18 Nov 2025 16:04:04 +0000"
    hops = parse_transmission([newest, oldest])
    assert [h["hop"] for h in hops] == [1, 2]
    assert hops[0]["received_from"]["ip"] == "203.0.113.7"
    assert hops[0]["received_by"]["host"] == "mx2.example.net"
    assert hops[1]["received_by"]["host"] == "vault.corp.example"
    assert hops[1]["tls"] and "TLS1_2" in hops[1]["tls"]
    assert hops[1]["id"] == "Q1"
    assert hops[0]["timestamp"].startswith("2025-11-18T16:04:04")
    assert hops[0]["raw"] == oldest


# ---------------------------------------------------------------- Auth-Results


def test_authresults_full():
    header = (
        "mx.corp.example; spf=fail (sender IP is 203.0.113.66) "
        "smtp.mailfrom=evil-example.com; dkim=pass (2048-bit key) "
        "header.d=corp.example header.s=sel1 header.b=AAAA; "
        "dmarc=fail action=quarantine header.from=evil-example.com; compauth=fail"
    )
    auth = parse_authentication_results([header])
    assert auth["source"] == "header"
    assert auth["spf"]["result"] == "fail"
    assert auth["spf"]["originating_ip"] == "203.0.113.66"
    assert auth["spf"]["return_path_domain"] == "evil-example.com"
    (sig,) = auth["dkim"]["signatures"]
    assert sig == {
        "selector": "sel1",
        "signing_domain": "corp.example",
        "algorithm": None,
        "verification": "2048-bit key",
        "result": "pass",
    }
    assert auth["dmarc"]["from_domain"] == "evil-example.com"
    assert auth["extras"][0]["method"] == "compauth"


def test_authresults_absent():
    auth = parse_authentication_results(None)
    assert auth["source"] is None
    assert auth["spf"]["result"] is None


def test_dkim_summary():
    assert summarize_dkim([]) == "No signatures"
    assert summarize_dkim([{"result": "pass"}]) == "1 Signature — 1 PASS"
    assert summarize_dkim([{"result": "pass"}, {"result": "neutral"}]) == \
        "2 Signatures — 1 PASS, 1 NEUTRAL"


# ---------------------------------------------------------------- Sanitizer


def test_sanitizer_strips_active_content():
    dirty = (
        '<html><body onload="x()">'
        "<script>alert(1)</script>"
        '<a href="javascript:evil()">click</a>'
        '<img src="https://t.example/p.gif" onerror="steal()">'
        '<meta http-equiv="refresh" content="0;url=http://evil.example">'
        "<p>ok</p></body></html>"
    )
    clean = sanitize_html(dirty)
    low = clean.lower()
    assert "<script" not in low
    assert "onerror" not in low
    assert "onload" not in low
    assert "javascript:" not in low
    assert "<meta" not in low
    assert "<p>ok</p>" in clean


def test_remote_content_blocked_by_default():
    html = (
        '<p><a href="http://link.example/a">go</a>'
        '<img src="https://tracker.example/pixel.gif">'
        '<video poster="https://cdn.example/v.jpg"></video>'
        '<div style="background:url(https://css.example/bg.png)">x</div></p>'
    )
    clean = sanitize_html(html)
    assert "tracker.example" not in clean
    assert "css.example" not in clean
    assert PLACEHOLDER_IMG in clean
    # Links stay inspectable — they only fetch on an explicit click.
    assert 'href="http://link.example/a"' in clean


def test_remote_content_allowed_when_opted_in():
    html = '<img src="https://tracker.example/pixel.gif">'
    clean = sanitize_html(html, block_remote=False)
    assert "https://tracker.example/pixel.gif" in clean


def test_css_import_blocked():
    html = "<style>@import url(https://evil.example/s.css); body{color:red}</style><p>x</p>"
    clean = sanitize_html(html)
    assert "evil.example" not in clean
    assert "color:red" in clean


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00\x01\x02",
        "<a href='".encode() + b"A" * 5000,
        "&lt;&gt;&quot;".encode() * 1000,
    ],
)
def test_sanitizer_never_raises(payload):
    sanitize_html(payload.decode("utf-8", errors="replace"))
