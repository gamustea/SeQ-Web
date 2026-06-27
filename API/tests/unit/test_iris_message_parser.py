"""Tests unitarios de Fase 2: parser de mensaje completo y reglas que
dependen del cuerpo/enlaces/adjuntos (``needs_context=True``).
"""

from __future__ import annotations

import pytest

from src.modules.iris.services.message_parser import parse_raw_message, MessageContext, Attachment
from src.modules.iris.rules.received_chain import check_received_chain
from src.modules.iris.rules.body_links import check_body_links
from src.modules.iris.rules.body_content import check_body_content
from src.modules.iris.rules.suspicious_attachments import check_suspicious_attachments

pytestmark = pytest.mark.unit


# --------------------------------------------------------------- message parser

def test_parse_headers_only_input_has_empty_body():
    raw = "From: a@b.com\nSubject: Hi\nDate: Wed, 25 Jun 2025 10:00:00 +0000\n"
    ctx = parse_raw_message(raw)
    assert ctx.body_text == ""
    assert ctx.body_html == ""
    assert ctx.links == []
    assert ctx.attachments == []
    assert ctx.headers["from"] == "a@b.com"


def test_parse_multipart_message_extracts_html_links_and_attachment():
    raw = (
        "From: a@b.com\r\n"
        "Subject: Hi\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n"
        "\r\n"
        "--BOUND\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body><a href=\"http://evil.example.com/x\">paypal.com</a></body></html>\r\n"
        "--BOUND\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename=\"invoice.exe\"\r\n"
        "\r\n"
        "binarydata\r\n"
        "--BOUND--\r\n"
    )
    ctx = parse_raw_message(raw)
    assert "evil.example.com" in ctx.body_html
    assert len(ctx.links) == 1
    assert ctx.links[0].href == "http://evil.example.com/x"
    assert ctx.links[0].text == "paypal.com"
    assert len(ctx.attachments) == 1
    assert ctx.attachments[0].filename == "invoice.exe"


# --------------------------------------------------------------- Received chain (C3/C8)

def test_received_chain_neutral_when_absent():
    ctx = MessageContext(headers={})
    result = check_received_chain(ctx)
    assert result.verdict == "neutral"
    assert result.score == 0


def test_received_chain_flags_private_origin_ip():
    ctx = MessageContext(
        headers={"date": "Wed, 25 Jun 2025 10:00:00 +0000"},
        received_headers=[
            "from mx.example.com by mx2.example.com; Wed, 25 Jun 2025 10:00:00 +0000",
            "from [10.0.0.5] by mx.example.com; Wed, 25 Jun 2025 09:59:00 +0000",
        ],
    )
    result = check_received_chain(ctx)
    assert result.verdict == "fail"
    assert result.score < 0


def test_received_chain_flags_date_mismatch():
    ctx = MessageContext(
        headers={"date": "Wed, 25 Jun 2025 10:00:00 +0000"},
        received_headers=[
            "from mx.example.com by mx2.example.com; Thu, 26 Jun 2025 20:00:00 +0000",
        ],
    )
    result = check_received_chain(ctx)
    assert result.verdict == "fail"


def test_received_chain_passes_when_consistent():
    ctx = MessageContext(
        headers={"date": "Wed, 25 Jun 2025 10:00:00 +0000"},
        received_headers=[
            "from mx.example.com by mx2.example.com; Wed, 25 Jun 2025 09:59:30 +0000",
        ],
    )
    result = check_received_chain(ctx)
    assert result.verdict == "pass"


# --------------------------------------------------------------- Body links (C10)

def test_body_links_neutral_when_no_links():
    ctx = MessageContext(headers={})
    result = check_body_links(ctx)
    assert result.verdict == "neutral"


def test_body_links_flags_cloaked_link():
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"http://attacker.example.net/login\">paypal.com</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "cloaked_link" in result.details["types"]


def test_body_links_flags_punycode_host():
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"http://xn--pypal-4ve.com/x\">click here</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "punycode" in result.details["types"]


def test_body_links_flags_known_shortener():
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"http://bit.ly/abc123\">click here</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "shortener" in result.details["types"]


def test_body_links_passes_when_clean():
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"https://some-business.com/notes\">Ver notas</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "pass"


# --------------------------------------------------------------- Body content (C12)

def test_body_content_neutral_when_empty():
    ctx = MessageContext(headers={})
    result = check_body_content(ctx)
    assert result.verdict == "neutral"


def test_body_content_flags_credential_phrase():
    ctx = MessageContext(headers={}, body_text="Please verify your account immediately.")
    result = check_body_content(ctx)
    assert result.verdict == "fail"
    assert result.score < 0


def test_body_content_flags_hidden_text():
    ctx = MessageContext(
        headers={},
        body_text="Hello, this is a normal message.",
        body_html='<div style="font-size:0px">hidden tracking text</div>',
    )
    result = check_body_content(ctx)
    assert result.verdict == "fail"
    assert result.details["hidden_text"] is True


def test_body_content_passes_on_benign_text():
    ctx = MessageContext(headers={}, body_text="Notas de la reunión de mayo, gracias.")
    result = check_body_content(ctx)
    assert result.verdict == "pass"


def test_body_content_ignores_preheader_and_tracking_pixel_inline_styles():
    # Real-world ESP pattern: a hidden "preheader" preview snippet, a
    # zero-size tracking pixel, and a responsive show/hide cell — all
    # inline display:none/font-size:0, none of it scanner-evasion.
    html = (
        '<div class="preheader" style="font-size: 1px; display: none !important;">'
        "Te esperamos!</div>"
        '<div style="font-size:0; line-height:0;"><img src="https://track.example.com/open"></div>'
        '<td class="mobile-only" style="display: none;">'
        '<img src="https://example.com/banner.png"></td>'
    )
    ctx = MessageContext(headers={}, body_text="Hola, nos vemos en el evento.", body_html=html)
    result = check_body_content(ctx)
    assert result.verdict == "pass"
    assert result.score == 0


def test_body_content_ignores_responsive_css_in_style_block():
    # Standard ESP responsive-design CSS (show/hide breakpoints) must not be
    # mistaken for evasive hidden text — it's a stylesheet rule, not content.
    html = (
        "<html><head><style>"
        ".lg-hidden { display: none !important; opacity: 0 !important; }"
        ".sm-hidden { display: table !important; opacity: 1 !important; }"
        "</style></head><body><p>Hola equipo, aquí el boletín de mayo.</p></body></html>"
    )
    ctx = MessageContext(headers={}, body_text="Hola equipo, aquí el boletín de mayo.", body_html=html)
    result = check_body_content(ctx)
    assert result.verdict == "pass"
    assert result.score == 0


# --------------------------------------------------------------- Suspicious attachments (C11)

def test_attachments_falls_back_to_headers_when_no_parts():
    ctx = MessageContext(headers={
        "content-type": "application/octet-stream",
        "content-disposition": 'attachment; filename="invoice.exe"',
    })
    result = check_suspicious_attachments(ctx)
    assert result.verdict == "fail"


def test_attachments_flags_real_dangerous_extension():
    ctx = MessageContext(headers={}, attachments=[
        Attachment(filename="invoice.exe", content_type="application/octet-stream", size=10),
    ])
    result = check_suspicious_attachments(ctx)
    assert result.verdict == "fail"
    assert result.details["findings"][0]["reason"] == "dangerous_extension"


def test_attachments_flags_macro_enabled_document():
    ctx = MessageContext(headers={}, attachments=[
        Attachment(filename="report.docm", content_type="application/vnd.ms-word.document.macroEnabled.12", size=10),
    ])
    result = check_suspicious_attachments(ctx)
    assert result.verdict == "fail"
    assert result.details["findings"][0]["reason"] == "macro_enabled"


def test_attachments_flags_zip_with_executable():
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("payload.exe", b"MZ\x00\x00fake-exe")
    zip_bytes = buf.getvalue()

    ctx = MessageContext(headers={}, attachments=[
        Attachment(filename="archive.zip", content_type="application/zip", size=len(zip_bytes), content=zip_bytes),
    ])
    result = check_suspicious_attachments(ctx)
    assert result.verdict == "fail"
    assert result.details["findings"][0]["reason"] == "archive_contains_executable"


def test_attachments_passes_on_benign_pdf():
    ctx = MessageContext(headers={}, attachments=[
        Attachment(filename="invoice.pdf", content_type="application/pdf", size=10),
    ])
    result = check_suspicious_attachments(ctx)
    assert result.verdict == "pass"
