"""
Parse a full raw email message (a ``.eml``'s contents) into a structured
context object.

Building on the existing header-only ``parse_raw_headers``, this module
uses the stdlib ``email`` package to additionally extract the body
(plain/HTML), every hyperlink found in the HTML/text body, real MIME
attachment metadata, and the full ``Received:`` chain (collapsed into one
entry by ``parse_raw_headers``, but needed in full here for hop analysis).

When *raw* is only a headers block (no body/MIME parts), every body-derived
field is simply empty — rules that need the full context degrade to a
neutral result rather than failing, so this parser is safe to use
unconditionally for both legacy headers-only submissions and full messages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string
from email.message import Message
from typing import Dict, List, Optional

from .header_parser import parse_raw_headers

_ANCHOR_RE = re.compile(
    r'<a\b[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_BARE_URL_RE = re.compile(r'(?<![\'"=])(https?://[^\s<>\'")]+)', re.IGNORECASE)


@dataclass
class Link:
    """A single hyperlink found in the message body."""
    href: str
    text: str = ""


@dataclass
class Attachment:
    """A real MIME attachment part found in the message."""
    filename: Optional[str]
    content_type: str
    size: int
    content: bytes = field(default=b"", repr=False)


@dataclass
class MessageContext:
    """Rich representation of a parsed email message.

    Header-only rules keep receiving the plain ``headers`` dict (via
    ``parse_raw_headers``). Rules registered with ``needs_context=True``
    receive this object instead — see ``rules/registry.py`` and the
    dispatch logic in ``managers.IrisManager._run_analysis``.
    """
    headers: Dict[str, str]
    body_text: str = ""
    body_html: str = ""
    links: List[Link] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)
    received_headers: List[str] = field(default_factory=list)


def _decode_payload(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return ""
    if not payload:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def _extract_links(html: str) -> List[Link]:
    links: List[Link] = []
    seen_hrefs = set()
    for m in _ANCHOR_RE.finditer(html):
        href = m.group(1).strip()
        text = _TAG_RE.sub("", m.group(2)).strip()
        links.append(Link(href=href, text=text))
        seen_hrefs.add(href)
    for m in _HREF_RE.finditer(html):
        href = m.group(1).strip()
        if href not in seen_hrefs:
            links.append(Link(href=href, text=""))
            seen_hrefs.add(href)
    return links


def _extract_bare_urls(text: str) -> List[Link]:
    return [Link(href=u, text=u) for u in _BARE_URL_RE.findall(text)]


def parse_raw_message(raw: str) -> MessageContext:
    """Parse a full raw RFC 5322 / MIME message into a ``MessageContext``.

    Args:
        raw: The full raw message text (headers + body), or just a
             headers block — both are accepted.

    Returns:
        A ``MessageContext`` with whatever could be extracted. Body,
        links and attachments are empty lists/strings when *raw* has no
        body (headers-only input).
    """
    msg = message_from_string(raw)
    headers = parse_raw_headers(raw)

    body_text = ""
    body_html = ""
    attachments: List[Attachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            disposition = (part.get("Content-Disposition") or "").lower()
            content_type = part.get_content_type()
            filename = part.get_filename()

            if filename or "attachment" in disposition:
                payload = part.get_payload(decode=True) or b""
                attachments.append(Attachment(
                    filename=filename,
                    content_type=content_type,
                    size=len(payload),
                    content=payload,
                ))
                continue

            if content_type == "text/plain" and not body_text:
                body_text = _decode_payload(part)
            elif content_type == "text/html" and not body_html:
                body_html = _decode_payload(part)
    else:
        content_type = msg.get_content_type()
        if content_type == "text/html":
            body_html = _decode_payload(msg)
        elif content_type.startswith("text/"):
            body_text = _decode_payload(msg)

    links = _extract_links(body_html) if body_html else []
    if not links and body_text:
        links = _extract_bare_urls(body_text)

    received_headers = [v for k, v in msg.items() if k.lower() == "received"]

    return MessageContext(
        headers=headers,
        body_text=body_text,
        body_html=body_html,
        links=links,
        attachments=attachments,
        received_headers=received_headers,
    )
