"""
Decode RFC 2047 "encoded-word" header values into plain Unicode text.

Phishing campaigns frequently MIME-encode the Subject and From display
name (e.g. ``=?UTF-8?B?...?=``) so that naive substring scanners never
see the underlying words.  Content rules must decode headers *before*
matching keywords or brand names, otherwise the check is trivially
bypassed.
"""

from __future__ import annotations

from email.header import decode_header, make_header


def decode_mime_words(value: str) -> str:
    """Decode RFC 2047 encoded-words in a header value to Unicode text.

    Handles mixed encoded / unencoded segments (e.g. an encoded display
    name followed by a plain ``<addr@host>``).  Falls back to the
    original string if the value cannot be decoded.

    Args:
        value: The raw header value, possibly containing encoded-words.

    Returns:
        The decoded Unicode string, or the original value on failure.
    """
    if not value:
        return value
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value
