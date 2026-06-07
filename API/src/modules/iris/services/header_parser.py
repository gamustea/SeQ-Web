"""
Parse raw email header text into a structured dictionary.

Rules receive this dict so they can look up headers by lowercase key
(e.g. headers["received-spf"], headers["dkim-signature"]).

Continuation lines (starting with space or tab) are folded into the
most recent header, matching RFC 5322 semantics.
"""

from __future__ import annotations

from typing import Dict


def parse_raw_headers(raw: str) -> Dict[str, str]:
    """Parse raw RFC 5322 header text into a ``{name: value}`` dict.

    Handles:
    - Standard ``Key: Value`` headers (keys lowercased).
    - Continuation lines (folded whitespace per RFC 5322 section 2.2.3).
    - Carriage-return / newline line endings.

    Args:
        raw: The raw header block as a plain string.

    Returns:
        A dictionary mapping lowercase header names to their full values.
        Headers that appear multiple times are represented by the last
        occurrence (folding continuation lines into it as they arrive).
    """
    headers: Dict[str, str] = {}
    current_key: str | None = None
    current_value: str | None = None

    for line in raw.split("\n"):
        line = line.rstrip("\r")

        # continuation line (starts with space or tab)
        if line and line[0] in (" ", "\t") and current_key is not None:
            current_value = (current_value or "") + " " + line.strip()
            headers[current_key] = (current_value or "").strip()
            continue

        # new header
        if ":" in line:
            key, _, val = line.partition(":")
            current_key = key.strip().lower()
            current_value = val.strip()
            headers[current_key] = current_value

    return headers
