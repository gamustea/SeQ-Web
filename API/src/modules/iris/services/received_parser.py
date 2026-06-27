"""
Parser for ``Received:`` header lines.

RFC 5321 §4.4 defines the on-wire shape of a Received line as a sequence
of ``KEY VALUE`` tokens (with several optional/repeating fields) followed
by a trailing ``; timestamp``. Real-world mail servers take many
liberties with whitespace, parentheses, and optional fields, so the
parser is intentionally **tolerant**: anything that cannot be matched is
preserved in the ``raw`` field of the hop and the unparsed structured
fields are returned as ``None``. Callers must always be able to render
the verbatim header even when structured fields are missing.

Two helpers are exposed:

- :func:`parse_received_line` parses a single line.
- :func:`build_path` parses a list of Received lines in **delivery**
  order (``received[0]`` = final hop, ``received[-1]`` = origin), and
  returns a path ordered **oldest -> newest** plus a list of transitions
  between consecutive hops (delay, suspicious flags). The transition
  flags are the same ones surfaced by the
  ``Received Path Anomaly`` rule, so the visual graph and the score
  stay in sync.
"""

from __future__ import annotations

import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional


# A bare IPv4 literal, optionally surrounded by brackets.
_IP_RE = re.compile(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]")

# RFC 1918 / loopback ranges we treat as private. The list mirrors the
# one in rules/received_chain.py so the two stay consistent.
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.", "0.0.0.0",
)

# Tokens in the Received grammar (the prefix before ``; timestamp``).
_KNOWN_KEYS = {"from", "by", "with", "via", "id", "for", "received"}


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in _PRIVATE_PREFIXES) or ip == "0.0.0.0"


def _hop_timestamp(line: str) -> Optional[datetime]:
    _, _, ts = line.rpartition(";")
    if not ts.strip():
        return None
    try:
        return parsedate_to_datetime(ts.strip())
    except (TypeError, ValueError, IndexError):
        return None


def _extract_ip(text: str) -> Optional[str]:
    """Return the first IPv4 literal found in *text*, or ``None``."""
    m = _IP_RE.search(text)
    if m:
        return m.group(1)
    # Fallback: bare IPv4 not in brackets, common in HELO/EHLO echoes.
    bare = re.search(r"(?<!\d)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)", text)
    return bare.group(1) if bare else None


def _split_tokens(prefix: str) -> List[str]:
    """Split the comment-heavy Received prefix into a flat token list.

    We strip the outermost parentheses and treat their contents as part
    of the surrounding token, since servers freely attach HELO/EHLO data
    in parentheses immediately after the IP they refer to. Anything we
    can't cleanly split falls back to a whitespace split so we never
    drop information.
    """
    flat = prefix.strip()
    if not flat:
        return []
    # Walk char-by-char; collapse "( ... )" into the surrounding token.
    tokens: List[str] = []
    buf: List[str] = []
    depth = 0
    for ch in flat:
        if ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch.isspace() and depth == 0:
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    return tokens


def _detect_tls(line: str, with_value: Optional[str], protocol: Optional[str]) -> bool:
    """Heuristic: was this hop encrypted?

    Servers usually signal TLS via either:
      * ``with = ESMTPS`` / ``ESMTPSA`` (encrypted submission)
      * ``with = ... version=TLSv1.x``
      * A literal ``(using TLSv1.x)`` somewhere in the line
    """
    if with_value:
        upper = with_value.upper()
        if "ESMTPS" in upper or "ESMTPSA" in upper:
            return True
        if "TLS" in upper:
            return True
        # HTTPS / internal Microsoft handoffs ("with HTTPS") are encrypted.
        if "HTTPS" in upper:
            return True
    if protocol and "TLS" in protocol.upper():
        return True
    if "version=TLS" in line:
        return True
    return False


def _is_cleartext_smtp_relay(hop: Dict[str, Any]) -> bool:
    """True only when a hop accepted mail over *unencrypted* SMTP/ESMTP.

    A genuine TLS downgrade means an encrypted hop handed off to a hop that
    received the message in clear text over SMTP *from another host*. The
    final internal delivery hops (``with HTTPS``, ``with LMTP``, local
    mailstore handoffs, ``Received: by ... with SMTP id`` notes that carry no
    ``from``, or hops with no ``with`` token at all) are not cleartext relays
    — treating their absence of a TLS marker as a "downgrade" was the source
    of constant false positives on ordinary Gmail/Outlook-routed mail.
    """
    if hop.get("tls"):
        return False
    # A real inbound relay names the host it received *from*. A ``by``-only
    # hop is an internal handoff, not a cleartext network relay.
    if not hop.get("from"):
        return False
    with_value = (hop.get("with") or "").upper()
    if not with_value:
        return False
    # ESMTP/SMTP without an "S" (already excluded by tls=False) is a real
    # cleartext relay; LMTP/HTTP/local deliveries are not.
    return with_value.startswith("ESMTP") or with_value.startswith("SMTP")


def parse_received_line(line: str) -> Dict[str, Any]:
    """Parse a single ``Received:`` header line into a structured dict.

    Args:
        line: The full header value, with or without the leading
            ``Received:`` token (we accept both shapes).

    Returns:
        A dict with keys ``from``, ``fromIp``, ``by``, ``with``,
        ``protocol``, ``tls``, ``timestamp``, ``flags`` and ``raw``.
        Fields that could not be extracted are ``None`` (or empty for
        ``flags``); the original line is always preserved in ``raw``.
    """
    raw = line.strip()
    # Strip the leading "Received:" if present.
    body = re.sub(r"^received\s*:\s*", "", raw, flags=re.IGNORECASE)

    timestamp = _hop_timestamp(body)
    prefix, _, _ = body.rpartition(";")
    if not prefix.strip():
        prefix = body

    tokens = _split_tokens(prefix)

    fields: Dict[str, Optional[str]] = {
        "from": None,
        "by": None,
        "with": None,
        "protocol": None,
        "id": None,
        "for": None,
    }
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        lower = tok.lower()
        if lower in _KNOWN_KEYS and i + 1 < len(tokens):
            # Repeated keys: keep the first non-null value seen.
            if fields.get(lower) is None:
                fields[lower] = tokens[i + 1]
            i += 2
        else:
            # Unrecognized token: stash into ``id`` (commonly holds
            # opaque MTA identifiers) and keep moving.
            if fields["id"] is None:
                fields["id"] = tok
            i += 1

    from_text = fields.get("from") or ""
    # The IP for the sending hop is often in the ``(...)`` block
    # immediately following the ``from`` address, not inside the
    # ``from`` token itself. Scan the full prefix so we catch both
    # shapes (bare IP in ``from``, or IP in trailing parentheses).
    from_ip = _extract_ip(from_text) or _extract_ip(prefix)

    flags: List[str] = []
    if from_ip and _is_private_ip(from_ip):
        flags.append("private_ip")

    tls = _detect_tls(raw, fields.get("with"), fields.get("protocol"))

    return {
        "from": from_text or None,
        "fromIp": from_ip,
        "by": fields.get("by"),
        "with": fields.get("with"),
        "protocol": fields.get("protocol"),
        "id": fields.get("id"),
        "for": fields.get("for"),
        "tls": tls,
        "timestamp": timestamp.isoformat() if timestamp else None,
        "flags": flags,
        "raw": raw,
    }


def _delay_ms(prev: Optional[datetime], curr: Optional[datetime]) -> Optional[int]:
    if prev is None or curr is None:
        return None
    delta = (curr - prev).total_seconds() * 1000.0
    return int(delta)


def build_path(received_headers: List[str]) -> Dict[str, Any]:
    """Build a graph-friendly representation of a Received chain.

    Args:
        received_headers: The full chain in **delivery order**
            (``received_headers[0]`` is the final delivery hop,
            ``received_headers[-1]`` is the origin). The same
            convention used elsewhere in Iris (see
            ``MessageContext.received_headers``).

    Returns:
        A dict with keys:
          * ``hops``: list of parsed hop dicts, ordered **oldest ->
            newest** so the first entry is the origin.
          * ``transitions``: list of edges between consecutive hops
            (oldest -> newest direction). Each entry includes
            ``from``, ``to``, ``delayMs`` and ``suspicious`` plus
            ``reasons`` when applicable.
          * ``hopsCount``: total number of hops (== len(hops)).
          * ``available``: True whenever a chain was present.
    """
    if not received_headers:
        return {
            "hops": [],
            "transitions": [],
            "hopsCount": 0,
            "available": False,
            "reason": "no Received chain available",
        }

    # Parse first; then reverse to oldest -> newest.
    parsed: List[Dict[str, Any]] = [parse_received_line(line) for line in received_headers]
    parsed.reverse()

    transitions: List[Dict[str, Any]] = []
    for idx in range(len(parsed) - 1):
        prev_hop = parsed[idx]
        curr_hop = parsed[idx + 1]
        # Re-derive timestamps from the original delivery-order lines:
        # after `parsed.reverse()`, parsed[idx] corresponds to
        # received_headers[N-1-idx] where N == len(received_headers).
        n = len(received_headers)
        prev_line = received_headers[n - 1 - idx]
        curr_line = received_headers[n - 2 - idx]
        prev_ts = _hop_timestamp(prev_line)
        curr_ts = _hop_timestamp(curr_line)
        delay = _delay_ms(prev_ts, curr_ts)

        reasons: List[str] = []
        if prev_hop["tls"] and _is_cleartext_smtp_relay(curr_hop):
            reasons.append("tls_downgrade")
        if delay is not None and delay < 0:
            reasons.append("time_inversion")

        transitions.append({
            "from": idx + 1,           # 1-based hop numbers for the UI
            "to": idx + 2,
            "delayMs": delay,
            "suspicious": bool(reasons),
            "reasons": reasons,
        })

    # Re-stamp each hop with its 1-based index for the UI.
    hops: List[Dict[str, Any]] = []
    for idx, hop in enumerate(parsed):
        stamped = dict(hop)
        stamped["hop"] = idx + 1
        stamped["index"] = len(parsed) - idx  # original index in delivery order
        hops.append(stamped)

    return {
        "hops": hops,
        "transitions": transitions,
        "hopsCount": len(hops),
        "available": True,
    }
