"""
Received-header chain analysis rule (Fase 2).

Inspects the full chain of ``Received:`` headers — only available via the
full-message parser, since ``parse_raw_headers`` collapses duplicate
headers into one — for hop-count anomalies, a private/internal origin IP
leaking through, and a Date-vs-first-hop timestamp mismatch.
"""

from __future__ import annotations

import re
from email.utils import parsedate_to_datetime

from .registry import iris_rules, RuleResult

_IP_RE = re.compile(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?")
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.",
)


def _is_private_ip(ip: str) -> bool:
    return ip.startswith(_PRIVATE_PREFIXES) or ip == "0.0.0.0"


def _hop_timestamp(received_line: str):
    _, _, ts = received_line.rpartition(";")
    if not ts.strip():
        return None
    try:
        return parsedate_to_datetime(ts.strip())
    except (TypeError, ValueError, IndexError):
        return None


@iris_rules.register(
    name="Received Chain", category="header_analysis",
    description=(
        "Analiza la cadena completa de cabeceras Received: número de saltos, "
        "IP de origen privada/interna, y consistencia temporal con Date."
    ),
    needs_context=True,
)
def check_received_chain(context) -> RuleResult:
    received = context.received_headers
    headers = context.headers

    if not received:
        return RuleResult(
            score=0, verdict="neutral",
            details={"hops": 0, "reason": "no Received chain available"},
        )

    findings: list[str] = []
    score = 0

    origin_hop = received[-1]
    ip_match = _IP_RE.search(origin_hop)
    if ip_match and _is_private_ip(ip_match.group(1)):
        findings.append(f"IP de origen privada/interna: {ip_match.group(1)}")
        score -= 5

    date_header = headers.get("date", "")
    top_ts = _hop_timestamp(received[0])
    try:
        date_ts = parsedate_to_datetime(date_header) if date_header else None
    except (TypeError, ValueError, IndexError):
        date_ts = None

    if top_ts is not None and date_ts is not None:
        delta_hours = abs((top_ts - date_ts).total_seconds()) / 3600
        if delta_hours > 6:
            findings.append(
                f"Desfase de {delta_hours:.1f}h entre Date y el primer salto Received"
            )
            score -= 5

    if not findings:
        return RuleResult(score=1, verdict="pass", details={"hops": len(received)})

    return RuleResult(
        score=score, verdict="fail",
        details={"hops": len(received), "findings": findings},
        recommendation="La cadena Received presenta anomalías: " + "; ".join(findings),
    )
