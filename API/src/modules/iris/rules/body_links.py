"""
Body link analysis rule (Fase 2) — the biggest gap of the header-only model.

Real phishing links live in the body, not the subject. This rule inspects
every hyperlink extracted by the full-message parser for the classic
link-cloaking and evasion patterns: visible text claiming one domain while
the href points to another, IDN/punycode homographs, IP-literal hosts, and
known URL shorteners.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .registry import iris_rules, RuleResult

_DOMAIN_IN_TEXT_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b",
    re.IGNORECASE,
)
_IP_HOST_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in",
    "soo.gd", "s.id", "v.gd",
}

MAX_SCORE_FLOOR = -25


def _host(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    netloc = parsed.netloc
    if not netloc:
        return None
    return netloc.split("@")[-1].split(":")[0].lower() or None


@iris_rules.register(
    name="Body Links", category="content_analysis",
    description=(
        "Analiza los enlaces reales del cuerpo: texto visible vs href, "
        "punycode/IDN, IPs literales, y acortadores de URL conocidos."
    ),
    needs_context=True,
)
def check_body_links(context) -> RuleResult:
    links = context.links
    if not links:
        return RuleResult(score=0, verdict="neutral", details={"link_count": 0})

    findings: list[dict] = []
    score = 0
    seen_types: set[str] = set()

    for link in links:
        host = _host(link.href)
        if not host:
            continue

        if any(label.startswith("xn--") for label in host.split(".")):
            findings.append({"type": "punycode", "href": link.href})
            seen_types.add("punycode")
            score -= 8

        if _IP_HOST_RE.match(host):
            findings.append({"type": "ip_literal", "href": link.href})
            seen_types.add("ip_literal")
            score -= 6

        if host in SHORTENER_DOMAINS:
            findings.append({"type": "shortener", "href": link.href})
            seen_types.add("shortener")
            score -= 4

        text_domain_match = _DOMAIN_IN_TEXT_RE.search(link.text or "")
        if text_domain_match:
            claimed = text_domain_match.group(1).lower()
            if claimed != host and not host.endswith("." + claimed) and claimed not in host:
                findings.append({
                    "type": "cloaked_link",
                    "visible_text": link.text.strip(),
                    "actual_href": link.href,
                })
                seen_types.add("cloaked_link")
                score -= 12

    if not findings:
        return RuleResult(score=1, verdict="pass", details={"link_count": len(links)})

    score = max(score, MAX_SCORE_FLOOR)
    return RuleResult(
        score=score, verdict="fail",
        details={"link_count": len(links), "findings": findings, "types": sorted(seen_types)},
        recommendation=(
            "Se detectaron enlaces sospechosos en el cuerpo del correo "
            f"({', '.join(sorted(seen_types))}). No hagas clic sin verificar el destino real."
        ),
    )
