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

from .registry import iris_rules, RuleResult, extract_domain, registrable_domain
from .subdomain_impersonation import find_brand_in_subdomain

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

    sender_domain = registrable_domain(extract_domain(context.headers.get("from", "")))

    findings: list[dict] = []
    score = 0
    seen_types: set[str] = set()

    for link in links:
        host = _host(link.href)
        if not host:
            continue

        # Brand-as-subdomain impersonation: a known brand (or the sender's own
        # domain) appears as a left-hand label while the real registrable
        # domain is someone else's — e.g. ``github.com.sessions-security.com``.
        # This is the highest-confidence body-link phishing signal and the
        # most common one missed by visible-text cloak detection (the visible
        # text often carries no domain at all).
        brand_hit = find_brand_in_subdomain(host)
        host_reg = registrable_domain(host)
        sender_impersonation = bool(
            sender_domain
            and host_reg != sender_domain
            and ("." + sender_domain + ".") in ("." + host + ".")
        )
        if brand_hit or sender_impersonation:
            findings.append({
                "type": "brand_impersonation",
                "href": link.href,
                "host": host,
                "real_domain": host_reg,
                "impersonates": (brand_hit or {}).get("brand") or sender_domain,
            })
            seen_types.add("brand_impersonation")
            score -= 20

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
