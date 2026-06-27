"""
Lookalike Sender Domain rule — detects when the *actual* From domain is a
typosquat, homoglyph, cousin domain, or IDN/punycode imitation of a known
brand.

The existing "Display Name Spoofing" and "Misspelled Brand Names" rules only
inspect the display name and Subject.  They miss the most direct signal: the
real registered domain the mail comes from.  Domains such as ``paypa1.com``
(homoglyph), ``paypal-security.com`` (cousin), or ``xn--pypal-4ve.com``
(punycode IDN) all carry valid SPF/DKIM and therefore sail through the
authentication rules — yet they are textbook phishing.
"""

import re

from .registry import iris_rules, RuleResult, extract_domain
from .misspelled_brands import CANONICAL_BRANDS, _normalize_homoglyphs, _levenshtein

_MULTI_LEVEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.mx", "com.br",
    "com.ar", "com.au", "com.es", "co.in", "co.nz", "com.tr", "com.co",
}


def _registrable_label(domain: str) -> str:
    """Return the owner-identifying label of the registrable domain.

    ``mail.paypal.com`` -> ``paypal``; ``a.example.co.uk`` -> ``example``.
    """
    labels = domain.strip(".").lower().split(".")
    if len(labels) < 2:
        return labels[0] if labels else ""
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LEVEL_TLDS and len(labels) >= 3:
        return labels[-3]
    return labels[-2]


@iris_rules.register(name="Lookalike Sender Domain", category="header_analysis",
                     description="Detecta si el dominio real del remitente imita a una marca conocida (typosquatting, homóglifos, cousin domain o punycode/IDN)")
def check_lookalike_domain(headers: dict) -> RuleResult:
    """Flag From domains that imitate a known brand.

    Returns:
        - ``fail`` (score -15) for homoglyph / typo / cousin / punycode imitations.
        - ``pass`` (score +1) for ordinary domains and legitimate brand domains.
        - ``neutral`` (score 0) when there is no parseable From domain.
    """
    domain = extract_domain(headers.get("from", ""))
    if not domain:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": headers.get("from", "")},
            recommendation=None,
        )

    # Punycode / IDN homograph — any xn-- label is inherently suspicious.
    if any(label.startswith("xn--") for label in domain.split(".")):
        return RuleResult(
            score=-15, verdict="fail",
            details={"domain": domain, "type": "punycode"},
            recommendation=(
                f"El dominio del remitente ({domain}) usa codificación punycode (IDN, 'xn--'). "
                "Es una técnica habitual para registrar dominios que parecen marcas conocidas "
                "usando caracteres Unicode visualmente idénticos. Trátalo como phishing."
            ),
        )

    label = _registrable_label(domain)
    if not label:
        return RuleResult(score=1, verdict="pass", details={"domain": domain}, recommendation=None)

    # Exact legitimate brand domain (e.g. paypal.com, gmail.com) — never flag.
    if label in CANONICAL_BRANDS:
        return RuleResult(score=1, verdict="pass", details={"domain": domain}, recommendation=None)

    tokens = [t for t in re.split(r"[^a-z0-9]+", label) if len(t) >= 4]
    findings: list[dict] = []

    for token in tokens:
        if token in CANONICAL_BRANDS:
            # Brand name combined with extra words in the registered domain
            # (e.g. "paypal-security") — a cousin/combosquat domain.
            findings.append({"token": token, "brand": token, "type": "cousin"})
            continue
        normalized = _normalize_homoglyphs(token)
        if normalized != token and normalized in CANONICAL_BRANDS:
            findings.append({"token": token, "brand": normalized, "type": "homoglyph"})
            continue
        for brand in CANONICAL_BRANDS:
            if len(brand) < 5 or abs(len(token) - len(brand)) > 1:
                continue
            if _levenshtein(token, brand) == 1:
                findings.append({"token": token, "brand": brand, "type": "typo"})
                break

    if not findings:
        return RuleResult(score=1, verdict="pass", details={"domain": domain}, recommendation=None)

    brands = ", ".join(sorted({f["brand"] for f in findings}))
    return RuleResult(
        score=-15, verdict="fail",
        details={"domain": domain, "registrable_label": label, "findings": findings},
        recommendation=(
            f"El dominio real del remitente ({domain}) imita a una marca conocida ({brands}) "
            "mediante typosquatting, homóglifos o un 'cousin domain'. Aunque pase SPF/DKIM "
            "(el atacante controla su propio dominio), NO es el dominio legítimo de la marca."
        ),
    )
