"""
Message-ID Domain rule — compares the domain inside the Message-ID with the
From domain.

Legitimate mail systems normally generate the Message-ID on the sending
infrastructure of the From domain, so a Message-ID whose domain is unrelated
to the sender is a (weak) spoofing indicator.  Kept low-weight because some
legitimate ESPs generate Message-IDs on their own infrastructure.
"""

import re

from .registry import iris_rules, RuleResult, extract_domain

_MULTI_LEVEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.mx", "com.br",
    "com.ar", "com.au", "com.es", "co.in", "co.nz", "com.tr", "com.co",
}


def _registrable(domain: str | None) -> str | None:
    if not domain:
        return None
    labels = domain.strip(".").lower().split(".")
    if len(labels) < 2:
        return domain.lower()
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LEVEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


@iris_rules.register(name="Message-ID Domain", category="header_analysis",
                     description="Compara el dominio del Message-ID con el dominio del remitente")
def check_msgid_domain(headers: dict) -> RuleResult:
    """Compare the Message-ID domain against the From domain.

    Returns:
        - ``pass`` (score +1) when the Message-ID domain aligns with From.
        - ``fail`` (score -3) when the domains differ.
        - ``neutral`` (score 0) when either domain is absent/unparseable.
    """
    message_id = headers.get("message-id", "")
    from_domain = _registrable(extract_domain(headers.get("from", "")))

    match = re.search(r"@([\w.-]+)", message_id)
    msgid_domain = _registrable(match.group(1)) if match else None

    if not msgid_domain or not from_domain:
        return RuleResult(score=0, verdict="neutral", details={"message_id": message_id}, recommendation=None)

    if msgid_domain == from_domain:
        return RuleResult(
            score=1, verdict="pass",
            details={"msgid_domain": msgid_domain, "from_domain": from_domain},
            recommendation=None,
        )

    return RuleResult(
        score=-3, verdict="fail",
        details={"msgid_domain": msgid_domain, "from_domain": from_domain},
        recommendation=(
            f"El dominio del Message-ID ({msgid_domain}) no coincide con el del remitente "
            f"({from_domain}). Puede ser legítimo (algunos servicios de envío generan el "
            "Message-ID en su propia infraestructura), pero también es un indicio de falsificación."
        ),
    )
