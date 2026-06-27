"""
Domain Alignment rule — verifies that the domain authenticated by SPF/DKIM
actually matches the visible ``From`` domain (DMARC alignment).

SPF and DKIM can both report ``pass`` while authenticating a domain that
has *nothing to do* with the ``From`` the user sees.  For example a message
DKIM-signed by ``d=sendgrid.net`` "passes" DKIM even when the visible From
is ``ceo@victima.com``.  The existing SPF/DKIM rules only look at the
pass/fail token and never compare domains, so this gap is invisible to
them.  This rule closes it by reproducing DMARC's alignment check:
authentication is only meaningful when the authenticated identity aligns
with the From domain.
"""

import re

from .registry import iris_rules, RuleResult, extract_domain

# Public-suffix second levels we need to keep two labels of (very small,
# pragmatic list — a full PSL is overkill for a header heuristic).
_MULTI_LEVEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.mx", "com.br",
    "com.ar", "com.au", "com.es", "co.in", "co.nz", "com.tr", "com.co",
}


def _registrable(domain: str | None) -> str | None:
    """Reduce a hostname to its registrable domain (best-effort, no PSL).

    ``mail.corp.paypal.com`` -> ``paypal.com``; ``a.b.example.co.uk`` ->
    ``example.co.uk``.  Good enough to compare organisational alignment.
    """
    if not domain:
        return None
    labels = domain.strip(".").lower().split(".")
    if len(labels) < 2:
        return domain.lower()
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LEVEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _dkim_domain(headers: dict) -> str | None:
    """Extract the DKIM signing domain (``d=``) from the signature or auth header."""
    for source in (headers.get("dkim-signature", ""), headers.get("authentication-results", "")):
        match = re.search(r"\b(?:header\.)?d=([\w.-]+)", source)
        if match:
            return match.group(1).lower()
    return None


def _spf_mailfrom_domain(headers: dict) -> str | None:
    """Extract the SPF-authenticated envelope domain (``smtp.mailfrom``)."""
    auth = headers.get("authentication-results", "")
    match = re.search(r"smtp\.mailfrom=([^\s;]+)", auth)
    if not match:
        return None
    value = match.group(1)
    return value.split("@")[-1].lower() if "@" in value else value.lower()


@iris_rules.register(name="Domain Alignment", category="authentication",
                     description="Comprueba que el dominio autenticado por SPF/DKIM coincide con el dominio del remitente (alineación DMARC)")
def check_domain_alignment(headers: dict) -> RuleResult:
    """Verify SPF/DKIM authenticated domains align with the From domain.

    Returns:
        - ``pass`` (score +3) when at least one passing mechanism aligns.
        - ``fail`` (score -15) when SPF/DKIM pass but none align with From.
        - ``neutral`` (score 0) when there is nothing to compare.
    """
    from_domain = _registrable(extract_domain(headers.get("from", "")))
    if not from_domain:
        return RuleResult(
            score=0, verdict="neutral",
            details={"reason": "no parseable From domain"},
            recommendation=None,
        )

    auth = headers.get("authentication-results", "").lower()

    # DMARC pass already proves alignment — nothing to add.
    if "dmarc=pass" in auth:
        return RuleResult(
            score=3, verdict="pass",
            details={"from_domain": from_domain, "reason": "dmarc=pass"},
            recommendation=None,
        )

    candidates: dict[str, str] = {}
    if "dkim=pass" in auth:
        d = _dkim_domain(headers)
        if d:
            candidates["dkim"] = d
    if "spf=pass" in auth:
        mf = _spf_mailfrom_domain(headers)
        if mf:
            candidates["spf"] = mf

    if not candidates:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from_domain": from_domain, "reason": "no passing SPF/DKIM identity to compare"},
            recommendation=None,
        )

    aligned = {mech: dom for mech, dom in candidates.items()
               if _registrable(dom) == from_domain}

    if aligned:
        return RuleResult(
            score=3, verdict="pass",
            details={"from_domain": from_domain, "aligned": aligned},
            recommendation=None,
        )

    return RuleResult(
        score=-15, verdict="fail",
        details={
            "from_domain": from_domain,
            "authenticated_domains": candidates,
        },
        recommendation=(
            "SPF/DKIM autentican un dominio que NO coincide con el remitente visible "
            f"({from_domain}). La autenticación no garantiza que el correo provenga de "
            "quien dice ser: un atacante puede firmar con su propio dominio (o el de un "
            "proveedor de envío) mientras falsifica el campo 'De'. Trátalo como sospechoso."
        ),
    )
