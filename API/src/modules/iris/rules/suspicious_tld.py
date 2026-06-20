"""
Suspicious TLD rule — flags email sender domains using top-level domains
that are disproportionately abused in phishing campaigns.

Free/cheap TLDs like .xyz, .tk, .ml, .ga, .cf, .top, .loan, .work,
.click, .zip, .download, .review, .country, .kim, .men, .bid are
rarely used by legitimate organisations for email correspondence.
"""

import re

from .registry import iris_rules, RuleResult

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf",                # Free Freenom TLDs
    ".xyz", ".club", ".top", ".loan", ".work",
    ".click", ".zip", ".download", ".review",
    ".country", ".kim", ".men", ".bid",
    ".trade", ".webcam", ".party", ".date",
    ".science", ".racing", ".win", ".review",
    ".gq",                                      # Equatorial Guinea (Freenom)
    ".faith", ".stream", ".accountant",
    ".bid", ".cricket", ".pro",
    ".lol", ".mom",
    ".bar", ".name", ".info",                   # Often abused due to cheap registration
    ".mobi", ".pw",                             # Professional web — commonly abused
}

LEGITIMATE_COMMON_TLDS = {
    ".com", ".org", ".net", ".edu", ".gov", ".mil",
    ".es", ".mx", ".ar", ".cl", ".co",           # Spanish-speaking country TLDs
    ".uk", ".de", ".fr", ".it", ".jp", ".au",
    ".ca", ".br", ".pt", ".us", ".eu",
    ".io", ".ai", ".app", ".dev",                 # Tech, generally well-managed
    ".co.uk", ".com.au", ".com.mx", ".co.jp",
}


def _get_domain_tld(email: str) -> str | None:
    match = re.search(r"@([\w.-]+)", email)
    if not match:
        return None
    domain = match.group(1).lower()
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return tld
    return None


@iris_rules.register(name="Suspicious TLD", category="header_analysis",
                     description="Detecta si el dominio del remitente usa TLDs frecuentemente asociados con phishing")
def check_suspicious_tld(headers: dict) -> RuleResult:
    from_addr = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    return_path = headers.get("return-path", "") or headers.get("envelope-from", "") or ""

    emails_to_check = []
    if from_addr:
        emails_to_check.append(from_addr)
    if reply_to:
        emails_to_check.append(reply_to)
    if return_path:
        emails_to_check.append(return_path)

    found_tlds: list[dict] = []

    for raw in emails_to_check:
        match = re.search(r"[\w.+-]+@([\w.-]+)", raw)
        if not match:
            continue
        domain = match.group(1).lower()
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                found_tlds.append({"domain": domain, "tld": tld, "header_source": raw})
                break

    if not found_tlds:
        return RuleResult(
            score=1, verdict="pass",
            details={"suspicious_tlds_found": []},
            recommendation=None,
        )

    count = len(found_tlds)
    domains_str = ", ".join(d["domain"] for d in found_tlds)
    tlds_str = ", ".join(d["tld"] for d in found_tlds)

    return RuleResult(
        score=-5 * count,
        verdict="fail",
        details={
            "suspicious_tlds_found": found_tlds,
            "count": count,
        },
        recommendation=(
            f"Se detectaron dominios con TLDs sospechosos ({tlds_str}) en las cabeceras del correo: "
            f"{domains_str}. Estos TLDs son utilizados desproporcionadamente en campañas de phishing "
            f"debido a su bajo costo y falta de verificación."
        ),
    )
