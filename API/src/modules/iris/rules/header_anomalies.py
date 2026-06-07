"""
Header anomalies rule — detects suspicious patterns in email headers.

Common phishing indicators:
- Mismatch between the domain in the From header and the envelope sender.
- Multiple recipients in To that look unusual (BCS / CEO fraud).
- Suspicious X-Mailer or User-Agent values.
- Empty or malformed Message-ID.
"""

import re

from .registry import iris_rules, RuleResult


@iris_rules.register(name="Header anomalies", category="header_analysis",
                     description="Detecta anomalías estructurales en las cabeceras indicativas de phishing")
def check_header_anomalies(headers: dict) -> RuleResult:
    """Detect structural header anomalies common in phishing emails.

    Checks performed (each contributes additively to the penalty):
        - ``Return-Path`` domain differs from ``From`` domain (-8).
        - ``Message-ID`` missing or too short (-4).
        - Body is text/plain only (no multipart alternative) (-2).
        - ``From`` header is empty or malformed (-10).

    Returns:
        - ``pass`` (score 0) when no anomalies are found.
        - ``suspicious`` (-5 ≤ score < 0) for minor issues.
        - ``fail`` (score < -5) when multiple strong signals are present.
    """
    score = 0
    details = {}
    recommendations = []

    from_addr = headers.get("from", "")
    return_path = headers.get("return-path", "") or headers.get("envelope-from", "") or headers.get("sender", "")
    message_id = headers.get("message-id", "")
    content_type = headers.get("content-type", "")

    # ── Return-Path vs From mismatch ──────────────────────────────────
    if return_path and from_addr:
        rp_domain = _extract_domain(return_path)
        from_domain = _extract_domain(from_addr)
        if rp_domain and from_domain and rp_domain != from_domain:
            score -= 8
            details["domain_mismatch"] = {"return_path_domain": rp_domain, "from_domain": from_domain}
            recommendations.append(
                "El dominio en Return-Path no coincide con el dominio remitente. "
                "Indica que el mensaje pudo ser generado por un servidor no autorizado."
            )

    # ── Missing or malformed Message-ID ────────────────────────────────
    if not message_id or len(message_id.strip()) < 5:
        score -= 4
        details["message_id"] = "missing or too short"
        recommendations.append(
            "El Message-ID está ausente o es sospechosamente corto. "
            "Los mensajes legítimos suelen tener un Message-ID único y completo."
        )

    # ── Multipart missing (plain text only can be suspicious) ──────────
    if content_type and "multipart" not in content_type.lower() and "text/plain" in content_type.lower():
        score -= 2
        details["content_type"] = "text/plain only — no multipart alternative"
        recommendations.append(
            "El correo solo contiene texto plano sin versión HTML. "
            "Aunque no es necesariamente malicioso, el phishing simple a menudo usa solo texto plano."
        )

    # ── Empty or unusual From ──────────────────────────────────────────
    if not from_addr or "<>" in from_addr:
        score -= 10
        details["from_empty"] = True
        recommendations.append(
            "La cabecera From está vacía. Un correo legítimo siempre tiene un remitente identificable."
        )

    # ── Verdict ────────────────────────────────────────────────────────
    if score >= 0:
        verdict = "pass"
        combined_recommendation = None
    elif score >= -5:
        verdict = "suspicious"
        combined_recommendation = " ".join(recommendations) if recommendations else None
    else:
        verdict = "fail"
        combined_recommendation = " ".join(recommendations)

    return RuleResult(score=float(score), verdict=verdict, details=details, recommendation=combined_recommendation)


def _extract_domain(email: str) -> str | None:
    """Extract the domain part from an email address string."""
    match = re.search(r"@([\w.-]+)", email)
    return match.group(1).lower() if match else None
