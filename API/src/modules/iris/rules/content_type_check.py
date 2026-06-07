"""
Content-Type check rule — flags emails that only carry text/plain.

While not inherently malicious, phishing is often sent as plain text
without a multipart alternative, making this a mild signal.
"""

from .registry import iris_rules, RuleResult


@iris_rules.register(name="Content-Type check", category="header_analysis",
                     description="Detecta si el correo carece de versión HTML (solo texto plano)")
def check_content_type(headers: dict) -> RuleResult:
    content_type = headers.get("content-type", "")

    if not content_type:
        return RuleResult(
            score=0, verdict="neutral",
            details={"content_type": "missing"},
            recommendation=None,
        )

    if "multipart" not in content_type.lower() and "text/plain" in content_type.lower():
        return RuleResult(
            score=-2, verdict="suspicious",
            details={"content_type": "text/plain only — no multipart alternative"},
            recommendation="El correo solo contiene texto plano sin versión HTML. "
                           "Aunque no es necesariamente malicioso, el phishing simple a menudo usa solo texto plano.",
        )

    return RuleResult(
        score=0, verdict="pass",
        details={"content_type": content_type},
        recommendation=None,
    )
