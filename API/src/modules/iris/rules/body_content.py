"""
Body content scanning rule (Fase 2).

Extends the subject/display-name keyword scan to the actual message
body, where most phishing pretexts (credential requests, payment
redirection, urgency) live. Also flags classic hidden-text evasion
(zero/near-zero font-size, display:none, opacity:0) used to dodge
plain-text keyword scanners while still rendering normally to victims.
"""

from __future__ import annotations

import re

from .registry import iris_rules, RuleResult

_TAG_RE = re.compile(r"<[^>]+>")

CREDENTIAL_PHRASES = [
    "verify your password", "confirm your password", "enter your password",
    "verify your account", "your account has been locked", "update your billing",
    "confirm your identity", "log in to verify", "click the link below to verify",
    "your account will be suspended", "unusual activity detected",
    "wire transfer", "payment is overdue", "outstanding invoice attached",
    "verify your social security", "update your payment information",
    "confirma tu contraseña", "verifica tu cuenta", "tu cuenta ha sido bloqueada",
    "actualiza tu información de pago", "transferencia bancaria urgente",
]

HIDDEN_TEXT_RE = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?\b|opacity\s*:\s*0\b)",
    re.IGNORECASE,
)


def _strip_html(html: str) -> str:
    return _TAG_RE.sub(" ", html)


@iris_rules.register(
    name="Body Content", category="content_analysis",
    description=(
        "Escanea el cuerpo del correo en busca de frases de phishing "
        "(credenciales/pago) y técnicas de texto oculto."
    ),
    needs_context=True,
)
def check_body_content(context) -> RuleResult:
    body_html = context.body_html or ""
    text = (context.body_text or "") + " " + _strip_html(body_html)
    text_lower = text.lower()

    if not text_lower.strip():
        return RuleResult(score=0, verdict="neutral", details={"reason": "empty body"})

    found = [p for p in CREDENTIAL_PHRASES if p in text_lower]
    hidden = bool(HIDDEN_TEXT_RE.search(body_html))

    if not found and not hidden:
        return RuleResult(score=0, verdict="pass", details={})

    score = 0
    if found:
        score -= 5 * min(len(found), 3)
    if hidden:
        score -= 10

    return RuleResult(
        score=score, verdict="fail",
        details={"phrases_found": found, "hidden_text": hidden},
        recommendation=(
            "El cuerpo del correo contiene frases típicas de phishing"
            + (" y texto oculto." if hidden else ".")
        ),
    )
