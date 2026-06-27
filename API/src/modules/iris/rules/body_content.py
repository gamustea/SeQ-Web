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
_STYLE_BLOCK_RE = re.compile(r"<style\b[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL)

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

# Tags whose opening attributes carry an inline hidden-text style, captured
# together with their content so we can judge *what* is being hidden.
_HIDDEN_TAG_RE = re.compile(
    r'<(?P<tag>\w+)\b(?P<attrs>[^>]*?style\s*=\s*"[^"]*'
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?\b|opacity\s*:\s*0\b)"
    r'[^"]*"[^>]*)>(?P<inner>.*?)</\1>',
    re.IGNORECASE | re.DOTALL,
)

# Well-known, ubiquitous ESP/email-template patterns that legitimately hide
# markup: preview/preheader text (shown only in the inbox list), responsive
# show/hide breakpoints, and tracking-pixel/icon spacer wrappers. None of
# these are scanner-evasion techniques, so they must not trip the rule.
_BENIGN_HIDDEN_CLASS_RE = re.compile(
    r'class\s*=\s*"[^"]*\b(preheader|preview-text|mobile-only|mobile-hidden|'
    r"desktop-only|lg-hidden|sm-hidden|hidden-mobile|hidden-desktop|icon|spacer|tracking)\b",
    re.IGNORECASE,
)


def _strip_html(html: str) -> str:
    return _TAG_RE.sub(" ", html)


def _strip_style_blocks(html: str) -> str:
    """Remove ``<style>...</style>`` blocks.

    Responsive HTML emails define show/hide breakpoints as plain CSS rules
    (``.mobile-hidden { display: none !important; }``). Those are stylesheet
    *definitions*, not evasive hidden text, and must not feed the hidden-text
    heuristic below — only inline ``style="..."`` on actual content should.
    """
    return _STYLE_BLOCK_RE.sub(" ", html)


def _has_evasive_hidden_text(body_html: str) -> bool:
    """Detect inline-hidden tags that hide *real, unlabelled text*.

    Email templates routinely hide markup on purpose: preheader/preview
    text, responsive show/hide breakpoints, and zero-size tracking pixels
    or icon spacers. Those are recognisable by their class name or by
    containing no real text (just an ``<img>``), so they're skipped. What's
    left — an inline ``display:none``/``font-size:0`` wrapper around plain
    text with no such marker — is the classic scanner-evasion pattern this
    rule targets.
    """
    for match in _HIDDEN_TAG_RE.finditer(body_html):
        if _BENIGN_HIDDEN_CLASS_RE.search(match.group("attrs")):
            continue
        inner_text = _strip_html(match.group("inner")).strip()
        if inner_text:
            return True
    return False


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
    hidden = _has_evasive_hidden_text(_strip_style_blocks(body_html))

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
