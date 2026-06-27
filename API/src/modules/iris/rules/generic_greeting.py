"""
Generic Greeting + Action Verb rule — flags the canonical mass-mailing
phishing pattern: a generic greeting ("Dear customer / Dear user / Dear
sir or madam") combined with a high-signal action verb
("verify / confirm / update / suspend / password") in the body.

Both elements on their own are weak: legitimate first-time mailouts use
generic greetings, and many legitimate transactional emails use action
verbs. The *combination* is the strong signal — bulk phish rarely
personalises and almost always asks the user to do something risky.
"""

import re

from .registry import iris_rules, RuleResult

GENERIC_GREETINGS = [
    "dear customer",
    "dear user",
    "dear member",
    "dear sir",
    "dear madam",
    "dear sir or madam",
    "dear sir/madam",
    "dear account holder",
    "dear valued customer",
    "dear client",
    "dear subscriber",
    "dear email owner",
    "hello dear",
    "hello customer",
    "hello user",
    "attention customer",
    "attention user",
    "important notice to all",
    "to our valued customer",
    "to whom it may concern",
    "estimado cliente",
    "estimado usuario",
    "estimado miembro",
    "estimado cliente de",
    "distinguido cliente",
    "querido usuario",
    "hola cliente",
    "hola usuario",
    "atención cliente",
    "atención usuario",
    "a quien corresponda",
    "a todos los usuarios",
    "notificación para todos",
    "apreciable cliente",
    "apreciable usuario",
]

# Action verbs that, when bundled with a credential/payment request,
# are the classic phishing payload. The list intentionally overlaps
# with ``alarming_keywords`` but lives here to be combined with the
# greeting heuristic — not used in isolation.
ACTION_VERBS = [
    "verify your account",
    "verify your identity",
    "verify your password",
    "verify your email",
    "verify your information",
    "verify your payment",
    "confirm your account",
    "confirm your identity",
    "confirm your password",
    "confirm your information",
    "confirm your payment",
    "confirm your billing",
    "confirm your details",
    "update your account",
    "update your billing",
    "update your payment",
    "update your information",
    "update your password",
    "reactivate your account",
    "re-activate your account",
    "unlock your account",
    "restore your account",
    "secure your account",
    "validate your account",
    "click here to verify",
    "click the link below",
    "click below to",
    "log in to verify",
    "sign in to confirm",
    "verifica tu cuenta",
    "verifica tu identidad",
    "verifica tu contraseña",
    "verifica tu correo",
    "verifica tu información",
    "verifica tu pago",
    "confirma tu cuenta",
    "confirma tu identidad",
    "confirma tu contraseña",
    "confirma tu información",
    "confirma los datos de su cuenta",
    "actualiza tu cuenta",
    "actualiza tu información",
    "actualiza tu contraseña",
    "actualiza tus datos",
    "actualiza tu pago",
    "reactiva tu cuenta",
    "desbloquea tu cuenta",
    "asegura tu cuenta",
    "valida tu cuenta",
    "haz clic aquí para verificar",
    "inicia sesión para verificar",
]

_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(html: str) -> str:
    return _TAG_RE.sub(" ", html or "")


@iris_rules.register(
    name="Generic Greeting",
    category="content_analysis",
    description=(
        "Detecta el patrón clásico de phishing masivo: saludo genérico "
        "('Dear customer') combinado con un verbo de acción sospechoso "
        "('verify', 'confirm', 'update') en el cuerpo del correo."
    ),
    needs_context=True,
)
def check_generic_greeting(context) -> RuleResult:
    body_html = context.body_html or ""
    body_text = context.body_text or ""
    text = (body_text + " " + _strip_html(body_html)).lower()
    if not text.strip():
        return RuleResult(score=0, verdict="neutral", details={"reason": "empty body"})

    first_chunk = text[:600]

    greeting_hits = [g for g in GENERIC_GREETINGS if g in first_chunk]
    action_hits = [v for v in ACTION_VERBS if v in text]

    if not greeting_hits or not action_hits:
        return RuleResult(
            score=0, verdict="neutral",
            details={"greeting_hits": greeting_hits, "action_hits": action_hits},
            recommendation=None,
        )

    score = -8
    if len(action_hits) >= 2:
        score -= 3

    return RuleResult(
        score=score, verdict="fail",
        details={
            "greeting_hits": greeting_hits,
            "action_hits": action_hits,
        },
        recommendation=(
            "El correo usa un saludo genérico "
            f"('{greeting_hits[0]}') y un verbo de acción sospechoso "
            f"('{action_hits[0]}'). Esta combinación es típica del phishing "
            "masivo: los remitentes legítimos que tienen tu dirección suelen "
            "personalizar el saludo. Verifica la legitimidad antes de actuar."
        ),
    )
