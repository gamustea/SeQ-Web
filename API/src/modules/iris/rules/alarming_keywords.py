"""
Alarming Keywords rule — flags urgent or pressuring language in Subject
and From display name (English & Spanish).

Phishing campaigns rely on urgency and fear to bypass rational thinking.
Keywords are split into two tiers so that ordinary marketing language
("free", "limited time") does not weigh the same as account-takeover
phrases ("account suspended", "verify now"), which keeps false positives
on legitimate promotional mail under control.
"""

from .registry import iris_rules, RuleResult
from ..services.header_decode import decode_mime_words

# Strong, phishing-specific phrases (account takeover, fraud, prizes).
HIGH_SIGNAL_KEYWORDS = [
    "action required", "acción requerida", "act now", "actúa ahora",
    "verify now", "verifica ahora", "verification required", "verificación requerida",
    "account suspended", "cuenta suspendida", "account blocked", "cuenta bloqueada",
    "password expired", "contraseña expirada",
    "security alert", "alerta de seguridad", "unauthorized access", "acceso no autorizado",
    "confirm your account", "confirma tu cuenta",
    "last warning", "último aviso", "final notice", "aviso final",
    "suspension notice", "aviso de suspensión", "reactivate", "reactivar",
    "billing issue", "problema de facturación", "payment failed", "pago fallido",
    "claim your prize", "reclama tu premio", "you won", "has ganado",
]

# Weaker, marketing-flavoured language that also appears in legitimate mail.
LOW_SIGNAL_KEYWORDS = [
    "urgent", "urgente", "immediate", "inmediato",
    "password reset", "restablecer contraseña",
    "limited time", "tiempo limitado", "expires soon", "vence pronto",
    "update required", "actualización requerida",
    "click here", "haz clic aquí", "download now", "descarga ahora",
    "exclusive offer", "oferta exclusiva", "free", "gratis",
    "dear customer", "estimado cliente", "dear user", "estimado usuario",
]

ALARMING_EMOJI_PATTERNS = [
    "\N{DOUBLE EXCLAMATION MARK}",
    "\N{EXCLAMATION QUESTION MARK}",
    "\N{CROSS MARK}",
    "\N{WARNING SIGN}",
]


def _extract_display_name(from_header: str) -> str:
    if "<" in from_header:
        return from_header.split("<")[0].strip().strip('"').strip("'")
    return ""


def _score_by_weight(weight: int) -> tuple[float, str, str | None]:
    """Map a weighted keyword score to (score, severity, recommendation).

    ``weight`` counts each high-signal hit as 2 and each low-signal hit
    (and alarming emoji) as 1.
    """
    if weight >= 5:
        return (-15, "high", "El asunto y/o nombre del remitente contiene múltiples palabras o frases "
                         "alarmantes que son características de campañas de phishing con alta urgencia.")
    if weight >= 3:
        return (-10, "medium", "Se detectaron varias palabras o frases alarmantes en el asunto o "
                         "nombre del remitente. Esto es común en correos de phishing que buscan "
                         "provocar una reacción impulsiva.")
    if weight >= 1:
        return (-5, "low", "Se detectó lenguaje de urgencia en el asunto o nombre del remitente. "
                         "Podría ser legítimo (marketing), pero merece atención.")
    return (0, "pass", None)


@iris_rules.register(name="Alarming Keywords", category="content_analysis",
                     description="Detecta palabras y frases alarmantes en el asunto y nombre del remitente (inglés/español)")
def check_alarming_keywords(headers: dict) -> RuleResult:
    subject = decode_mime_words(headers.get("subject", ""))
    from_addr = decode_mime_words(headers.get("from", ""))
    display_name = _extract_display_name(from_addr)

    combined = (subject + " " + display_name).lower()

    high_found = [kw for kw in HIGH_SIGNAL_KEYWORDS if kw in combined]
    low_found = [kw for kw in LOW_SIGNAL_KEYWORDS if kw in combined]
    emoji_found = [repr(e) for e in ALARMING_EMOJI_PATTERNS if e in combined]

    weight = 2 * len(high_found) + len(low_found) + len(emoji_found)
    score, severity, recommendation = _score_by_weight(weight)

    found_keywords = high_found + low_found + emoji_found

    if severity == "pass":
        return RuleResult(
            score=1, verdict="pass",
            details={"subject": subject, "display_name": display_name, "alarming_keywords_found": []},
            recommendation=None,
        )

    return RuleResult(
        score=score, verdict=f"alarming_{severity}",
        details={
            "subject": subject,
            "display_name": display_name,
            "alarming_keywords_found": found_keywords,
            "high_signal": high_found,
            "low_signal": low_found,
            "weight": weight,
        },
        recommendation=recommendation,
    )
