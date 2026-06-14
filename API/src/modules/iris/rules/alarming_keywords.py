"""
Alarming Keywords rule — flags urgent or pressuring language in Subject
and From display name (English & Spanish).

Phishing campaigns rely on urgency and fear to bypass rational thinking.
Common tactics include words like "urgent", "suspended", "verify now",
"action required", "cuenta suspendida", "verificación requerida", etc.
"""

from .registry import iris_rules, RuleResult

ALARMING_KEYWORDS = [
    "urgent", "urgente", "immediate", "inmediato",
    "action required", "acción requerida", "act now", "actúa ahora",
    "verify now", "verifica ahora", "verification required", "verificación requerida",
    "account suspended", "cuenta suspendida", "account blocked", "cuenta bloqueada",
    "password expired", "contraseña expirada", "password reset", "restablecer contraseña",
    "limited time", "tiempo limitado", "expires soon", "vence pronto",
    "security alert", "alerta de seguridad", "unauthorized access", "acceso no autorizado",
    "confirm your account", "confirma tu cuenta", "update required", "actualización requerida",
    "click here", "haz clic aquí", "download now", "descarga ahora",
    "last warning", "último aviso", "final notice", "aviso final",
    "suspension notice", "aviso de suspensión", "reactivate", "reactivar",
    "billing issue", "problema de facturación", "payment failed", "pago fallido",
    "claim your prize", "reclama tu premio", "you won", "has ganado",
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


def _score_by_count(count: int) -> tuple[float, str, str | None]:
    if count >= 4:
        return (-15, "high", "El asunto y/o nombre del remitente contiene múltiples palabras o frases "
                         "alarmantes que son características de campañas de phishing con alta urgencia.")
    if count >= 2:
        return (-10, "medium", "Se detectaron varias palabras o frases alarmantes en el asunto o "
                         "nombre del remitente. Esto es común en correos de phishing que buscan "
                         "provocar una reacción impulsiva.")
    if count == 1:
        return (-5, "low", "Se detectó una palabra o frase alarmante en el asunto o nombre del "
                         "remitente. Podría ser legítimo, pero merece atención.")
    return (0, "pass", None)


@iris_rules.register(name="Alarming Keywords", category="content_analysis",
                     description="Detecta palabras y frases alarmantes en el asunto y nombre del remitente (inglés/español)")
def check_alarming_keywords(headers: dict) -> RuleResult:
    subject = headers.get("subject", "")
    from_addr = headers.get("from", "")
    display_name = _extract_display_name(from_addr)

    combined = (subject + " " + display_name).lower()
    found_keywords: list[str] = []

    for kw in ALARMING_KEYWORDS:
        if kw in combined:
            found_keywords.append(kw)

    for emoji in ALARMING_EMOJI_PATTERNS:
        if emoji in combined:
            found_keywords.append(repr(emoji))

    count = len(found_keywords)
    score, severity, recommendation = _score_by_count(count)

    if severity == "pass":
        return RuleResult(
            score=0, verdict="pass",
            details={"subject": subject, "display_name": display_name, "alarming_keywords_found": []},
            recommendation=None,
        )

    return RuleResult(
        score=score, verdict=f"alarming_{severity}",
        details={
            "subject": subject,
            "display_name": display_name,
            "alarming_keywords_found": found_keywords,
            "keyword_count": count,
        },
        recommendation=recommendation,
    )
