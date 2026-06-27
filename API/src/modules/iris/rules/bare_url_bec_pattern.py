"""
BEC / Wire-Transfer Pattern rule — flags the classic Business Email
Compromise payload: a corporate-looking sender requesting an urgent
financial action (wire transfer, gift cards, crypto, banking change).

The body-content rule already detects credential phrases, but it does
not weight them against the *legitimacy* of the sender domain. In a BEC
attack, the sender domain is the real corporate domain (it was either
spoofed successfully or a legitimate account was compromised) and the
phishing signal lives entirely in the body asking for money.
"""

import re

from .registry import iris_rules, RuleResult, extract_domain, registrable_domain

# High-signal action phrases for BEC. These are the *payload* verbs, not
# the credential-phishing phrases already covered by ``body_content``.
_BEC_PHRASES_EN = [
    "wire transfer", "wire the funds", "initiate a wire",
    "send the payment", "process the payment", "urgent payment",
    "outstanding invoice", "overdue invoice", "pay this invoice",
    "outstanding balance", "settle the balance", "make the deposit",
    "send gift cards", "buy gift cards", "purchase gift cards",
    "send bitcoin", "send crypto", "wire cryptocurrency", "usdt transfer",
    "change the bank account", "update our banking details",
    "new bank account", "new routing number", "new wire instructions",
    "change of vendor payment", "vendor banking update",
    "confidential transaction", "do not notify", "keep this confidential",
    "do this while i'm out", "while i'm in a meeting", "asap",
    "w-2 form", "w2 form", "employee tax forms", "1099 form",
]
_BEC_PHRASES_ES = [
    "transferencia urgente", "transferencia bancaria urgente",
    "realizar el pago", "procesar el pago", "pago pendiente",
    "factura pendiente", "factura vencida", "saldo pendiente",
    "comprar tarjetas de regalo", "tarjetas de regalo",
    "enviar bitcoin", "transferencia cripto", "criptomonedas",
    "cambiar la cuenta bancaria", "nueva cuenta bancaria",
    "número de ruta", "datos bancarios nuevos",
    "confidencial", "no notifiques", "no informar a",
    "mientras estoy en reunión", "con urgencia", "lo antes posible",
]

_ALL_PHRASES = _BEC_PHRASES_EN + _BEC_PHRASES_ES

_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(html: str) -> str:
    return _TAG_RE.sub(" ", html or "")


@iris_rules.register(
    name="BEC Wire Transfer Pattern",
    category="content_analysis",
    description=(
        "Detecta el patrón típico de BEC (Business Email Compromise): "
        "remitente con dominio corporativo y cuerpo pidiendo wire transfer, "
        "cripto, tarjetas de regalo, o cambio de cuenta bancaria."
    ),
    needs_context=True,
)
def check_bec_wire_pattern(context) -> RuleResult:
    headers = context.headers
    body_html = context.body_html or ""
    body_text = context.body_text or ""
    text = (body_text + " " + _strip_html(body_html)).lower()

    from_domain = registrable_domain(extract_domain(headers.get("from", "")))
    reply_domain = registrable_domain(extract_domain(headers.get("reply-to", "")))

    if not from_domain:
        return RuleResult(score=0, verdict="neutral", details={}, recommendation=None)

    matches = [p for p in _ALL_PHRASES if p in text]

    if not matches:
        return RuleResult(score=0, verdict="neutral",
                          details={"from_domain": from_domain, "matches": []}, recommendation=None)

    suspicious_redirect = (
        reply_domain and reply_domain != from_domain
    )

    base = -12
    if len(matches) >= 2:
        base -= 6
    if suspicious_redirect:
        base -= 4

    return RuleResult(
        score=base, verdict="fail",
        details={
            "from_domain": from_domain,
            "reply_domain": reply_domain,
            "matches": matches,
            "redirect_to_external_reply": suspicious_redirect,
        },
        recommendation=(
            f"El cuerpo contiene {len(matches)} frase(s) típica(s) de fraude BEC "
            f"({', '.join(matches[:3])}). El remitente usa un dominio "
            f"corporativo ({from_domain}), lo que hace este patrón especialmente "
            "peligroso: si el dominio es legítimo, la cuenta puede estar "
            "comprometida; si es suplantado, es un ataque dirigido. Verifica "
            "por un canal alternativo (teléfono, en persona) ANTES de "
            "realizar cualquier pago o cambio de datos bancarios."
        ),
    )
