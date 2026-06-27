"""
Subdomain Impersonation rule — detects subdomain tricks where a brand
name is embedded as a subdomain of an attacker-controlled domain.

Examples:
    ``paypal.com.secure-login.tk`` — brand as third+ label
    ``secure-paypal.com``           — brand combined with action words
    ``paypal-login.xyz``            — brand + dash + action word
    ``account-microsoft-verify.com`` — multiple brand/action tokens

This is distinct from ``Lookalike Sender Domain``, which only inspects
the registrable label. Here we look at the *full* domain from the right
and flag any well-known brand name appearing in a non-registrable label.
"""

import re

from .registry import iris_rules, RuleResult, extract_domain, _MULTI_LEVEL_TLDS
from .misspelled_brands import CANONICAL_BRANDS

_ACTION_WORDS = {
    "login", "log-in", "signin", "sign-in", "secure", "security", "verify",
    "verification", "verification1", "account", "accounts", "support",
    "billing", "invoice", "update", "confirm", "auth", "authenticate",
    "service", "help", "alert", "alerts", "notification", "notifications",
    "online", "web", "portal", "office", "365", "mail", "team", "reset",
    "unlock", "recovery",
}


def _registrable_label(domain: str) -> str:
    labels = domain.strip(".").lower().split(".")
    if len(labels) < 2:
        return labels[0] if labels else ""
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LEVEL_TLDS and len(labels) >= 3:
        return labels[-3]
    return labels[-2]


def _is_trusted_brand_domain(domain: str) -> bool:
    label = _registrable_label(domain)
    return label in CANONICAL_BRANDS


def find_brand_in_subdomain(domain: str) -> dict | None:
    """Detect a known brand used as a *non-registrable* label of ``domain``.

    ``github.com.sessions-security.com`` -> brand ``github`` appears to the
    left while the real registrable domain is ``sessions-security.com``. This
    is the brand-as-subdomain deception, reusable for both the From domain
    and body-link hosts. Returns ``{"brand", "label"}`` or ``None`` when the
    domain genuinely belongs to the brand (or no brand is embedded).
    """
    if not domain or "xn--" in domain:
        return None
    labels = [l for l in domain.lower().strip(".").split(".") if l]
    if len(labels) < 3:
        return None
    if _registrable_label(domain) in CANONICAL_BRANDS:
        return None  # genuinely the brand's own domain (e.g. mail.github.com)
    pre_labels = (
        labels[:-3] if ".".join(labels[-2:]) in _MULTI_LEVEL_TLDS else labels[:-2]
    )
    for lbl in pre_labels:
        for token in re.split(r"[^a-z0-9]+", lbl):
            if token in CANONICAL_BRANDS:
                return {"brand": token, "label": lbl}
    return None


@iris_rules.register(
    name="Subdomain Impersonation",
    category="header_analysis",
    description=(
        "Detecta trucos de subdominio donde un nombre de marca conocido aparece "
        "como subdominio o combinado con action-words en un dominio controlado "
        "por el atacante (paypal.com.secure-login.tk, secure-microsoft-verify.com)."
    ),
)
def check_subdomain_impersonation(headers: dict) -> RuleResult:
    domain = extract_domain(headers.get("from", ""))
    if not domain:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": headers.get("from", "")},
            recommendation=None,
        )

    if _is_trusted_brand_domain(domain):
        return RuleResult(score=1, verdict="pass", details={"domain": domain}, recommendation=None)

    if "xn--" in domain:
        return RuleResult(
            score=-10, verdict="fail",
            details={"domain": domain, "type": "punycode_in_subdomain"},
            recommendation=(
                f"El dominio {domain} usa codificación punycode. Combinado con la "
                "imposible coincidencia con un subdominio, es muy probable phishing."
            ),
        )

    labels = domain.lower().split(".")
    reg_label = _registrable_label(domain)
    if reg_label in CANONICAL_BRANDS:
        return RuleResult(score=0, verdict="neutral", details={"domain": domain}, recommendation=None)

    pre_labels = [l for l in labels[:-2] if l] if ".".join(labels[-2:]) in _MULTI_LEVEL_TLDS \
        else [l for l in labels[:-1] if l]

    findings: list[dict] = []

    if len(labels) >= 3:
        for lbl in pre_labels:
            tokens = re.split(r"[^a-z0-9]+", lbl)
            for token in tokens:
                if not token:
                    continue
                if token in CANONICAL_BRANDS:
                    findings.append({"subdomain_label": lbl, "token": token, "type": "brand_in_subdomain"})

    all_left_labels = pre_labels + [reg_label]
    for lbl in all_left_labels:
        if "-" not in lbl:
            continue
        if lbl in CANONICAL_BRANDS:
            continue
        tokens = re.split(r"-+", lbl)
        brand_hits = [t for t in tokens if t in CANONICAL_BRANDS]
        action_hits = [t for t in tokens if t in _ACTION_WORDS]
        if brand_hits and action_hits:
            if not any(f.get("label") == lbl and f.get("type") == "brand_action_combo" for f in findings):
                findings.append({
                    "label": lbl, "brand": brand_hits[0], "action": action_hits[0],
                    "type": "brand_action_combo",
                })

    if not findings:
        return RuleResult(score=0, verdict="neutral", details={"domain": domain}, recommendation=None)

    types = sorted({f["type"] for f in findings})
    score = -12 if any(f["type"] == "brand_in_subdomain" for f in findings) else -8

    return RuleResult(
        score=score, verdict="fail",
        details={"domain": domain, "registrable_label": reg_label, "findings": findings},
        recommendation=(
            f"El dominio {domain} usa un truco de subdominio para imitar a una "
            f"marca conocida ({', '.join(types)}). El dominio real del remitente "
            "NO pertenece a la marca; el atacante solo usa la marca como "
            "etiqueta para aparentar legitimidad."
        ),
    )
