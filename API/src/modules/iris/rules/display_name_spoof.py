"""
Display Name Spoofing rule — detects when the From display name mimics a
well-known brand but the actual email domain is not owned by that brand.

Phishing attacks commonly set a display name like "Microsoft Support" or
"PayPal Customer Service" while using a free email provider (gmail.com,
outlook.com) or an obviously unrelated domain.
"""

import re

from .registry import iris_rules, RuleResult

BRAND_TRUSTED_DOMAINS: dict[tuple[str, ...], list[str]] = {
    ("microsoft", "windows", "office 365", "microsoft 365", "outlook", "azure", "msn"): [
        "microsoft.com", "microsoftsupport.com", "office.com",
        "office365.com", "outlook.com", "hotmail.com", "live.com",
        "azure.com", "msn.com", "windows.com", "xbox.com",
        "microsoftonline.com", "sharepoint.com", "teams.microsoft.com",
    ],
    ("paypal", "paypal"): [
        "paypal.com", "paypal.de", "paypal.fr", "paypal.es",
        "paypal.com.mx", "paypal.co.uk",
    ],
    ("netflix", "netflix"): [
        "netflix.com", "nflx.com",
    ],
    ("amazon", "amazon prime", "amazon web services", "aws"): [
        "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
        "amazon.es", "amazon.it", "amazon.ca", "amazon.co.jp",
        "amazonaws.com", "aws.amazon.com",
    ],
    ("google", "gmail", "youtube", "google drive"): [
        "google.com", "gmail.com", "youtube.com", "googlemail.com",
        "googleusercontent.com", "googleapis.com",
    ],
    ("apple", "icloud", "itunes", "app store", "apple store"): [
        "apple.com", "icloud.com", "me.com", "mac.com",
    ],
    ("facebook", "meta", "instagram", "whatsapp", "messenger"): [
        "facebook.com", "fb.com", "fbcdn.net", "meta.com",
        "instagram.com", "whatsapp.com", "messenger.com",
    ],
    ("linkedin", "linkedin"): [
        "linkedin.com", "linkedin-mail.com",
    ],
    ("twitter", "x.com", "twitter"): [
        "twitter.com", "x.com",
    ],
    ("dropbox", "dropbox"): [
        "dropbox.com", "dropboxmail.com",
    ],
    ("adobe", "adobe"): [
        "adobe.com", "adobeemail.com",
    ],
    ("bank of america", "boa", "bank of america"): [
        "bankofamerica.com", "ml.com",
    ],
    ("chase", "jpmorgan", "chase"): [
        "chase.com", "jpmorgan.com",
    ],
    ("wells fargo", "wells fargo"): [
        "wellsfargo.com",
    ],
    ("bbva", "bbva", "bancomer"): [
        "bbva.com", "bbva.com.mx", "bbvanet.com.mx",
    ],
    ("santander", "santander"): [
        "santander.com", "santander.com.mx", "santander.es",
        "openbank.com",
    ],
    ("mercadopago", "mercadopago", "mercadolibre"): [
        "mercadopago.com", "mercadolibre.com",
        "mercadolibre.com.mx",
    ],
}

FREE_PROVIDER_DOMAINS = [
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "yahoo.com.mx", "yahoo.es", "ymail.com",
    "aol.com", "aim.com",
    "protonmail.com", "proton.me",
    "mail.com", "email.com",
    "icloud.com", "me.com",
    "zoho.com", "yandex.com",
    "gmx.com", "gmx.es",
    "tutanota.com", "tutanota.de",
    "fastmail.com",
    "rediffmail.com",
    "mail.ru",
]


def _extract_email(from_header: str) -> str:
    match = re.search(r"[\w.+-]+@[\w.-]+", from_header)
    return match.group(0) if match else ""


def _extract_display_name(from_header: str) -> str:
    if "<" in from_header:
        return from_header.split("<")[0].strip().strip('"').strip("'")
    name_part = from_header.strip()
    if "@" not in name_part:
        return name_part
    return ""


def _domain_matches_trusted(domain: str, trusted_domains: list[str]) -> bool:
    domain = domain.lower()
    for trusted in trusted_domains:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False


@iris_rules.register(name="Display Name Spoofing", category="header_analysis",
                     description="Detecta si el nombre del remitente suplanta a una marca conocida pero el dominio del correo no pertenece a ella")
def check_display_name_spoof(headers: dict) -> RuleResult:
    from_addr = headers.get("from", "")
    display_name = _extract_display_name(from_addr)
    email = _extract_email(from_addr)

    if not email:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": from_addr},
            recommendation=None,
        )

    if not display_name:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": from_addr, "email": email},
            recommendation=None,
        )

    domain = email.split("@")[-1].lower()
    display_lower = display_name.lower()
    display_words = set(re.findall(r"[\w']+", display_lower))

    matched_brands: list[str] = []

    for keywords, trusted_domains in BRAND_TRUSTED_DOMAINS.items():
        for kw in keywords:
            if kw in display_lower:
                matched_brands.append(kw)
                break

    if not matched_brands:
        return RuleResult(
            score=0, verdict="pass",
            details={"from": from_addr, "email": email, "display_name": display_name},
            recommendation=None,
        )

    for keywords, trusted_domains in BRAND_TRUSTED_DOMAINS.items():
        if any(kw in matched_brands for kw in keywords):
            if _domain_matches_trusted(domain, trusted_domains):
                return RuleResult(
                    score=5, verdict="pass",
                    details={
                        "from": from_addr, "email": email,
                        "display_name": display_name,
                        "found_brand": matched_brands,
                    },
                    recommendation=None,
                )
            break

    is_free_provider = any(domain == d or domain.endswith("." + d) for d in FREE_PROVIDER_DOMAINS)

    if is_free_provider:
        score = -12
        recommendation = (
            f"El nombre del remitente contiene '{', '.join(matched_brands)}' pero el correo "
            f"proviene de un proveedor de correo gratuito ({domain}). "
            "Las marcas legítimas no envían correos desde direcciones de Gmail, Outlook, etc. "
            "Esto es un fuerte indicador de suplantación (phishing)."
        )
    else:
        score = -8
        recommendation = (
            f"El nombre del remitente contiene '{', '.join(matched_brands)}' pero el dominio "
            f"real del correo ({domain}) no pertenece a la marca. "
            "Verifica que esta diferencia sea intencionada antes de responder o hacer clic."
        )

    return RuleResult(
        score=score, verdict="spoof",
        details={
            "from": from_addr, "email": email,
            "display_name": display_name,
            "domain": domain,
            "matched_brands": matched_brands,
            "is_free_provider": is_free_provider,
        },
        recommendation=recommendation,
    )
