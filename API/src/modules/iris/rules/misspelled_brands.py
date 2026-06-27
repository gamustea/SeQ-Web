"""
Misspelled Brand Names rule — detects homoglyph attacks and common
typosquatting of well-known brands in the Subject and From display name.

Phishing campaigns use deceptive spellings (e.g., "Micr0soft", "PayPa1",
"Netfl1x") to bypass brand filters while visually mimicking legitimate
companies.
"""

import re

from .registry import iris_rules, RuleResult, extract_display_name
from ..services.header_decode import decode_mime_words

HOMOGLYPH_MAP = str.maketrans({
    "0": "o", "1": "l", "2": "z", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "€": "e",
})

CANONICAL_BRANDS = {
    "microsoft", "paypal", "netflix", "amazon", "google", "apple",
    "facebook", "instagram", "linkedin", "twitter", "whatsapp",
    "adobe", "dropbox", "spotify", "yahoo", "outlook", "hotmail",
    "gmail", "youtube", "tiktok", "snapchat", "pinterest",
    "telegram", "signal", "discord", "github", "gitlab",
    "bitbucket", "salesforce", "oracle", "ibm", "intel", "nvidia",
    "amd", "cisco", "vmware", "sap", "accenture", "deloitte",
    "pwc", "kpmg", "ey",
    "mercadopago", "bbva", "santander", "banamex",
    "bancomer", "hsbc", "amex", "mastercard", "visa",
    "wellsfargo", "chase", "bankofamerica",
    "alibaba", "aliexpress", "ebay", "shopify", "etsy",
    "walmart", "target", "costco", "homedepot", "bestbuy",
    "nike", "adidas", "zara", "hm", "uniqlo",
    "uber", "lyft", "airbnb", "booking", "expedia",
    "hulu", "disney", "hbomax", "primevideo",
    "whatsapp", "telegram", "wechat", "messenger", "skype",
    "zoom", "teams", "slack", "notion", "trello",
    "wordpress", "shopify", "wix", "godaddy",
    "cloudflare", "digitalocean", "aws", "azure", "gcp",
}


def _normalize_homoglyphs(text: str) -> str:
    return text.lower().translate(HOMOGLYPH_MAP)


def _find_typosquats(text: str) -> list[dict]:
    results: list[dict] = []
    words = set(re.findall(r"[a-zA-Z0-9@$€]{5,}", text.lower()))

    for word in words:
        # Exact match against a known brand — legitimate, skip
        if word in CANONICAL_BRANDS:
            continue

        # Check homoglyph-normalized match
        normalized = _normalize_homoglyphs(word)
        if normalized != word and normalized in CANONICAL_BRANDS:
            results.append({
                "found": word,
                "normalized": normalized,
                "type": "homoglyph",
            })
            continue

        # Check single-character edits (insertion, deletion, substitution)
        for brand in CANONICAL_BRANDS:
            if len(brand) < 4:
                continue
            # Skip if length difference > 2
            if abs(len(word) - len(brand)) > 2:
                continue

            # Check for common typos: double letters, missing letters
            if _levenshtein(word, brand) <= 2:
                results.append({
                    "found": word,
                    "normalized": brand,
                    "type": "typo",
                })
                break

    return results


def _levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev + cost)
            prev = temp
    return dp[n]


@iris_rules.register(name="Misspelled Brand Names", category="content_analysis",
                     description="Detecta homóglifos y errores tipográficos de marcas conocidas en el asunto y nombre del remitente")
def check_misspelled_brands(headers: dict) -> RuleResult:
    subject = decode_mime_words(headers.get("subject", ""))
    from_addr = decode_mime_words(headers.get("from", ""))
    display_name = extract_display_name(from_addr)

    combined = subject + " " + display_name

    if not combined.strip():
        return RuleResult(
            score=0, verdict="neutral",
            details={"subject": subject, "display_name": display_name},
            recommendation=None,
        )

    found = _find_typosquats(combined)

    if not found:
        return RuleResult(
            score=0, verdict="pass",
            details={"subject": subject, "display_name": display_name},
            recommendation=None,
        )

    count = len(found)
    types = set(f["type"] for f in found)
    names = ", ".join(f["found"] for f in found)

    return RuleResult(
        score=-5 * min(count, 2),
        verdict="fail",
        details={
            "subject": subject,
            "display_name": display_name,
            "suspicious_words": found,
            "count": count,
        },
        recommendation=(
            f"Se detectaron palabras sospechosas que se asemejan a marcas conocidas: {names}. "
            f"El uso de homóglifos ({'sí' if 'homoglyph' in types else 'no'}) o errores "
            f"tipográficos ({'sí' if 'typo' in types else 'no'}) es común en ataques de "
            f"phishing para evadir filtros de seguridad. "
            "No confíes en la apariencia visual del nombre del remitente."
        ),
    )
