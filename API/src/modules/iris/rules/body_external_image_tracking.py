"""
External Image Tracking rule — flags emails whose HTML body pulls
images (or other resources) from a domain that is NOT the From domain
and NOT a known Email Service Provider (ESP) tracker.

Legitimate bulk mailers either inline their images (cid:) or load them
from their own infrastructure or from a recognised ESP
(SendGrid/Mailgun/Amazon SES, marketing platforms, etc.). A phishing
email embedding remote images from an unrelated, non-ESP domain is
either:
- A tracking pixel whose 1x1 GIF is used to confirm the address is live.
- A credential-harvesting page screenshot hosted on attacker infra.

We can not *prove* the image is malicious without fetching it, but the
*absence* of any of the legitimate senders is a useful soft signal,
especially combined with the image-only rule.
"""

import re
from urllib.parse import urlparse

from .registry import iris_rules, RuleResult, extract_domain, registrable_domain

# ESP / Marketing / bulk-mail image CDNs that are NOT the From domain but
# are still legitimate (almost every ESP proxies images through its own
# domain). This list is intentionally narrow — add new ESPs as you
# encounter them in your legitimate mail flow.
KNOWN_ESP_TRACKER_DOMAINS = {
    "sendgrid.net", "mailgun.org", "mailchimp.com", "constantcontact.com",
    "hubspot.com", "hubspotusercontent-na1.net", "hubspotusercontent-eu1.net",
    "marketo.com", "eloqua.com", "exacttarget.com", "responsys.net",
    "mailerlite.com", "mailjet.com", "postmarkapp.com", "smtp.com",
    "amazonaws.com", "cloudfront.net", "googleusercontent.com",
    "s3.amazonaws.com", "mailchimpusercontent.com", "list-manage.com",
    "mktoresp.com", "en25.com", "s4.exacttarget.com",
    "s7.addthis.com", "addthis.com", "tracking.mi-al.it",
    "mta-in.com", "rs6.net", "t.sendgrid.net", "click.mi-al.it",
    "link.mi-al.it", "open.mi-al.it",
}

_IMG_SRC_RE = re.compile(r'<img\b[^>]*src\s*=\s*["\']([^"\']+)["\']',
                          re.IGNORECASE)
_SRC_RE = re.compile(r'''src\s*=\s*["\']([^"']+)["\']''', re.IGNORECASE)


def _host_of(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = parsed.netloc.split("@")[-1].split(":")[0].lower()
    return host or None


@iris_rules.register(
    name="External Image Tracking",
    category="content_analysis",
    description=(
        "Detecta imágenes (u otros recursos) embebidos desde un dominio "
        "externo que no es el From ni un ESP/marketing conocido. Patrón "
        "de tracking pixel y de phishing con payload en imagen."
    ),
    needs_context=True,
)
def check_external_image_tracking(context) -> RuleResult:
    body_html = context.body_html or ""
    if not body_html:
        return RuleResult(score=0, verdict="neutral", details={"reason": "no html body"})

    from_domain = registrable_domain(extract_domain(context.headers.get("from", "")))

    sources = [m.group(1) for m in _IMG_SRC_RE.finditer(body_html)]

    findings: list[dict] = []
    for src in sources:
        if not src.startswith(("http://", "https://")):
            continue
        host = _host_of(src)
        if not host:
            continue
        reg = registrable_domain(host)
        if from_domain and reg == from_domain:
            continue
        if reg in KNOWN_ESP_TRACKER_DOMAINS or host in KNOWN_ESP_TRACKER_DOMAINS:
            continue
        findings.append({"src": src, "host": host, "registrable": reg})

    if not findings:
        return RuleResult(
            score=0, verdict="pass",
            details={"from_domain": from_domain, "external_image_count": 0},
            recommendation=None,
        )

    unique_hosts = {f["registrable"] for f in findings if f["registrable"]}
    score = -5 if len(unique_hosts) == 1 else -8

    return RuleResult(
        score=score, verdict="fail",
        details={
            "from_domain": from_domain,
            "external_image_count": len(findings),
            "external_image_hosts": sorted(unique_hosts),
            "findings": findings,
        },
        recommendation=(
            f"El cuerpo carga imágenes desde {len(unique_hosts)} dominio(s) "
            f"externo(s) no-ESP ({', '.join(sorted(unique_hosts))}). Esto es "
            "compatible con un tracking pixel de confirmación de dirección "
            "activa o con un payload de phishing renderizado como imagen. "
            "Bloquea la carga automática de imágenes en tu cliente hasta "
            "verificar el remitente."
        ),
    )
