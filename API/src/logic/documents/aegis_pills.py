"""
aegis_pills.py
─────────────
Lógica de generación de píldoras de concienciación.

Contiene:
    — Dataclasses de tránsito: AegisTipData, AegisContent, AegisAlert
    — Decoradores de resiliencia: retry_on_failure, circuit_breaker
    — AegisAlertFetcher: fetch concurrente de INCIBE y CIRCL
    — AegisAIWriter: generación de contenido con Ollama (hereda de AIWriter)
"""

from __future__ import annotations

import hashlib
import html
import json
import random
import re
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import ollama
from ddgs import DDGS

from src.core.model import Topic
from src.misc import SecOpsLogger

from src.logic.documents._base import AIWriter


# ============================================================================
# CONSTANTES
# ============================================================================

class SeverityLevel(str, Enum):
    CRITICA = "crítica"
    ALTA    = "alta"
    MEDIA   = "media"
    BAJA    = "baja"
    INFO    = "informativa"


class AlertSource(str, Enum):
    INCIBE = "incibe"
    CIRCL  = "circl"


MAX_BRANDS         = 5
MAX_ALERT_AGE_YEARS = 5
MAX_RETRIES        = 3
RETRY_DELAY_BASE   = 1.5  # segundos, backoff exponencial

FALLBACK_BRANDS: list[str] = [
    "Microsoft", "Google", "Cisco", "Apple", "Adobe",
    "Oracle", "SAP", "VMware", "Fortinet", "Palo Alto",
    "Juniper", "IBM", "Linux", "Android", "Chrome",
]

BRAND_SLUGS: dict[str, tuple[str, str]] = {
    "Microsoft": ("microsoft", "windows"),
    "Cisco":     ("cisco",     "ios"),
    "Apple":     ("apple",     "macos"),
    "Google":    ("google",    "chrome"),
    "Adobe":     ("adobe",     "acrobat"),
    "Android":   ("google",    "android"),
    "HPE":       ("hp",        "hpe"),
    "SonicWall": ("sonicwall", "sonicos"),
    "Konica":    ("konicaminolta", "printer"),
    "Juniper":   ("juniper",   "junos"),
    "VMware":    ("vmware",    "esxi"),
    "Palo Alto": ("paloaltonetworks", "pan-os"),
    "SAP":       ("sap",       "netweaver"),
    "Oracle":    ("oracle",    "database"),
    "Mozilla":   ("mozilla",   "firefox"),
    "Linux":     ("linux",     "kernel"),
    "Fortinet":  ("fortinet",  "fortios"),
}

FEW_SHOT_EXAMPLES = """
Ejemplo de output válido para tema "Phishing Empresarial":

{
    "subtitle": "No muerdas el anzuelo: Protección contra el phishing moderno",
    "intro": "El phishing representa una de las amenazas cibernéticas más persistentes y evolutivas del panorama actual de seguridad empresarial. Lo que comenzó hace décadas como correos electrónicos obvios y mal escritos se ha transformado en campañas sofisticadas de ingeniería social que explotan la psicología humana y el contexto organizacional. En entornos corporativos modernos, los atacantes han perfeccionado técnicas de suplantación que imitan con precisión alarmante a compañeros de trabajo, directivos e incluso proveedores de confianza, utilizando dominios similares y contextos conversacionales robados de brechas previas. Un solo clic en un enlace malicioso puede desencadenar una cascada de compromisos: desde el robo de credenciales corporativas hasta la instalación de ransomware que paraliza operaciones críticas, pasando por el acceso lateral a sistemas financieros y bases de datos de clientes. Las consecuencias económicas y reputacionales son devastadoras, con costes promedio que superan el millón de euros en medianas empresas. Esta píldora de concienciación profundiza en las señales de alerta sutiles que distinguen un correo legítimo de una trampa diseñada por ciberdelincuentes, proporcionando marcos prácticos de verificación y protocolos de respuesta que todo empleado debe internalizar para proteger los activos digitales de la organización.",
    "tips": [
        {
            "headline": "Verifica siempre el remitente real, no solo el nombre visible",
            "body": "Los atacantes configuran nombres de display que imitan a directivos o IT support. Haz clic en el nombre del remitente para ver la dirección email real. Desconfía de dominios similares como 'company-it.com' en lugar de 'company.com'.",
            "links": [
                {"text": "Guía de Google sobre verificación de remitentes", "url": "https://support.google.com/mail/answer/185835"}
            ]
        }
    ],
    "closing": "La prevención del phishing es responsabilidad de todos. Cuando tengas dudas sobre un correo sospechoso, contacta directamente a la persona o equipo mediante un canal alternativo antes de interactuar con el mensaje.",
    "contactEmail": "seguridad@empresa.com"
}

NOTA: El subtitle "No muerdas el anzuelo..." es creativo y diferente del tema técnico "Phishing Empresarial".

REGLA CRÍTICA: 
- Tema de entrada: "Phishing Empresarial" (técnico, genérico)
- Subtítulo generado: Debe ser creativo, atractivo y DIFERENTE al tema de entrada.
- NUNCA repitas "Phishing Empresarial" como subtitle. Transforma el concepto.
"""


# ============================================================================
# DATACLASSES DE TRÁNSITO
# ============================================================================

@dataclass(frozen=True)
class AegisTipData:
    """
    Consejo individual inmutable y validado.

    Se crea a partir de la respuesta del modelo, se valida en __post_init__
    y se descarta tras la persistencia en BD. No es un modelo ORM.
    """

    headline: str
    body:     str
    links:    list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.headline or len(self.headline) > 150:
            raise ValueError("headline debe tener entre 1 y 150 caracteres")
        if not self.body or len(self.body) < 50:
            raise ValueError("body debe tener al menos 50 caracteres")
        for link in self.links:
            if not isinstance(link, dict) or "text" not in link or "url" not in link:
                raise ValueError("cada link debe ser un dict con 'text' y 'url'")


@dataclass
class AegisContent:
    """
    Resultado estructurado de AegisAIWriter.generate_pill().

    Actúa como DTO de salida del writer. El manager lo consume para persistir
    en BD y para escribir el archivo JSON en disco (vía to_json_dict).
    No contiene lógica de exportación de cara al usuario: eso es
    responsabilidad de los exportadores en aegis_exporters.py.
    """

    topic_id:      int
    topic_title:   str
    language:      str
    company:       str
    generated_at:  str
    topic_note:    str           = ""
    subtitle:      str           = ""
    intro:         str           = ""
    tips:          list[AegisTipData] = field(default_factory=list)
    closing:       str           = ""
    contact_email: str           = ""

    def to_json_dict(self, document_id: int, alerts: list[AegisAlert]) -> dict:
        """
        Serialización para el archivo .json que se guarda en disco.

        Este método existe exclusivamente para la escritura del fichero de
        archivo. No se usa para respuestas de API ni para los exportadores
        de usuario (que leen de BD a través de get_document).
        """
        return {
            "version": "2.0",
            "metadata": {
                "documentId":  document_id,
                "topicId":     self.topic_id,
                "topicTitle":  self.topic_title,
                "language":    self.language,
                "company":     self.company,
                "generatedAt": self.generated_at,
                "checksum":    self._checksum(),
            },
            "pill": {
                "subtitle":     self.subtitle,
                "intro":        self.intro,
                "tips": [
                    {
                        "position": i + 1,
                        "headline": t.headline,
                        "body":     t.body,
                        "links":    t.links,
                    }
                    for i, t in enumerate(self.tips)
                ],
                "closing":      self.closing,
                "contactEmail": self.contact_email,
            },
            "alerts": [
                {
                    "title":       a.title,
                    "description": a.description,
                    "url":         a.url,
                    "source":      a.source.value,
                    "published":   a.published,
                    "severity":    a.severity.value if isinstance(a.severity, Enum) else a.severity,
                    "brands":      a.brands,
                }
                for a in alerts
            ],
        }

    def _checksum(self) -> str:
        raw = f"{self.topic_id}{self.subtitle}{self.generated_at}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class AegisAlert:
    """
    Alerta de vulnerabilidad validada e inmutable.

    Se crea en AegisAlertFetcher, se valida en __post_init__ y se persiste
    en AegisDocumentAlert. La inmutabilidad (frozen=True) garantiza que
    el estado no cambia durante el pipeline de persistencia.
    """

    title:       str
    description: str
    url:         str
    source:      AlertSource
    published:   str
    severity:    SeverityLevel | str = ""
    brands:      list[str]          = field(default_factory=list)

    def __post_init__(self) -> None:
        # Normalizar severidad al enum correspondiente
        if isinstance(self.severity, str) and self.severity:
            mapping = {
                "critical": SeverityLevel.CRITICA, "crítica": SeverityLevel.CRITICA,
                "high":     SeverityLevel.ALTA,    "alta":    SeverityLevel.ALTA,
                "medium":   SeverityLevel.MEDIA,   "media":   SeverityLevel.MEDIA,
                "low":      SeverityLevel.BAJA,    "baja":    SeverityLevel.BAJA,
            }
            # frozen=True impide asignación directa; usamos object.__setattr__
            object.__setattr__(self, "severity", mapping.get(self.severity.lower(), SeverityLevel.INFO))

        if not self.url.startswith(("http://", "https://")):
            raise ValueError(f"URL inválida: {self.url}")


# ============================================================================
# DECORADORES DE RESILIENCIA
# ============================================================================

def retry_on_failure(max_retries: int = MAX_RETRIES, exceptions: tuple = (Exception,)):
    """Reintentos con backoff exponencial y jitter."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except exceptions:
                    if attempt == max_retries - 1:
                        raise
                    delay = RETRY_DELAY_BASE ** attempt + random.uniform(0, 0.5)
                    time.sleep(delay)
        return wrapper
    return decorator


def circuit_breaker(threshold: int = 5, timeout: int = 60):
    """Circuit breaker simple para llamadas a servicios externos."""
    failures         = 0
    last_failure_time = None
    lock             = threading.Lock()

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal failures, last_failure_time

            with lock:
                if failures >= threshold:
                    elapsed = time.time() - (last_failure_time or 0)
                    if elapsed < timeout:
                        raise RuntimeError("Circuit breaker abierto")
                    failures = 0

            try:
                result = func(*args, **kwargs)
                with lock:
                    failures = 0
                return result
            except Exception as exc:
                with lock:
                    failures          += 1
                    last_failure_time  = time.time()
                raise exc

        return wrapper
    return decorator


def validate_url(url: str) -> bool:
    """Valida que una URL sea real y no un placeholder."""
    if not url or not isinstance(url, str):
        return False

    invalid_patterns = [
        "example.com", "placeholder", "link.com", "url.com",
        "sitio-web.com", "tu-sitio.com", "domain.com",
        "localhost", "herramienta-ejemplo", "recurso-ejemplo",
        "clickhere.com", "test.com", "sample.org",
    ]
    if any(p in url.lower() for p in invalid_patterns):
        return False

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        domain = parsed.netloc.replace("www.", "")
        if "." not in domain:
            return False
        tld = domain.split(".")[-1]
        return len(tld) >= 2 and tld.isalpha()
    except Exception:
        return False


# ============================================================================
# FETCHER DE ALERTAS
# ============================================================================

class AegisAlertFetcher:
    """
    Fetch concurrente de alertas de vulnerabilidad desde INCIBE y CIRCL.

    Mantiene una caché en memoria por instancia de clase (compartida entre
    instancias del mismo proceso) con TTL de 15 minutos. Las llamadas
    externas se protegen con @retry_on_failure.
    """

    INCIBE_FEED = "https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed"

    _cache:     dict[str, tuple[list[AegisAlert], datetime]] = {}
    _cache_ttl  = timedelta(minutes=15)
    _lock       = threading.Lock()

    def __init__(self, logger: SecOpsLogger, fallback_brands: list[str] | None = None) -> None:
        self.logger           = logger
        self._fallback_brands = fallback_brands or FALLBACK_BRANDS[:]

    # ── Caché ─────────────────────────────────────────────────────────────────

    def _get_cached(self, key: str) -> list[AegisAlert] | None:
        with self._lock:
            entry = self._cache.get(key)
            if entry:
                alerts, timestamp = entry
                if datetime.now() - timestamp < self._cache_ttl:
                    self.logger.debug(f"Cache hit para '{key}'")
                    return alerts
                del self._cache[key]
        return None

    def _set_cached(self, key: str, alerts: list[AegisAlert]) -> None:
        with self._lock:
            self._cache[key] = (alerts, datetime.now())

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_brands(self, brands: list[str]) -> list[str]:
        """Completa la lista de marcas hasta MAX_BRANDS con fallbacks."""
        unique    = list(dict.fromkeys(b.strip() for b in brands if b.strip()))
        if len(unique) >= MAX_BRANDS:
            return unique[:MAX_BRANDS]
        available = [b for b in self._fallback_brands if b not in unique]
        padding   = random.sample(available, min(MAX_BRANDS - len(unique), len(available)))
        return unique + padding

    def _is_recent(self, date_str: str) -> bool:
        if not date_str:
            return True
        try:
            pub_date = datetime.strptime(date_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            cutoff   = datetime.now(timezone.utc) - timedelta(days=365 * MAX_ALERT_AGE_YEARS)
            return pub_date >= cutoff
        except ValueError:
            self.logger.warning(f"Fecha no parseable '{date_str}', asumiendo reciente")
            return True

    # ── Fuentes externas ──────────────────────────────────────────────────────

    @retry_on_failure(max_retries=3)
    def _fetch_incibe(self, brands: list[str], max_per_brand: int) -> list[AegisAlert]:
        """Fetch de alertas desde INCIBE."""
        import urllib.request
        from email.utils import parsedate_to_datetime

        cache_key = f"incibe_{','.join(sorted(brands))}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        req = urllib.request.Request(
            self.INCIBE_FEED,
            headers={"User-Agent": "AegisAlertFetcher/2.0", "Accept": "application/rss+xml"},
        )
        
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()

        root = ET.fromstring(raw)
        channel = root.find("channel")
        if channel is None:
            return []

        alerts = []
        brand_counts = {b: 0 for b in brands}

        for item in channel.findall("item"):
            title = (item.findtext("title") or "").strip()
            desc_raw = html.unescape(item.findtext("description") or "").strip()
            url = (item.findtext("link") or "").strip()
            pub = (item.findtext("pubDate") or "").strip()

            # Parseo de fecha
            pub_iso = pub[:10]
            try:
                pub_iso = parsedate_to_datetime(pub).strftime("%Y-%m-%d")
            except Exception:
                pass

            # Limpieza de descripción
            desc_text = re.sub(r"<[^>]+>", "", desc_raw).strip()
            m = re.search(r"Descripción.*?<p>(.*?)</p>", desc_raw, re.DOTALL)
            summary = html.unescape(m.group(1)) if m else desc_text[:300]

            # Detección de severidad
            haystack = (title + " " + desc_text).lower()
            severity = ""
            for keyword, level in [
                ("crítica", "crítica"), ("critical", "crítica"),
                ("alta", "alta"), ("high", "alta"),
                ("media", "media"), ("medium", "media"),
                ("baja", "baja"), ("low", "baja"),
            ]:
                if keyword in haystack:
                    severity = level
                    break

            # Matching de marcas
            matched = []
            for brand in brands:
                if brand_counts[brand] >= max_per_brand:
                    continue
                if brand.lower() in haystack:
                    matched.append(brand)
                    brand_counts[brand] += 1

            if matched:
                try:
                    alerts.append(AegisAlert(
                        title=title[:200],
                        description=summary[:500],
                        url=url[:512],
                        source=AlertSource.INCIBE,
                        published=pub_iso,
                        severity=severity,
                        brands=matched[:MAX_BRANDS],
                    ))
                except ValueError as e:
                    self.logger.debug(f"Alerta INCIBE inválida descartada: {e}")

        self._set_cached(cache_key, alerts)
        return alerts

    @retry_on_failure(max_retries=3)
    def _fetch_circl(self, brands: list[str], max_per_brand: int) -> list[AegisAlert]:
        """Fetch de alertas desde CIRCL/NVD."""
        import urllib.request

        cache_key = f"circl_{','.join(sorted(brands))}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        alerts = []
        brand_counts = {b: 0 for b in brands}

        for brand in brands:
            if brand_counts[brand] >= max_per_brand:
                continue

            vendor, product = BRAND_SLUGS.get(brand, (brand.lower().replace(" ", ""), ""))
            url = (
                f"https://cve.circl.lu/api/search/{vendor}/{product}"
                if product else 
                f"https://cve.circl.lu/api/search/{vendor}"
            )

            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "AegisAlertFetcher/2.0", "Accept": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
            except Exception as e:
                self.logger.warning(f"CIRCL error para '{brand}': {e}")
                continue

            # FIX: Extraer correctamente la estructura anidada
            results = data.get("results", {}) if isinstance(data, dict) else {}
            cve_list = results.get("cvelistv5", []) if isinstance(results, dict) else []
            
            if not isinstance(cve_list, list):
                continue

            # Ordenar por fecha descendente
            def extract_date(entry):
                try:
                    if isinstance(entry, (list, tuple)) and len(entry) > 1:
                        return entry[1].get("cveMetadata", {}).get("datePublished", "")
                    return ""
                except Exception:
                    return ""

            sorted_entries = sorted(cve_list, key=extract_date, reverse=True)

            for entry in sorted_entries:
                if brand_counts[brand] >= max_per_brand:
                    break

                try:
                    # FIX: entry es una tupla [cve_id, metadata_dict]
                    if not isinstance(entry, (list, tuple)) or len(entry) < 2:
                        continue
                        
                    cve_id = entry[0].upper()
                    meta = entry[1]
                    
                    if not isinstance(meta, dict):
                        continue

                    # Extraer metadata
                    cve_metadata = meta.get("cveMetadata", {})
                    pub_raw = cve_metadata.get("datePublished", "")[:10]
                    
                    if not self._is_recent(pub_raw):
                        continue

                    # Extraer descripción desde containers.cna
                    containers = meta.get("containers", {})
                    cna = containers.get("cna", {})
                    descriptions = cna.get("descriptions", [])
                    
                    desc = next(
                        (d["value"] for d in descriptions if d.get("lang", "").startswith("es")),
                        next((d["value"] for d in descriptions if d.get("lang", "").startswith("en")), "")
                    ) if descriptions else ""

                    # Extraer severidad desde metrics
                    severity = ""
                    metrics = cna.get("metrics", [])
                    for metric in metrics:
                        for key in ("cvssV3_1", "cvssV3_0", "cvssV3"):
                            cvss = metric.get(key, {})
                            if cvss:
                                base = cvss.get("baseSeverity", "").upper()
                                severity = {
                                    "CRITICAL": "crítica", "HIGH": "alta",
                                    "MEDIUM": "media", "LOW": "baja"
                                }.get(base, "")
                                break
                        if severity:
                            break

                    # Extraer producto afectado
                    affected = cna.get("affected", [])
                    product_name = affected[0].get("product", "") if affected else ""
                    title = f"{cve_id}" + (f" — {product_name}" if product_name else "")

                    alerts.append(AegisAlert(
                        title=title[:200],
                        description=(desc[:400] + "…" if len(desc) > 400 else desc) if desc else f"Vulnerabilidad en {brand}",
                        url=f"https://cve.circl.lu/cve/{cve_id}",
                        source=AlertSource.CIRCL,
                        published=pub_raw,
                        severity=severity,
                        brands=[brand],
                    ))
                    brand_counts[brand] += 1

                except Exception as e:
                    self.logger.debug(f"Entrada CIRCL malformada: {e}")
                    continue

            time.sleep(0.2)

        self._set_cached(cache_key, alerts)
        return alerts

    def fetch_alerts(
        self,
        brands:          list[str],
        max_per_brand:   int  = 3,
        use_concurrency: bool = True,
    ) -> list[AegisAlert]:
        """
        Fetch paralelo de INCIBE y CIRCL con fallback y deduplicación.
        Devuelve como máximo 20 alertas ordenadas por fecha descendente.
        """
        if not brands and not self._fallback_brands:
            return []

        resolved = self._resolve_brands(brands)
        results: list[AegisAlert] = []

        if use_concurrency:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {
                    executor.submit(self._fetch_incibe, resolved, max_per_brand): "INCIBE",
                    executor.submit(self._fetch_circl,  resolved, max_per_brand): "CIRCL",
                }
                for future in as_completed(futures):
                    source_name = futures[future]
                    try:
                        results.extend(future.result())
                    except Exception as exc:
                        self.logger.error(f"Error fetch {source_name}: {exc}")
        else:
            for fetch_fn, name in [(self._fetch_incibe, "INCIBE"), (self._fetch_circl, "CIRCL")]:
                try:
                    results.extend(fetch_fn(resolved, max_per_brand))
                except Exception as exc:
                    self.logger.error(f"Error fetch {name}: {exc}")

        # Deduplicación por (título, fecha)
        seen:          set[str]         = set()
        unique_alerts: list[AegisAlert] = []
        for alert in sorted(results, key=lambda a: a.published, reverse=True):
            key = f"{alert.title}_{alert.published}"
            if key not in seen:
                seen.add(key)
                unique_alerts.append(alert)

        return unique_alerts[:20]


# ============================================================================
# WRITER DE CONTENIDO
# ============================================================================

class AegisAIWriter(AIWriter):
    """
    Genera el contenido de una píldora mediante Ollama con few-shot prompting,
    tool calling para búsqueda web y validación estructural del JSON resultante.
    
    Si no se proporcionan host o model, se obtienen de las variables de entorno
    OLLAMA_HOST y OLLAMA_MODEL (o valores por defecto).
    """

    def __init__(
        self,
        host: Optional[str] = None,
        model: Optional[str] = None,
        logger: Optional[SecOpsLogger] = None,
    ) -> None:
        super().__init__(host, model, logger)

    # ── Prompts ───────────────────────────────────────────────────────────────

    def _build_system_prompt(self) -> str:
        return """\
        Eres un redactor senior de concienciación en ciberseguridad con 15 años de experiencia 
        en comunicación corporativa. Tu especialidad es transformar conceptos técnicos complejos 
        en consejos prácticos y accionables para empleados no técnicos.

        REGLAS ABSOLUTAS:
        1. Generas EXCLUSIVAMENTE JSON válido, sin markdown, sin explicaciones previas ni posteriores.
        2. NUNCA inventas URLs. Si no tienes fuentes verificadas, usa array vacío [].
        3. La 'intro' DEBE ser EXTENSA y DETALLADA (mínimo 1200 caracteres, ideal 1500-1800). 
        Desarrolla el contexto empresarial, las consecuencias del riesgo y por qué es relevante para la empresa.
        4. Priorizas la precisión técnica sobre la creatividad cuando haya conflicto.
        5. Adaptas el nivel de detalle al perfil de audiencia especificado.
        6. Mantienes un tono profesional pero cercano, evitando alarmismo innecesario.
        7. Cumples estrictamente el formato JSON solicitado, sin campos adicionales.
        8. El 'subtitle' DEBE ser creativo, atractivo y ORIGINAL. NUNCA repitas literalmente el nombre del tema.
        9. Si el tema es "Phishing", el subtitle podría ser "No muerdas el anzuelo: Protección contra ataques de ingeniería social"."""

    def _build_user_prompt(
        self,
        topic:              Topic | None,
        topic_id:           int,
        reference:          str,
        tweaks:             dict[str, Any],
        verified_resources: str,
    ) -> str:
        company  = tweaks.get("company", "la empresa")
        sector   = tweaks.get("sector", "tecnología")
        audience = tweaks.get("audienceLevel", "mixed")
        brands   = ", ".join(tweaks.get("associatedBrands", []))
        contact  = tweaks.get("mentionContact", "el equipo de seguridad")
        language = tweaks.get("language", "es")
        tone     = tweaks.get("tone", "profesional")
        focus    = tweaks.get("topicFocus", "")

        audience_profile = {
            "technical":     "técnico (administradores de sistemas, desarrolladores)",
            "mixed":         "mixto (técnicos y no técnicos)",
            "non-technical": "no técnico (ventas, RRHH, dirección)",
        }.get(str(audience), "mixto")

        if topic:
            topic_context = (
                f"\nTema seleccionado:\n"
                f"- Título: {topic.title}\n"
                f"- Descripción: {getattr(topic, 'description', 'No disponible')}\n"
                f"- ID: {topic.id}"
            )
        else:
            topic_context = (
                f"\nTema genérico (ID {topic_id} no encontrado en base de datos):\n"
                f"Genera contenido sobre ciberseguridad general para el sector {sector}."
            )

        return f"""\
        {FEW_SHOT_EXAMPLES}

        CONTEXTO DEL DESTINATARIO:
        - Empresa: {company}
        - Sector: {sector}
        - Tecnologías en uso: {brands or "No especificadas"}
        - Perfil de audiencia: {audience_profile}
        - Tono requerido: {tone}
        - Idioma: {language.upper()}
        - Contacto de referencia: {contact}
        {topic_context}
        {f"- Enfoque específico solicitado: {focus}" if focus else ""}

        RECURSOS VERIFICADOS (usar prioritariamente si son relevantes):
        {verified_resources[:2000]}

        INSTRUCCIONES DE GENERACIÓN:

        1. ANÁLISIS PREVIO (interno, antes de generar):
            - Identifica los riesgos más críticos para el sector {sector}
            - Considera las tecnologías {brands or "mencionadas"} si están presentes
            - Adapta la complejidad al perfil de audiencia

        2. ESTRUCTURA REQUERIDA:
            - subtitle: Título atractivo pero profesional (máx 80 caracteres) que NO sea idéntico a "{topic.title}". 
                Debe captar la atención pero reflejar el espíritu del tema de forma original.
            - intro: Extensa, como se indicó anteriormente, con contexto real y relevancia empresarial. Evita generalidades.
            - tips: Array de 5-7 objetos con:
               * headline: Acción específica o riesgo concreto (máx 100 caracteres)
               * body: Explicación práctica con contexto real (mín 100, máx 300 caracteres)
               * links: Máx 2 URLs verificadas por tip, solo si son oficiales
            - closing: Llamada a la acción clara y concreta
            - contactEmail: Email de contacto o string vacío

        3. CONSTRAINTS TÉCNICOS:
            - NO uses markdown dentro de strings (sin **, sin `, sin listas con -)
            - URLs deben ser absolutas y verificables (https://...)
            - Contenido específico, no genérico
            - Incluye al menos un tip relacionado con {brands or "las tecnologías mencionadas"}

        4. VALIDACIÓN FINAL:
            - Verifica que el JSON sea parseable
            - Confirma que no hay campos null (usa "" para strings vacíos)
            - Asegúrate de que tips tenga entre 5 y 7 elementos exactos

        Responde ÚNICAMENTE con el objeto JSON, sin texto adicional."""

    # ── Generación ────────────────────────────────────────────────────────────

    @circuit_breaker(threshold=3, timeout=60)
    def generate(
        self,
        *,
        topic:             Topic | None,
        resolved_topic_id: int,
        topic_title:       str,
        topic_note:        str,
        reference:         str,
        tweaks:            dict[str, Any],
    ) -> AegisContent:
        """
        Genera el contenido de la píldora con tool calling y reintentos.
        Devuelve un AegisContent validado listo para persistir.
        
        Implementa el método abstracto generate() de AIWriter.
        """
        # Enriquecimiento de contexto con búsqueda web
        search_queries = [
            f"{topic_title} ciberseguridad guía oficial {tweaks.get('language', 'es')}",
            f"{topic_title} mejores prácticas empresa {tweaks.get('sector', '')}",
            f"CVE recientes {','.join(tweaks.get('associatedBrands', [])[:2])}",
        ]
        verified_resources = ""
        for query in search_queries:
            try:
                verified_resources += f"\n{self._web_search(query, max_results=3)}"
            except Exception as exc:
                self.logger.warning(f"Búsqueda fallida '{query}': {exc}")

        prompt = self._build_user_prompt(
            topic, resolved_topic_id, reference, tweaks, verified_resources
        )

        tools = [{
            "type": "function",
            "function": {
                "name":        "web_search",
                "description": "Busca información actualizada sobre vulnerabilidades o guías de seguridad",
                "parameters": {
                    "type":       "object",
                    "properties": {"query": {"type": "string", "description": "Términos de búsqueda"}},
                    "required":   ["query"],
                },
            },
        }]

        raw_response = None
        for attempt in range(MAX_RETRIES):
            try:
                messages = [
                    {"role": "system", "content": self._build_system_prompt()},
                    {"role": "user",   "content": prompt},
                ]
                resp = self._client.chat(
                    model    = self.model,
                    messages = messages,
                    tools    = tools,
                    format   = "json",
                    options  = {
                        "num_predict":    4096,
                        "temperature":    0.4 if attempt == 0 else 0.7,
                        "top_p":          0.9,
                        "repeat_penalty": 1.1,
                    },
                )

                # Resolución de tool calls
                if getattr(resp.message, "tool_calls", None):
                    self.logger.info(f"Tool calls: {len(resp.message.tool_calls)}")
                    messages.append({
                        "role":       "assistant",
                        "content":    resp.message.content or "",
                        "tool_calls": resp.message.tool_calls,
                    })
                    for tc in resp.message.tool_calls:
                        query         = tc.function.arguments.get("query", "")
                        search_result = self._web_search(query)
                        messages.append({"role": "tool", "content": search_result})

                    resp = self._client.chat(
                        model    = self.model,
                        messages = messages,
                        format   = "json",
                        options  = {"num_predict": 4096, "temperature": 0.5},
                    )

                raw_response = resp.message.content.strip()
                if raw_response:
                    break

            except Exception as exc:
                self.logger.error(f"Intento {attempt + 1} fallido: {exc}")
                if attempt == MAX_RETRIES - 1:
                    raise RuntimeError(f"Fallo tras {MAX_RETRIES} intentos: {exc}")
                time.sleep(RETRY_DELAY_BASE ** attempt)

        data = self._parse_response(raw_response)

        raw_subtitle = str(data.get("subtitle", "")).strip()
        
        if not raw_subtitle or raw_subtitle.lower() == topic_title.lower():
            self.logger.warning(
                f"IA generó subtitle idéntico al tema '{topic_title}' o vacío. "
                f"Forzando generación creativa..."
            )
            # Transformación automática para evitar duplicados
            prefixes = [
                "Protección empresarial contra",
                "Guía práctica de",
                "Cómo prevenir",
                "Seguridad avanzada en",
                "Manual de supervivencia ante"
            ]
            import random
            prefix = random.choice(prefixes)
            raw_subtitle = f"{prefix} {topic_title}"
        
        # También validar que no sea demasiado genérico
        if len(raw_subtitle) < 10:
            raw_subtitle = f"Píldora de concienciación: {topic_title}"

        # Construcción y validación de tips
        tips: list[AegisTipData] = []
        for i, tip_data in enumerate(data.get("tips", [])):
            if not isinstance(tip_data, dict):
                continue
            valid_links = [
                {"text": str(lk["text"])[:50], "url": str(lk["url"])[:512]}
                for lk in (tip_data.get("links") or [])
                if isinstance(lk, dict) and validate_url(lk.get("url")) and lk.get("text")
            ]
            try:
                tips.append(AegisTipData(
                    headline = str(tip_data.get("headline", f"Consejo {i + 1}"))[:150],
                    body     = str(tip_data.get("body", ""))[:1000],
                    links    = valid_links[:2],
                ))
            except ValueError as exc:
                self.logger.warning(f"Tip {i + 1} descartado: {exc}")

        if len(tips) < 3:
            raise ValueError(f"Insuficientes tips válidos: {len(tips)}")

        return AegisContent(
            topic_id      = resolved_topic_id,
            topic_title   = topic_title,
            language      = tweaks.get("language", "es"),
            company       = tweaks.get("company", "la empresa"),
            generated_at  = datetime.now(timezone.utc).isoformat(),
            topic_note    = topic_note,
            subtitle      = raw_subtitle[:100],  # Título creativo garantizado
            intro         = str(data.get("intro", ""))[:2500],
            tips          = tips,
            closing       = str(data.get("closing", ""))[:500],
            contact_email = str(data.get("contactEmail", ""))[:100],
        )

    def _parse_response(self, raw: str) -> dict:
        """Parseo robusto con múltiples estrategias de recuperación."""
        if not raw:
            raise ValueError("Respuesta vacía del modelo")

        # Intento directo
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # Extracción de bloque JSON con patrones alternativos
        for pattern in [r'\{[\s\S]*\}', r'```(?:json)?\s*([\s\S]*?)\s*```', r'JSON:\s*(\{[\s\S]*\})']:
            match = re.search(pattern, raw)
            if match:
                try:
                    return json.loads(match.group(1) if match.groups() else match.group())
                except json.JSONDecodeError:
                    continue

        # Limpieza agresiva
        cleaned = re.sub(r'^[^{]*', '', raw)
        cleaned = re.sub(r'[^}]*$', '', cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as exc:
            self.logger.error(f"No se pudo parsear respuesta: {raw[:500]}")
            raise ValueError(f"JSON inválido tras limpieza: {exc}")