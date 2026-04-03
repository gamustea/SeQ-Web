import os
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any

import ollama

from ddgs import DDGS

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    Image,
    PageBreak,
    CondPageBreak,
)

from src.misc.configread import ConfigReader, DirectoryType
from src.misc.logging import SecOpsLogger
from src.core.model import NmapScan, NiktoScan, Scan, Host, Topic


@dataclass
class AegisTipData:
    """Consejo individual estructurado."""
    headline: str
    body: str
    links: list[dict] = field(default_factory=list)

@dataclass
class AegisContent:
    """Resultado estructurado de generate_pill."""
    topic_id: int
    topic_title: str
    language: str
    company: str
    generated_at: str
    topic_note: str
    subtitle: str = ""
    intro: str = ""
    tips: list[AegisTipData] = field(default_factory=list)
    closing: str = ""
    contact_email: str = ""

    def to_json_dict(self, document_id: int, alerts: list) -> dict:
        """Serializa el contenido completo a un dict exportable como .json."""
        return {
            "version": "1.0",
            "metadata": {
                "documentId": document_id,
                "topicId": self.topic_id,
                "topicTitle": self.topic_title,
                "language": self.language,
                "company": self.company,
                "generatedAt": self.generated_at,
            },
            "pill": {
                "subtitle": self.subtitle,
                "intro": self.intro,
                "tips": [
                    {
                        "position": i + 1,
                        "headline": t.headline,
                        "body": t.body,
                        "links": t.links,
                    }
                    for i, t in enumerate(self.tips)
                ],
                "closing": self.closing,
                "contactEmail": self.contact_email,
            },
            "alerts": [
                {
                    "position": i + 1,
                    "source": a.source,
                    "sourceLabel": "INCIBE-CERT" if a.source == "incibe" else "NVD/CVE",
                    "title": a.title,
                    "published": a.published,
                    "severity": a.severity,
                    "affectedBrands": a.brands,
                    "description": a.description,
                    "url": a.url,
                }
                for i, a in enumerate(alerts)
            ],
        }


@dataclass
class AegisAlert:
    """Aviso de vulnerabilidad (INCIBE / CIRCL)."""
    title: str
    description: str
    url: str
    source: str     # "incibe" o "circl"
    published: str  # ISO-8601 o fecha en texto
    severity: str   # "crítica"/"alta"/"media"/"baja" o ""
    brands: list[str] = field(default_factory=list)


class AegisAlertFetcher:
    """Responsable de obtener y formatear vulnerabilidades desde Internet."""

    INCIBE_FEED = "https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed"
    MAX_BRANDS = 5
    MAX_ALERT_AGE_YEARS = 5

    def __init__(self, logger: SecOpsLogger, fallback_brands: list[str]):
        """
        fallback_brands: marcas de relleno tipo ["Microsoft", "Google", ...]
        """
        self.logger = logger
        self._fallback_brands = fallback_brands

    # ---------- Helpers genéricos -------------------------------------

    def _resolve_brands(self, brands: list[str]) -> list[str]:
        """Rellena hasta MAX_BRANDS usando fallback_brands, sin duplicados."""
        unique = [b.strip() for b in brands if b.strip()]
        unique = list(dict.fromkeys(unique))  # conserva orden
        if len(unique) >= self.MAX_BRANDS:
            return unique[: self.MAX_BRANDS]

        available = [b for b in self._fallback_brands if b not in unique]
        needed = self.MAX_BRANDS - len(unique)
        padding = random.sample(available, min(needed, len(available)))
        resolved = unique + padding
        self.logger.info(
            f"AegisAlertFetcher: marcas cliente={unique} relleno={padding}"
        )
        return resolved

    def _is_recent(self, date_str: str) -> bool:
        """Devuelve True si la fecha está dentro de la ventana de MAX_ALERT_AGE_YEARS."""
        if not date_str:
            return True
        try:
            clean = date_str[:10]
            pubdate = datetime.strptime(clean, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            now = datetime.now(timezone.utc)
            cutoff = now.replace(year=now.year - self.MAX_ALERT_AGE_YEARS)
            return pubdate >= cutoff
        except ValueError:
            self.logger.warning(
                f"AegisAlertFetcher: fecha no parseable '{date_str}', se considera reciente"
            )
            return True

    def _parse_incibe_feed(
        self,
        brands: list[str],
        max_per_brand: int,
        timeout: int,
    ) -> list[AegisAlert]:
        import xml.etree.ElementTree as ET
        import urllib.request
        import html
        import re

        def strip_html(text: str) -> str:
            return re.sub(r"<[^>]+>", "", text).strip()

        alerts: list[AegisAlert] = []
        brand_counts: dict[str, int] = {}

        req = urllib.request.Request(
            self.INCIBE_FEED,
            headers={"User-Agent": "AegisAlertFetcher/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()

        root = ET.fromstring(raw)
        channel = root.find("channel")
        if channel is None:
            return []

        for item in channel.findall("item"):
            title = (item.findtext("title") or "").strip()
            desc_raw = html.unescape(item.findtext("description") or "").strip()
            url = (item.findtext("link") or "").strip()
            pub = (item.findtext("pubDate") or "").strip()

            # Normalizar fecha (similar a tu código actual)
            pub_iso = pub[:10]
            try:
                from email.utils import parsedate_to_datetime

                pub_iso = parsedate_to_datetime(pub).strftime("%Y-%m-%d")
            except Exception:
                pass

            # Texto plano para matching y resumen
            desc_text = strip_html(desc_raw)
            m = re.search(r"Descripción.*?<p>(.*?)</p>", desc_raw, re.DOTALL)
            summary = strip_html(m.group(1)) if m else desc_text[:300]

            # Severidad simple por palabras clave
            severity = ""
            haystack = (title + " " + desc_text).lower()
            for sev_str, sev_label in [
                ("crítica", "crítica"),
                ("critical", "crítica"),
                ("alta", "alta"),
                ("high", "alta"),
                ("media", "media"),
                ("medium", "media"),
                ("baja", "baja"),
                ("low", "baja"),
            ]:
                if sev_str in haystack:
                    severity = sev_label
                    break

            # Filtrado por marcas
            haystack_brands = haystack
            matched: list[str] = []
            for brand in brands:
                count = brand_counts.get(brand, 0)
                if count >= max_per_brand:
                    continue
                if brand.lower() in haystack_brands:
                    matched.append(brand)
                    brand_counts[brand] = count + 1

            if matched:
                alerts.append(
                    AegisAlert(
                        title=title,
                        description=summary,
                        url=url,
                        source="incibe",
                        published=pub_iso,
                        severity=severity,
                        brands=matched,
                    )
                )

        return alerts

    def _parse_circl_api(
        self,
        brands: list[str],
        max_per_brand: int,
        timeout: int,
    ) -> list[AegisAlert]:
        import urllib.request
        import json

        alerts: list[AegisAlert] = []
        brand_counts: dict[str, int] = {}

        BRAND_SLUGS: dict[str, tuple[str, str]] = {
            "Microsoft": ("microsoft", "windows"),
            "Cisco": ("cisco", "ios"),
            "Apple": ("apple", "macos"),
            "Google": ("google", "chrome"),
            "Adobe": ("adobe", "acrobat"),
            "Android": ("google", "android"),
            "HPE": ("hp", "hpe"),
            "SonicWall": ("sonicwall", "sonicos"),
            "Konica": ("konicaminolta", "printer"),
            "Juniper": ("juniper", "junos"),
            "VMware": ("vmware", "esxi"),
            "Palo Alto": ("paloaltonetworks", "pan-os"),
            "SAP": ("sap", "netweaver"),
            "Oracle": ("oracle", "database"),
            "Mozilla": ("mozilla", "firefox"),
            "Linux": ("linux", "kernel"),
            "Fortinet": ("fortinet", "fortios"),
        }

        for brand in brands:
            if brand_counts.get(brand, 0) >= max_per_brand:
                continue

            vendor, product = BRAND_SLUGS.get(
                brand, (brand.lower().replace(" ", ""), "")
            )
            url = (
                f"https://cve.circl.lu/api/search/{vendor}/{product}"
                if product
                else f"https://cve.circl.lu/api/search/{vendor}"
            )

            req = urllib.request.Request(
                url,
                headers={"User-Agent": "AegisAlertFetcher/1.0"},
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read())
            except Exception as e:
                self.logger.warning(
                    f"AegisAlertFetcher CIRCL: error para '{brand}': {e}"
                )
                continue

            results = data.get("results", {})
            cve_list = results.get("cvelistv5", [])

            def pub_date(entry):
                try:
                    return entry[1]["cveMetadata"].get("datePublished", "")
                except Exception:
                    return ""

            cve_sorted = sorted(cve_list, key=pub_date, reverse=True)

            for entry in cve_sorted:
                if brand_counts.get(brand, 0) >= max_per_brand:
                    break
                try:
                    cve_id = entry[0].upper()
                    meta = entry[1].get("cveMetadata", {})
                    pub_raw = meta.get("datePublished", "")[:10]
                    if not self._is_recent(pub_raw):
                        continue

                    cna = entry[1].get("containers", {}).get("cna", {})
                    descriptions = cna.get("descriptions", [])
                    desc_en = next(
                        (
                            d["value"]
                            for d in descriptions
                            if d.get("lang", "").startswith("en")
                        ),
                        "",
                    )
                    desc_es = next(
                        (
                            d["value"]
                            for d in descriptions
                            if d.get("lang", "").startswith("es")
                        ),
                        "",
                    )
                    desc = desc_es or desc_en

                    severity = ""
                    metrics = cna.get("metrics", [])
                    for metric in metrics:
                        for key in ("cvssV3_1", "cvssV3_0", "cvssV3"):
                            cvss = metric.get(key, {})
                            if cvss:
                                base = cvss.get("baseSeverity", "").upper()
                                severity = {
                                    "CRITICAL": "crítica",
                                    "HIGH": "alta",
                                    "MEDIUM": "media",
                                    "LOW": "baja",
                                }.get(base, base.lower())
                                break
                        if severity:
                            break

                    affected = cna.get("affected", [])
                    product_name = (
                        affected[0].get("product", "") if affected else ""
                    )
                    title = f"{cve_id}" + (
                        f" — {product_name}" if product_name else ""
                    )

                    alerts.append(
                        AegisAlert(
                            title=title,
                            description=desc[:400] + ("…" if len(desc) > 400 else ""),
                            url=f"https://cve.circl.lu/cve/{cve_id}",
                            source="circl",
                            published=pub_raw,
                            severity=severity,
                            brands=[brand],
                        )
                    )
                    brand_counts[brand] = brand_counts.get(brand, 0) + 1

                except Exception as e:
                    self.logger.debug(
                        f"AegisAlertFetcher CIRCL: entrada malformada para '{brand}': {e}"
                    )
                    continue

        return alerts

    def fetch_alerts(
        self,
        brands: list[str],
        max_per_brand: int = 3,
        timeout: int = 10,
    ) -> list[AegisAlert]:
        """Resuelve marcas, consulta INCIBE + CIRCL, filtra por antigüedad."""
        if not brands and not self._fallback_brands:
            return []

        resolved_brands = self._resolve_brands(brands)
        alerts: list[AegisAlert] = []

        # INCIBE
        incibe_alerts: list[AegisAlert] = []
        try:
            incibe_alerts = self._parse_incibe_feed(
                resolved_brands, max_per_brand, timeout
            )
        except Exception as e:
            self.logger.warning(f"AegisAlertFetcher: error feed INCIBE: {e}")

        incibe_alerts = [
            a for a in incibe_alerts if self._is_recent(a.published)
        ]

        # Detectar marcas del cliente sin resultados en INCIBE → sustituir en NVD
        client_brands = list(
            dict.fromkeys(b.strip() for b in brands if b.strip())
        )
        matched_brands = {b for a in incibe_alerts for b in a.brands}
        missing = [b for b in client_brands if b not in matched_brands]

        if missing:
            already_used = set(resolved_brands)
            candidates = [
                b for b in self._fallback_brands if b not in already_used
            ]
            substitutes = random.sample(
                candidates, min(len(missing), len(candidates))
            )
            self.logger.info(
                f"AegisAlertFetcher: marcas sin resultados en INCIBE {missing} → "
                f"sustituyendo por {substitutes}"
            )
            resolved_brands = [
                substitutes.pop(0) if b in missing and substitutes else b
                for b in resolved_brands
            ]

        alerts.extend(incibe_alerts)

        # NVD / CIRCL
        nvd_alerts: list[AegisAlert] = []
        try:
            nvd_alerts = self._parse_circl_api(
                resolved_brands, max_per_brand, timeout
            )
        except Exception as e:
            self.logger.warning(
                f"AegisAlertFetcher: error NVD/CIRCL API: {e}"
            )

        nvd_alerts = [a for a in nvd_alerts if self._is_recent(a.published)]
        alerts.extend(nvd_alerts)

        return alerts

    @staticmethod
    def alerts_to_markdown(alerts: list[AegisAlert]) -> str:
        """Serializa las alertas como sección Markdown."""
        if not alerts:
            return ""

        lines = ["# Vulnerabilidades y avisos de seguridad:\n"]
        for a in alerts:
            source_label = "INCIBE-CERT" if a.source == "incibe" else "NVD/CVE"
            sev_tag = f" ⚠️ **{a.severity.upper()}**" if a.severity else ""
            lines.append(f"### {a.title}{sev_tag}")
            lines.append(
                f"- **Fuente:** {source_label} | **Publicado:** {a.published}"
            )
            if a.brands:
                lines.append(
                    f"- **Tecnologías afectadas:** {', '.join(a.brands)}"
                )
            lines.append(f"- **Descripción:** {a.description}")
            lines.append(f"- **Enlace:** [{a.title}]({a.url})\n")

        return "\n".join(lines)


class AegisAIWriter:
    """Responsable solo de generar contenido usando IA (Ollama)."""

    def __init__(self, host: str, model: str, logger: SecOpsLogger):
        self.host = host
        self.model = model
        self.logger = logger

    def _web_search(self, query: str, max_results: int = 5) -> str:
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=max_results))
            if not results:
                return f"No se encontraron resultados para: {query}"

            lines = [f"Resultados para '{query}':\n"]
            for i, r in enumerate(results, 1):
                lines.append(f"{i}. {r.get('title', '')}")
                lines.append(f"   {r.get('body', '')}")
                lines.append(f"   Fuente: {r.get('href', '')}\n")
            return "\n".join(lines)
        except ImportError:
            self.logger.error(
                "duckduckgo-search no instalado (pip install duckduckgo-search)"
            )
            return "Búsqueda no disponible: dependencia no instalada."
        except Exception as e:
            self.logger.warning(f"Búsqueda fallida '{query}': {e}")
            return f"No se pudo completar la búsqueda: {e}"

    def _build_prompt(
        self,
        topic: Optional[Topic],
        topic_id: int,
        reference: str,
        tweaks: dict[str, Any],
        verified_resources: str = "",
    ) -> str:
        company = tweaks.get("company", "la empresa destinataria")
        sector = tweaks.get("sector", "")
        audience = tweaks.get("audienceLevel", "mixed")
        brands = ", ".join(tweaks.get("associatedBrands", []))
        contact = tweaks.get("mentionContact", "")
        language = tweaks.get("language", "es")
        tone = tweaks.get("tone", "formal")
        focus = tweaks.get("topicFocus", "")

        audience_label = {
            "technical": "técnico (conocimiento avanzado de seguridad)",
            "mixed": "mixto (empleados técnicos y no técnicos)",
            "non-technical": "no técnico (empleados de negocio sin perfil IT)",
        }.get(audience, audience)

        context_parts = [f"- Empresa destinataria: {company}"]
        if sector:   context_parts.append(f"- Sector de actividad: {sector}")
        if brands:   context_parts.append(f"- Tecnologías y herramientas en uso: {brands}")
        if focus:    context_parts.append(f"- Enfoque específico solicitado: {focus}")
        if contact:  context_parts.append(f"- Contacto de referencia para el lector: {contact}")
        context_parts += [
            f"- Perfil de la audiencia: {audience_label}",
            f"- Tono: {tone}",
            f"- Idioma de salida: {language.upper()}",
        ]
        context_block = "\n".join(context_parts)

        if topic:
            topic_block = f"- Título: {topic.title}"
            if getattr(topic, "description", None):
                topic_block += f"\n- Descripción: {topic.description}"
        else:
            topic_block = (
                f"- ID de tema: {topic_id} (no encontrado en BD).\n"
                "- Elige un tema de ciberseguridad relevante para empleados de empresa."
            )

        # Incluir recursos verificados si existen
        resources_block = ""
        if verified_resources and "No se encontraron resultados" not in verified_resources:
            resources_block = (
                "\n\nRECURSOS VERIFICADOS DISPONIBLES (usa estos si son relevantes):\n"
                "━━━\n"
                + verified_resources[:1500] +  # Limitar para no saturar el contexto
                "\n━━━\n"
            )

        role_block = (
            f"Eres un redactor senior especializado en comunicación de ciberseguridad corporativa. "
            f"Tu trabajo es producir contenido de concienciación en {language.upper()} "
            f"para empleados de empresas. Escribes de forma clara, directa y práctica. "
            f"Das información amplia sobre lo que estás hablando, aprotando contenido extenso y de calidad. "
            f"REGLA ABSOLUTA: responde SOLO con el JSON solicitado, sin nada más."
        )

        json_instruction = """\
        Responde ÚNICAMENTE con un objeto JSON válido, sin texto adicional, sin bloques de código, sin explicaciones.

        SCHEMA OBLIGATORIO:
        {
        "subtitle": "string - título atractivo de la píldora",
        "intro": "string - párrafo introductorio de 3-5 frases",
        "tips": [
            {
            "headline": "string - acción o riesgo en una frase corta",
            "body": "string - desarrollo en 2-3 frases",
            "links": [{"text": "string", "url": "string"}]
            }
        ],
        "closing": "string - frase de cierre con llamada a la acción",
        "contactEmail": "string - email de contacto o vacío"
        }

        REGLAS CRÍTICAS SOBRE ENLACES:
        1. El campo "links" es OPCIONAL. Si no tienes URLs reales y verificadas, usa un array vacío: []
        2. NUNCA inventes URLs, uses "example.com", "placeholder.com" o dominios genéricos.
        3. SOLO incluye enlaces si son URLs reales que empiecen con https:// y provengan de fuentes oficiales (gov, org, empresas reconocidas).
        4. Si no estás 100% seguro de que una URL es real y accesible, NO la incluyas.
        5. Prioriza los recursos verificados proporcionados arriba si son relevantes para el tip.
        6. tips: entre 5 y 7 elementos.
        7. Todos los valores en el idioma indicado.
        8. NO uses Markdown dentro de los valores (sin **, sin #, sin -).
        """

        prompt_parts = [role_block]
        if reference:
            prompt_parts.append(
                "Ejemplos de píldoras reales de este cliente (imita su estilo):\n\n"
                "━━━ REFERENCIAS ━━━\n"
                + reference +
                "\n━━━ FIN ━━━"
            )
        
        if resources_block:
            prompt_parts.append(resources_block)
            
        prompt_parts += [
            f"CONTEXTO DEL CLIENTE:\n{context_block}",
            f"TEMA A DESARROLLAR:\n{topic_block}",
            json_instruction,
        ]
        return "\n\n".join(prompt_parts)
    
    def _call_ollama(self, prompt: str) -> str:
        """Llama a Ollama con tool calling (misma lógica que tu _call_ollama)."""
        client = ollama.Client(host=self.host)
        system = (
            "Eres un redactor senior especializado en ciberseguridad corporativa. "
            "Produces documentos finales en Markdown, listos para distribuir. "
            "Nunca describes lo que vas a escribir: escribes directamente el documento. "
            "Si necesitas contexto actualizado (noticias recientes, vulnerabilidades activas), "
            "usa la herramienta web_search antes de redactar."
        )

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "web_search",
                    "description": (
                        "Busca información actualizada en internet sobre ciberseguridad. "
                        "Úsala para encontrar noticias recientes, vulnerabilidades activas o "
                        "incidentes relevantes que enriquezcan el contenido de la píldora."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": (
                                    "Consulta concisa en español o inglés orientada a obtener "
                                    "noticias o información técnica reciente."
                                ),
                            }
                        },
                        "required": ["query"],
                    },
                },
            }
        ]

        messages: list[dict] = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        try:
            resp = client.chat(
                model=self.model,
                messages=messages,
                tools=tools,
                format="json",
                options={"num_predict": 4096, "temperature": 0.7},
            )
        except ollama.ResponseError as e:
            self.logger.error(f"Ollama ResponseError (1ª llamada): {e}")
            raise RuntimeError(f"Error del modelo: {e}") from e
        except Exception as e:
            self.logger.error(f"Error conectando Ollama en {self.host}: {e}")
            raise RuntimeError(f"No se pudo conectar con Ollama en {self.host}") from e

        tool_calls = getattr(resp.message, "tool_calls", None) or []
        if tool_calls:
            self.logger.info(
                f"AegisAIWriter: {len(tool_calls)} búsqueda(s) solicitadas por el modelo"
            )
            messages.append(
                {
                    "role": "assistant",
                    "content": getattr(resp.message, "content", "") or "",
                    "tool_calls": tool_calls,
                }
            )
            for tc in tool_calls:
                query = tc.function.arguments.get("query", "")
                result = self._web_search(query)
                self.logger.info(f"AegisAIWriter: búsqueda ejecutada → '{query}'")
                messages.append({"role": "tool", "content": result})

            try:
                resp = client.chat(
                    model=self.model,
                    messages=messages,
                    options={"num_predict": 4096, "temperature": 0.7},
                )
            except ollama.ResponseError as e:
                self.logger.error(f"Ollama ResponseError (2ª llamada): {e}")
                raise RuntimeError(f"Error del modelo: {e}") from e
            except Exception as e:
                self.logger.error(f"Error conectando Ollama en {self.host}: {e}")
                raise RuntimeError(f"No se pudo conectar con Ollama en {self.host}") from e
        else:
            self.logger.info("AegisAIWriter: el modelo no solicitó búsquedas web")

        content = (getattr(resp.message, "content", None) or "").strip()
        if not content:
            raise RuntimeError("El modelo devolvió una respuesta vacía")
        return content

    def _filter_valid_links(self, links: list[dict]) -> list[dict]:
        """
        Filtra links para eliminar placeholders y URLs inválidas.
        Solo permite URLs reales con dominios válidos.
        """
        if not links:
            return []
        
        # Patrones que indican URLs inventadas/placeholders
        invalid_patterns = [
            "example.com", "placeholder", "link.com", "url.com", 
            "sitio-web.com", "tu-sitio.com", "domain.com",
            "http://localhost", "https://localhost",
            "herramienta-ejemplo", "recurso-ejemplo"
        ]
        
        valid_links = []
        for link in links:
            if not isinstance(link, dict):
                continue
            url = link.get("url", "").lower().strip()
            text = link.get("text", "").strip()
            
            # Debe tener URL y texto
            if not url or not text:
                continue
            
            # Debe empezar con http/https
            if not url.startswith(("http://", "https://")):
                continue
            
            # Verificar que no sea placeholder
            if any(pattern in url for pattern in invalid_patterns):
                self.logger.debug(f"Filtrando URL placeholder: {url}")
                continue
            
            # Verificar que el dominio sea válido (tiene al menos un punto y TLD)
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc.replace("www.", "")
                if "." not in domain or len(domain.split(".")[-1]) < 2:
                    continue
            except Exception:
                continue
            
            valid_links.append({"text": text, "url": link["url"]})
        
        return valid_links

    def generate_pill(
        self,
        *,
        topic: Optional[Topic],
        resolved_topic_id: int,
        topic_title: str,
        topic_note: str,
        reference: str,
        tweaks: dict[str, Any],
    ) -> AegisContent:
        # Buscar recursos reales sobre el tema antes de generar
        self.logger.info(f"Buscando recursos verificados para: {topic_title}")
        search_query = f"{topic_title} ciberseguridad guía oficial consejos"
        verified_resources = self._web_search(search_query, max_results=5)
        
        prompt = self._build_prompt(
            topic, resolved_topic_id, reference, tweaks, verified_resources
        )
        self.logger.info(
            f"AegisAIWriter generando píldora | topic_id={resolved_topic_id} "
            f"| modelo={self.model}"
        )
        
        raw_response = self._call_ollama(prompt)
        
        # Parsear JSON...
        try:
            data = json.loads(raw_response)
        except json.JSONDecodeError:
            import re
            match = re.search(r'\{.*\}', raw_response, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group())
                except json.JSONDecodeError as e:
                    raise ValueError(f"Respuesta no es JSON válido: {raw_response[:200]}") from e
            else:
                raise ValueError(f"Respuesta no contiene JSON: {raw_response[:200]}")

        # Validar campos requeridos
        required = {"subtitle", "intro", "tips", "closing"}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"JSON incompleto. Faltan: {missing}")

        # Convertir tips y filtrar links inválidos/placeholders
        tips = []
        for i, tip_data in enumerate(data.get("tips", [])):
            if not isinstance(tip_data, dict):
                continue
            
            raw_links = tip_data.get("links", []) or []
            # Filtrar solo links con URLs reales (no placeholders)
            valid_links = self._filter_valid_links(raw_links)
            
            tips.append(AegisTipData(
                headline=tip_data.get("headline", f"Consejo {i+1}"),
                body=tip_data.get("body", ""),
                links=valid_links
            ))

        return AegisContent(
            topic_id=resolved_topic_id,
            topic_title=topic_title,
            language=tweaks.get("language", "es"),
            company=tweaks.get("company", "la empresa destinataria"),
            generated_at=datetime.now(timezone.utc).isoformat(),
            topic_note=topic_note,
            subtitle=data.get("subtitle", ""),
            intro=data.get("intro", ""),
            tips=tips,
            closing=data.get("closing", ""),
            contact_email=data.get("contactEmail", ""),
        )
