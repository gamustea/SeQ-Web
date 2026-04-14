"""
aegis_exporters.py
──────────────────
Exportadores de documentos Aegis a Markdown y JSON.

Clases públicas:
    ExportData      — DTO de entrada para todos los exportadores
    ExportResult    — resultado inmutable de una exportación
    MarkdownExporter
    JsonExporter
    get_exporter_for_format  — factory por formato

El protocolo AegisData se conserva para compatibilidad con código externo
que construya objetos ad-hoc, pero ExportData es la forma canónica de
alimentar los exportadores desde managers y endpoints.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from src.misc import SecOpsLogger
from src.core.exceptions import (
    ExporterError,
    ExporterFormatError,
    ExporterConfigurationError,
)

_logger = SecOpsLogger(name="AegisExporters").get_logger()


# ============================================================================
# ENUMERACIONES Y TIPOS DE DATOS
# ============================================================================

class ExportFormat(str, Enum):
    JSON     = "json"
    MARKDOWN = "md"
    PDF      = "pdf"
    HTML     = "html"
    DOCX     = "docx"


@dataclass(frozen=True)
class ExportResult:
    """Resultado inmutable de una operación de exportación."""

    content:      bytes | str
    filename:     str
    mimetype:     str
    format:       ExportFormat
    size_bytes:   int
    generated_at: datetime

    def to_response_dict(self) -> dict[str, Any]:
        """Metadatos serializables para respuestas de API."""
        return {
            "filename":    self.filename,
            "format":      self.format.value,
            "mimetype":    self.mimetype,
            "sizeBytes":   self.size_bytes,
            "generatedAt": self.generated_at.isoformat(),
        }


@dataclass
class ExportData:
    """
    DTO canónico de entrada para los exportadores.
    """
    topic_id:      int   = 0
    topic_title:   str   = ""
    subtitle:      str   = ""
    company:       str   = "Empresa"
    language:      str   = "es"
    generated_at:  str   = ""
    subtitle:      str   = ""
    intro:         str   = ""
    tips:          list[dict] = field(default_factory=list)
    closing:       str   = ""
    contact_email: str   = ""
    alerts:        list[dict] = field(default_factory=list)
    document_id:   int   = 0

    @classmethod
    def from_document_dict(cls, doc: dict, doc_id: int | None = None) -> "ExportData":
        """
        Construye un ExportData a partir del dict devuelto por
        AegisManager.get_document(). Centraliza el mapeo de claves
        para que endpoints y managers no lo repitan.
        """
        pill = doc.get("pill") or {}
        return cls(
            topic_id      = doc.get("topicId", 0),
            topic_title   = doc.get("title", "Sin título"),
            company       = pill.get("company") or doc.get("company", "Empresa"),
            language      = pill.get("language", "es"),
            generated_at  = doc.get("generatedAt", ""),
            subtitle      = pill.get("subtitle", ""),
            intro         = pill.get("intro", ""),
            tips          = pill.get("tips", []),
            closing       = pill.get("closing", ""),
            contact_email = pill.get("contactEmail", ""),
            alerts        = doc.get("alerts", []),
            document_id   = doc_id if doc_id is not None else doc.get("id", 0),
        )


# ============================================================================
# BASE Y CONFIGURACIÓN
# ============================================================================

@dataclass
class MarkdownTemplate:
    """Configuración de plantilla para el exportador Markdown."""

    include_toc:            bool = False
    include_metadata_block: bool = True
    alert_section_title:    str  = "## 🔴 Alertas de Seguridad Recientes"
    tip_emoji:              str  = "💡"
    severity_emojis:        dict[str, str] = field(default_factory=lambda: {
        "crítica":    "🔴",
        "alta":       "🟠",
        "media":      "🟡",
        "baja":       "🟢",
        "informativa": "🔵",
    })


class AegisExporter(ABC):
    """
    Clase base para exportadores.

    Implementa el patrón Strategy: cada subclase define su formato de salida
    sin cambiar la interfaz que usan managers y endpoints.
    """

    format:             ExportFormat
    extension:          str
    mimetype:           str
    supports_streaming: bool = False

    def __init__(self) -> None:
        self._validate_configuration()

    def _validate_configuration(self) -> None:
        required = ["format", "extension", "mimetype"]
        missing = [a for a in required if not getattr(self, a, None)]
        if missing:
            raise ExporterConfigurationError(missing)

    @abstractmethod
    def export(self, data: ExportData, output_path: Path | None = None) -> ExportResult:
        raise NotImplementedError("Subclass must implement export method")

    def generate_filename(self, data: ExportData, suffix: str = "") -> str:
        timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name   = "".join(c for c in data.company if c.isalnum() or c in "-_").lower()[:20]
        base        = f"aegis_{safe_name}_{data.topic_id}_{timestamp}"
        if suffix:
            base += f"_{suffix}"
        return f"{base}.{self.extension}"

    def _sanitize(self, text: str | None, max_length: int = 10_000) -> str:
        if not text:
            return ""
        text = str(text).strip()
        if len(text) > max_length:
            text = text[:max_length] + "\n\n[Contenido truncado por longitud máxima]"
        return text

    def _format_datetime(self, iso_string: str) -> str:
        try:
            dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
            return dt.strftime("%d de %B de %Y, %H:%M")
        except Exception:
            return iso_string


# ============================================================================
# EXPORTADOR MARKDOWN
# ============================================================================

class MarkdownExporter(AegisExporter):

    format             = ExportFormat.MARKDOWN
    extension          = "md"
    mimetype           = "text/markdown; charset=utf-8"
    supports_streaming = True

    def __init__(self, template: MarkdownTemplate | None = None) -> None:
        super().__init__()
        self.template = template or MarkdownTemplate()

    # ── Punto de entrada ──────────────────────────────────────────────────────

    def export(self, data: ExportData, output_path: Path | None = None) -> ExportResult:
        content       = self._generate_content(data)
        content_bytes = content.encode("utf-8")
        filename      = output_path.with_suffix(f".{self.extension}").name if output_path else self.generate_filename(data)

        if output_path:
            output_path.with_suffix(f".{self.extension}").write_text(content, encoding="utf-8")

        return ExportResult(
            content      = content_bytes,
            filename     = filename,
            mimetype     = self.mimetype,
            format       = self.format,
            size_bytes   = len(content_bytes),
            generated_at = datetime.now(),
        )

    # ── Generación por secciones ──────────────────────────────────────────────

    def _generate_content(self, data: ExportData) -> str:
        sections: list[list[str]] = []

        if self.template.include_metadata_block:
            sections.append(self._frontmatter(data))

        sections.append(self._header(data))

        if data.intro:
            sections.append(self._intro(data))

        sections.append(self._tips(data))

        if data.alerts:
            sections.append(self._alerts(data))

        sections.append(self._closing(data))
        sections.append(self._footer(data))

        return "\n".join(line for section in sections for line in section)

    def _frontmatter(self, data: ExportData) -> list[str]:
        return [
            "---",
            f"title: '{self._sanitize(data.subtitle)}'",
            f"company: '{self._sanitize(data.company)}'",
            f"topic: '{self._sanitize(data.topic_title)}'",
            f"language: {data.language}",
            f"generated: '{data.generated_at}'",
            f"document_id: {data.document_id}",
            "---",
            "",
        ]

    def _header(self, data: ExportData) -> list[str]:
        return [
            f"# {self._sanitize(data.subtitle)}",
            "",
            "> **Píldora de Concienciación en Ciberseguridad**",
            f"> Empresa: *{self._sanitize(data.company)}*",
            f"> Fecha de generación: {self._format_datetime(data.generated_at)}",
            "",
            "---",
            "",
        ]

    def _intro(self, data: ExportData) -> list[str]:
        paragraphs = [p.strip() for p in self._sanitize(data.intro).split("\n\n") if p.strip()]
        lines: list[str] = []
        for paragraph in paragraphs:
            lines.append(paragraph)
            lines.append("")
        return lines

    def _tips(self, data: ExportData) -> list[str]:
        lines = ["## Consejos Prácticos", ""]

        for i, tip in enumerate(data.tips, 1):
            headline = self._sanitize(tip.get("headline", f"Consejo {i}"))
            body     = self._sanitize(tip.get("body", ""))

            lines.append(f"### {self.template.tip_emoji} {headline}")
            lines.append("")

            for paragraph in body.split("\n\n"):
                if paragraph.strip():
                    lines.append(paragraph.strip())
                    lines.append("")

            links = tip.get("links") or []
            if links:
                lines.append("**Recursos relacionados:**")
                for link in links:
                    text = self._sanitize(link.get("text", "Enlace"))
                    url  = link.get("url", "#")
                    lines.append(f"- [{text}]({url})")
                lines.append("")

        return lines

    def _alerts(self, data: ExportData) -> list[str]:
        if not self.template.alert_section_title:
            return []

        lines = [self.template.alert_section_title, ""]

        for alert in data.alerts:
            title       = self._sanitize(alert.get("title", "Alerta"))
            description = self._sanitize(alert.get("description", ""))
            source      = alert.get("sourceLabel", "Fuente desconocida")
            published   = alert.get("published", "Fecha desconocida")
            severity    = alert.get("severity", "")
            brands      = alert.get("affectedBrands", [])
            url         = alert.get("url", "#")

            severity_emoji = self.template.severity_emojis.get(severity.lower(), "⚪")

            lines.append(f"### {severity_emoji} {title}")
            lines.append("")
            lines.append(f"- **Fuente:** {source}")
            lines.append(f"- **Publicado:** {published}")
            if severity:
                lines.append(f"- **Severidad:** {severity.upper()}")
            if brands:
                lines.append(f"- **Tecnologías afectadas:** {', '.join(brands)}")
            lines.append("")

            if description:
                lines.append(description)
                lines.append("")

            lines.append(f"[Ver detalle completo →]({url})")
            lines.append("")
            lines.append("---")
            lines.append("")

        return lines

    def _closing(self, data: ExportData) -> list[str]:
        if not data.closing:
            return []
        return ["## Conclusión", "", self._sanitize(data.closing), ""]

    def _footer(self, data: ExportData) -> list[str]:
        lines = [
            "---",
            "",
            "*Este documento fue generado automáticamente por el sistema Aegis "
            "de concienciación en ciberseguridad.*",
        ]
        if data.contact_email:
            lines.append(f"*Para más información, contacta con: {data.contact_email}*")
        lines.append("")
        lines.append(f"*ID del documento: {data.document_id}*")
        return lines


# ============================================================================
# EXPORTADOR JSON
# ============================================================================

class JsonExporter(AegisExporter):

    format             = ExportFormat.JSON
    extension          = "json"
    mimetype           = "application/json; charset=utf-8"
    supports_streaming = True

    def __init__(self, indent: int = 2, sort_keys: bool = False) -> None:
        super().__init__()
        self.indent    = indent
        self.sort_keys = sort_keys

    def export(self, data: ExportData, output_path: Path | None = None) -> ExportResult:
        content_dict  = self._to_dict(data)
        content       = json.dumps(content_dict, ensure_ascii=False, indent=self.indent,
                                   sort_keys=self.sort_keys, default=str)
        content_bytes = content.encode("utf-8")
        filename      = output_path.with_suffix(f".{self.extension}").name if output_path else self.generate_filename(data)

        if output_path:
            output_path.with_suffix(f".{self.extension}").write_bytes(content_bytes)

        return ExportResult(
            content      = content_bytes,
            filename     = filename,
            mimetype     = self.mimetype,
            format       = self.format,
            size_bytes   = len(content_bytes),
            generated_at = datetime.now(),
        )

    def _to_dict(self, data: ExportData) -> dict:
        """
        Estructura corregida:
        - topicTitle: Nombre del tema de la base de datos (categoría)
        - title: Título creativo de la píldora (el subtitle generado por IA)
        """
        return {
            "documentId":   data.document_id,
            "topicId":      data.topic_id,
            "topicTitle":   data.topic_title,
            "title":        data.subtitle,
            "company":      data.company,
            "language":     data.language,
            "generatedAt":  data.generated_at,
            "intro":        data.intro,
            "tips":         data.tips,
            "closing":      data.closing,
            "contactEmail": data.contact_email,
            "alerts":       data.alerts,
        }


def get_exporter_for_format(format_type: ExportFormat | str) -> AegisExporter:
    """Devuelve el exportador adecuado para el formato solicitado."""
    if isinstance(format_type, str):
        format_type = ExportFormat(format_type.lower())

    exporters: dict[ExportFormat, type[AegisExporter]] = {
        ExportFormat.MARKDOWN: MarkdownExporter,
        ExportFormat.JSON:     JsonExporter,
    }

    exporter_class = exporters.get(format_type)
    if not exporter_class:
        raise ExporterFormatError(format_type.value if hasattr(format_type, 'value') else format_type)

    return exporter_class()