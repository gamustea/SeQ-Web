"""
Report generation for security scans.

This module provides classes for generating PDF security reports from scan results.
It includes strategies for different scan types (Nmap, OpenVAS, Nikto) with support
for AI-powered analysis using Ollama.

Classes:
    ColorType: Enumeration of color palette types.
    ReportTheme: Theme configuration for PDF styling.
    _PrintingStrategy: Abstract base class for printing strategies.
    PDFCreator: Main class for PDF document generation.
    NmapPrintingStrategy: Strategy for Nmap scan reports.
    OpenVASPrintingStrategy: Strategy for OpenVAS scan reports.
    NiktoPrintingStrategy: Strategy for Nikto scan reports.
    NmapAIWriter: AI writer for Nmap scan analysis.
    NiktoAIWriter: AI writer for Nikto scan analysis.
"""

import os
import json
import random
import re
import time
import textwrap

from enum import Enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any

import ollama

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

from src.misc import ConfigReader, DirectoryType, SecOpsLogger
from src.core.model import NmapScan, NiktoScan, Scan, Host, Topic, NiktoIncident
from src.logic.documents._base import AIWriter
from src.core.exceptions import (
    AIConnectionError,
    AIResponseError,
    AIFallbackExhaustedError,
    PDFGenerationError,
)


class ColorType(Enum):
    """Color palette type identifiers for report theming."""
    BLACK = "black"
    DARK = "dark"
    MAIN = "main"
    SECONDARY = "secondary"
    LIGHT = "light"
    WHITE = "white"


class ReportTheme:
    """PDF report theme configuration.
    
    Manages styling for PDF reports including paragraph styles, table styles,
    and helper methods for creating report sections like headers, cards, and tables.
    
    Attributes:
        palette: Dictionary mapping ColorType to hex color values.
        styles: Base styles from ReportLab.
        title: Main section title style.
        subtitle: Subtitle style.
        pill: Pill/badge style.
        info: Information text style.
        body: Body paragraph style.
        label: Label style.
        footer: Footer style.
        kv_table_style: Key-value table style.
    """
    
    def __init__(self, base_styles, palette):
        self.palette = palette
        self.styles = base_styles

        main = colors.HexColor(palette[ColorType.MAIN])
        light = colors.HexColor(palette[ColorType.LIGHT])
        white = colors.HexColor(palette[ColorType.WHITE])
        black = colors.HexColor(palette[ColorType.BLACK])

        self._accent_color = light

        self.title = ParagraphStyle(
            "ReportTitle",
            parent=base_styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=black,
            alignment=TA_CENTER,
            spaceBefore=6,
            spaceAfter=4,
            fontName="Helvetica-Bold",
        )

        self.subtitle = ParagraphStyle(
            "ReportSubtitle",
            parent=base_styles["Heading2"],
            fontSize=9,
            leading=12,
            textColor=main,
            alignment=TA_CENTER,
            spaceBefore=2,
            spaceAfter=2,
            fontName="Helvetica-Bold",
        )

        self.pill = ParagraphStyle(
            "Pill",
            parent=base_styles["Normal"],
            fontSize=7,
            leading=9,
            textColor=white,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )

        self.info = ParagraphStyle(
            "Info",
            parent=base_styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=main,
            alignment=TA_LEFT,
        )

        self.body = ParagraphStyle(
            "Body",
            parent=base_styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=black,
            alignment=TA_JUSTIFY,
            spaceAfter=5,
        )

        self.label = ParagraphStyle(
            "Label",
            parent=base_styles["Normal"],
            fontSize=7,
            leading=9,
            textColor=main,
            alignment=TA_LEFT,
            fontName="Helvetica-Bold",
        )

        self.pill = ParagraphStyle(
            "Pill",
            parent=base_styles["Normal"],
            fontSize=7,
            leading=9,
            textColor=white,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )

        self.footer = ParagraphStyle(
            "Footer",
            parent=base_styles["Normal"],
            fontSize=8,
            leading=9,
            textColor=colors.HexColor("#aaaaaa"),
            alignment=TA_CENTER,
        )

        self.kv_table_style = TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), white),
            ("TEXTCOLOR", (0, 0), (0, -1), main),
            ("TEXTCOLOR", (1, 0), (1, -1), black),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.4, light),
        ])

    def kv_table(self, data, col_widths):
        """Create a key-value style table.
        
        Args:
            data: List of [key, value] pairs.
            col_widths: Column widths for the table.
            
        Returns:
            Table with applied key-value style.
        """
        t = Table(data, colWidths=col_widths)
        t.setStyle(self.kv_table_style)
        return t

    def section_header(self, title_text: str, tag_text: str) -> list:
        """Create a section header with pill, title, and accent line.
        
        Args:
            title_text: The main title text.
            tag_text: The pill/tag text to display.
            
        Returns:
            List of flowable elements: [pill_wrapper, title_wrapper, divider_wrapper].
        """
        main = colors.HexColor(self.palette[ColorType.MAIN])
        accent = self._accent_color

        pill_para = Paragraph(tag_text.upper(), self.pill)
        pill_table = Table([[pill_para]], colWidths=[1.8 * inch])
        pill_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), main),
            ("BOX", (0, 0), (-1, -1), 0.7, main),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        pill_wrapper = Table([[pill_table]], colWidths=[6 * inch])
        pill_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        title_para = Paragraph(title_text, self.title)
        title_wrapper = Table([[title_para]], colWidths=[6 * inch])
        title_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        divider = Table([[""]], colWidths=[2.5 * inch], rowHeights=[0.035 * inch])
        divider.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), accent),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        
        divider_wrapper = Table([[divider]], colWidths=[6 * inch])
        divider_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        return [pill_wrapper, title_wrapper, divider_wrapper]

    def card(self, inner_flowables, severity_color=None):
        """Create a card container with optional severity color band.
        
        Args:
            inner_flowables: Content to put inside the card.
            severity_color: Optional color for the left severity band.
            
        Returns:
            Table representing the card.
        """
        white = colors.HexColor(self.palette[ColorType.WHITE]) 
        border = colors.HexColor("#DDDDDD")
        band_color = severity_color or colors.HexColor(self.palette[ColorType.MAIN])
        
        band = Table([[""]], colWidths=[0.12 * inch])
        band.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), band_color),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        content_table = Table([[inner_flowables]], colWidths=[5.8 * inch])
        content_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))

        outer = Table([[band, content_table]], colWidths=[0.12 * inch, 5.88 * inch])
        outer.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.7, border),
            ("BACKGROUND", (0, 0), (-1, -1), white),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        return outer

    def severity_header_table(self, left_text: str, right_text: str, bg_color) -> Table:
        """Create a severity header table with left and right text.
        
        Args:
            left_text: Text for the left side.
            right_text: Text for the right side.
            bg_color: Background color for the header.
            
        Returns:
            Table with severity header styling.
        """
        data = [[left_text, right_text]]
        t = Table(data, colWidths=[3 * inch, 3 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg_color),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor(self.palette[ColorType.BLACK])),
            ("ALIGN", (0, 0), (0, -1), "LEFT"),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor(self.palette[ColorType.LIGHT])),
        ]))
        return t

    def section_header(self, title_text: str, tag_text: str) -> list:
        """
        Devuelve [píldora centrada, título centrado, línea de acento].
        """
        main = colors.HexColor(self.palette[ColorType.MAIN])
        accent = self._accent_color

        # Píldora centrada
        pill_para = Paragraph(tag_text.upper(), self.pill)
        pill_table = Table([[pill_para]], colWidths=[1.8 * inch]) # Ancho ajustado para tags largos
        pill_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), main),
            ("BOX", (0, 0), (-1, -1), 0.7, main),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        pill_wrapper = Table([[pill_table]], colWidths=[6 * inch])
        pill_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        # Título centrado
        title_para = Paragraph(title_text, self.title)
        title_wrapper = Table([[title_para]], colWidths=[6 * inch])
        title_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))

        # Línea de acento
        divider = Table([[""]], colWidths=[2.5 * inch], rowHeights=[0.035 * inch])
        divider.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), accent),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        
        divider_wrapper = Table([[divider]], colWidths=[6 * inch])
        divider_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        return [pill_wrapper, title_wrapper, divider_wrapper]

    def card(self, inner_flowables, severity_color=None):
        """
        Envuelve un bloque (vuln/incidente) en una 'card' con borde, padding
        y banda de color opcional a la izquierda.
        """
        white = colors.HexColor(self.palette[ColorType.WHITE]) 
        border = colors.HexColor("#DDDDDD")
        band_color = severity_color or colors.HexColor(self.palette[ColorType.MAIN])
        
        # banda vertical + contenido
        band = Table([[""]], colWidths=[0.12 * inch])
        band.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), band_color),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))

        content_table = Table([[inner_flowables]], colWidths=[5.8 * inch])
        content_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))

        outer = Table([[band, content_table]], colWidths=[0.12 * inch, 5.88 * inch])
        outer.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.7, border),
            ("BACKGROUND", (0, 0), (-1, -1), white),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        return outer

    def severity_header_table(self, left_text: str, right_text: str, bg_color) -> Table:
        data = [[left_text, right_text]]
        t = Table(data, colWidths=[3 * inch, 3 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg_color),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor(self.palette[ColorType.BLACK])),
            ("ALIGN", (0, 0), (0, -1), "LEFT"),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor(self.palette[ColorType.LIGHT])),
        ]))
        return t


class _PrintingStrategy(ABC):
    """Abstract base class for printing strategies.
    
    Defines the interface for generating PDF report content from scan data.
    Each subclass implements type-specific report generation.
    
    Attributes:
        scan: The scan object to generate report from.
        writer: AI writer instance for analysis generation.
        color_palette: Color palette for the report theme.
        logger: Logger instance for the class.
    """

    def __init__(self, scan: Scan) -> None:
        super().__init__()
        self.scan = scan
        self.writer = None
        self.color_palette: Dict[ColorType, str] = {}
        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()

    def _append_ai_analysis(self, elements: list, theme: ReportTheme) -> None:
        """Append AI-generated security analysis to the report.
        
        Args:
            elements: List of flowable elements to append to.
            theme: Report theme for styling.
        """
        ai_analysis = self.writer.generate(self.scan)
        elements.append(PageBreak())
        
        elements.extend(theme.section_header("Análisis de Seguridad IA", "INTELIGENCIA ARTIFICIAL"))
        elements.append(Spacer(1, 0.15 * inch))

        risk = ai_analysis.get("risk_level", "MEDIO")

        risk_colors = {
            "CRÍTICO": colors.HexColor("#b71c1c"),
            "ALTO": colors.HexColor("#d32f2f"),
            "MEDIO": colors.HexColor("#f57c00"),
            "BAJO": colors.HexColor("#388e3c"),
            "INFORMATIVO": colors.HexColor("#1976d2"),
        }
        
        risk_color = risk_colors.get(risk.upper(), colors.HexColor("#757575"))
        
        risk_para = Paragraph(f"NIVEL DE RIESGO: {risk.upper()}", theme.pill)
        risk_table = Table([[risk_para]], colWidths=[2 * inch])
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), risk_color),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BOX", (0, 0), (-1, -1), 0.5, risk_color),
        ]))
        
        risk_wrapper = Table([[risk_table]], colWidths=[6 * inch])
        risk_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(risk_wrapper)
        elements.append(Spacer(1, 0.1 * inch))

        exec_summary = ai_analysis.get("executive_summary", "")
        if exec_summary and isinstance(exec_summary, str):
            elements.append(Paragraph("Resumen Ejecutivo", theme.subtitle))
            elements.append(Spacer(1, 0.05 * inch))
            elements.append(Paragraph(exec_summary, theme.body))
            elements.append(Spacer(1, 0.15 * inch))

        tech_analysis = ai_analysis.get("technical_analysis", "")
        if tech_analysis and isinstance(tech_analysis, str):
            elements.append(Paragraph("Análisis Técnico", theme.subtitle))
            elements.append(Spacer(1, 0.05 * inch))
            elements.append(Paragraph(tech_analysis, theme.body))
            elements.append(Spacer(1, 0.15 * inch))

        recommendations = ai_analysis.get("recommendations", [])
        if recommendations:
            elements.append(Paragraph("Recomendaciones de Seguridad", theme.subtitle))
            elements.append(Spacer(1, 0.1 * inch))

            priority_colors = {
                "ALTA": colors.HexColor("#d32f2f"),
                "MEDIA": colors.HexColor("#f57c00"),
                "BAJA": colors.HexColor("#388e3c"),
                "INFORMATIVA": colors.HexColor("#1976d2"),
            }

            for i, rec in enumerate(recommendations, 1):
                title = rec.get("title", "Recomendación") if isinstance(rec, dict) else "Recomendación"
                desc = rec.get("description", "") if isinstance(rec, dict) else ""
                priority = rec.get("priority", "MEDIA") if isinstance(rec, dict) else "MEDIA"
                remediation = rec.get("remediation", "") if isinstance(rec, dict) else ""

                pri_color = priority_colors.get(priority.upper(), colors.HexColor("#757575"))

                rec_flowables = []
                rec_flowables.append(Paragraph(f"<b>{i}. {title}</b> — Prioridad: {priority}", theme.info))
                if desc:
                    rec_flowables.append(Spacer(1, 0.05 * inch))
                    rec_flowables.append(Paragraph(desc, theme.body))
                if remediation:
                    rec_flowables.append(Spacer(1, 0.05 * inch))
                    rec_flowables.append(Paragraph(f"<b>Acción:</b> {remediation}", theme.body))
                    
                elements.append(theme.card(rec_flowables, severity_color=pri_color))
                elements.append(Spacer(1, 0.1 * inch))

        conclusions = ai_analysis.get("conclusions", "")
        if conclusions and isinstance(conclusions, str):
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(Paragraph("Conclusiones", theme.subtitle))
            elements.append(Spacer(1, 0.05 * inch))
            elements.append(Paragraph(conclusions, theme.body))

        disclaimer_text = """
        <b>Nota:</b> El contenido de esta sección ha sido generado mediante 
        inteligencia artificial y se basa en el análisis automático de los datos del escaneo. 
        Si bien se ha diseñado para proporcionar una evaluación de seguridad objetiva, los 
        resultados deben ser interpretados por un profesional cualificado, pues Sentinel no cuenta
        con todo el contexto en el que se encuentran los hosts escaneados. SeQ no garantiza 
        la exactitud, completitud o aplicabilidad de las recomendaciones generadas. Este análisis con
        inteligencia artificial no sustituye —sino complementa— una auditoría de seguridad manual o la evaluación 
        detallada por parte de un experto en ciberseguridad.
        """
        disclaimer_style = ParagraphStyle(
            "Disclaimer",
            parent=theme.styles["Normal"],
            fontSize=7,
            leading=9,
            textColor=colors.HexColor("#6C757D"),
            alignment=TA_JUSTIFY,
            spaceAfter=5,
        )
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(Paragraph(disclaimer_text, disclaimer_style))
        elements.append(Spacer(1, 0.15 * inch))

    @abstractmethod
    def append_body(self, theme: "ReportTheme", elements: list, ai_report: bool = False) -> None:
        """Add the report body specific to each scan tool.
        
        Args:
            theme: Report theme for styling.
            elements: List of flowable elements to append to.
            ai_report: Whether to include AI-generated analysis.
        """
        ...

    @abstractmethod
    def get_filename_suffix(self) -> str:
        """Get the PDF filename suffix for this scan type.
        
        Returns:
            Filename suffix string (e.g., "_Nmap.pdf").
        """
        ...

    @abstractmethod
    def get_picture_name(self, dark: bool = True) -> str:
        """Get the logo image name for this scan type.
        
        Args:
            dark: Whether to use dark variant of logo.
            
        Returns:
            Logo image filename.
        """
        ...

    @abstractmethod
    def get_report_title(self) -> str:
        """Get the report title for the cover page.
        
        Returns:
            Report title string.
        """
        ...


class PDFCreator:
    """PDF document generator for security scan reports.
    
    Coordinates the creation of PDF reports using printing strategies
    for different scan types. Handles cover page, content, consent page,
    and footer generation.
    
    Attributes:
        config_reader: Configuration reader for directory paths.
        directory: Output directory for PDF files.
        printing_strategy: Strategy for generating report content.
        scan: Source scan data.
    """

    def __init__(self, printing_strategy: _PrintingStrategy) -> None:
        self.config_reader = ConfigReader()
        self.directory = self.config_reader.get_directory_of(DirectoryType.OUTPUT_SENTINEL)
        self.printing_strategy = printing_strategy
        self.scan = printing_strategy.scan

    def _set_pdf_metadata(self, doc) -> None:
        """Set PDF document metadata.
        
        Args:
            doc: SimpleDocTemplate instance.
        """
        scan = self.scan
        started = getattr(scan, "started_at", None)
        date_str = started.strftime("%d/%m/%Y") if started else datetime.now().strftime("%d/%m/%Y")
        doc.title = f"Informe de Seguridad - {scan.id}"
        doc.author = "SecOps Security Team"
        doc.subject = f"Análisis de seguridad realizado el {date_str}"
        doc.creator = "SecOps PDF Generator v2.0"

    def _on_page(self, canv, doc):
        """Callback for rendering page elements (header, footer, sidebar).
        
        Args:
            canv: Canvas instance.
            doc: Document instance.
        """
        canv.saveState()
        width, height = A4

        palette = self.printing_strategy.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])

        canv.setFillColor(main)
        canv.rect(20, 20, 6, height - 40, stroke=0, fill=1)

        canv.setFont("Helvetica-Bold", 9)
        canv.setFillColor(dark)
        canv.drawString(40, height - 30, "SecOps Security Report")

        canv.setStrokeColor(colors.HexColor("#e0e0e0"))
        canv.setLineWidth(0.5)
        canv.line(36, height - 42, width - 36, height - 42)

        page_num = canv.getPageNumber()
        canv.setFont("Helvetica", 8)
        canv.setFillColor(colors.HexColor("#999999"))
        canv.drawRightString(width - 40, 28, f"Página {page_num}")

        canv.restoreState()

    def append_cover_page(
        self,
        elements: list,
        theme: ReportTheme,
        title: str,
        subtitle: str = "",
        client_name: Optional[str] = None,
        document_type: str = "Informe de Seguridad",
        date: Optional[datetime] = None,
    ) -> None:
        """Append cover page to the document.
        
        Args:
            elements: List of flowable elements.
            theme: Report theme for styling.
            title: Main title text.
            subtitle: Optional subtitle text.
            client_name: Optional client name.
            document_type: Type of document.
            date: Optional date (defaults to now).
        """
        if date is None:
            date = datetime.now()

        palette = theme.palette
        main = colors.HexColor(palette[ColorType.MAIN])
        light = colors.HexColor(palette[ColorType.LIGHT])
        white = colors.HexColor(palette[ColorType.WHITE])
        black = colors.HexColor(palette[ColorType.BLACK])

        self.append_logo(elements, is_cover=True)

        doc_type_style = ParagraphStyle(
            "CoverDocType",
            parent=theme.styles["Normal"],
            fontSize=11,
            textColor=main,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
            spaceAfter=10,
        )
        elements.append(Paragraph(document_type.upper(), doc_type_style))
        elements.append(Spacer(1, 0.25 * inch))

        title_style = ParagraphStyle(
            "CoverTitle",
            parent=theme.styles["Heading1"],
            fontSize=30,
            leading=34,
            textColor=white,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )
        title_paragraph = Paragraph(title, title_style)
        title_table = Table([[title_paragraph]], colWidths=[6 * inch])
        title_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), main),
            ("TOPPADDING", (0, 0), (-1, -1), 24),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 24),
            ("LEFTPADDING", (0, 0), (-1, -1), 24),
            ("RIGHTPADDING", (0, 0), (-1, -1), 24),
        ]))
        elements.append(title_table)

        if subtitle:
            elements.append(Spacer(1, 0.3 * inch))
            subtitle_style = ParagraphStyle(
                "CoverSubtitle",
                parent=theme.styles["Normal"],
                fontSize=13,
                leading=16,
                textColor=black,
                alignment=TA_CENTER,
            )
            elements.append(Paragraph(subtitle, subtitle_style))

        elements.append(Spacer(1, 1.3 * inch))

        info_data = []
        if client_name:
            info_data.append(["Cliente:", client_name])
        info_data.append(["Fecha:", date.strftime("%d/%m/%Y")])

        info_table = Table(info_data, colWidths=[1.8 * inch, 3.2 * inch])
        info_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), white),
            ("TEXTCOLOR", (0, 0), (0, -1), main),
            ("TEXTCOLOR", (1, 0), (1, -1), black),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("BOX", (0, 0), (-1, -1), 1, light),
        ]))
        elements.append(info_table)

        elements.append(Spacer(1, 1.0 * inch))
        decoration = Table([[""]], colWidths=[6 * inch], rowHeights=[0.12 * inch])
        decoration.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), light),
        ]))
        elements.append(decoration)
        elements.append(PageBreak())

    def append_logo(self, elements: list, is_cover: bool = False) -> None:
        """Append logo image to the document.
        
        Args:
            elements: List of flowable elements.
            is_cover: Whether this is for the cover page (larger logo).
        """
        resource_directory = self.config_reader.get_directory_of(DirectoryType.RESOURCE)
        picture_name = self.printing_strategy.get_picture_name()
        image_filename = os.path.join(resource_directory, picture_name)

        if not os.path.exists(image_filename):
            return

        if is_cover:
            logo = Image(image_filename, width=3 * inch, height=3 * inch)
            logo.hAlign = "CENTER"
            elements.append(logo)
            elements.append(Spacer(1, 0.3 * inch))
        else:
            logo = Image(image_filename, width=1.2 * inch, height=1.2 * inch)
            logo.hAlign = "LEFT"
            elements.append(logo)
            elements.append(Spacer(1, 0.15 * inch))

    def append_consent(self, elements: list, theme: ReportTheme) -> None:
        """Append consent declaration page to the document.
        
        Args:
            elements: List of flowable elements.
            theme: Report theme for styling.
        """
        elements.append(PageBreak())

        palette = theme.palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])

        title_style = ParagraphStyle(
            "ConsentTitle",
            parent=theme.styles["Heading2"],
            fontSize=11,
            textColor=main,
            spaceAfter=10,
            fontName="Helvetica-Bold",
        )
        text_style = ParagraphStyle(
            "ConsentText",
            parent=theme.styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=dark,
            alignment=TA_JUSTIFY,
        )

        title = Paragraph("DECLARACIÓN DE CONFORMIDAD Y CONSENTIMIENTO", title_style)
        elements.append(title)

        consent_text = """
        El usuario declara y confirma que ha otorgado su consentimiento expreso e
        inequívoco para la realización del escaneo de seguridad sobre el sitio web
        y/o sistema informático objeto del presente informe. El usuario acepta y
        reconoce que es el titular legítimo o cuenta con la autorización necesaria
        de los equipos, sistemas y redes escaneados.

        El usuario asume la plena responsabilidad sobre las consecuencias derivadas
        del escaneo realizado, incluyendo cualquier resultado, hallazgo o
        vulnerabilidad identificada en el proceso. Asimismo, el usuario exonera
        de toda responsabilidad a los ejecutores del análisis de seguridad respecto
        al uso que se haga de la información contenida en este documento.

        Este documento contiene información sensible de carácter confidencial y
        debe ser tratado con las medidas de seguridad apropiadas conforme a la
        normativa vigente en materia de protección de datos.
        """
        paragraph = Paragraph(consent_text.strip(), text_style)
        table = Table([[paragraph]], colWidths=[6 * inch])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), white),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("BOX", (0, 0), (-1, -1), 1.2, main),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

    def append_footer(self, elements: list, theme: ReportTheme) -> None:
        """Append footer text to the document.
        
        Args:
            elements: List of flowable elements.
            theme: Report theme for styling.
        """
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        footer_text = f"Informe generado automáticamente | {timestamp}"
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph(footer_text, theme.footer))

    def print_pdf(self, 
        ai_report: bool = False, 
        client_name: Optional[str] = None
    ) -> str:
        """Generate the complete PDF report.
        
        Args:
            ai_report: Whether to include AI-generated analysis.
            client_name: Optional client name for the cover page.
            
        Returns:
            Path to the generated PDF file.
        """
        os.makedirs(self.directory, exist_ok=True)

        filename = os.path.join(
            self.directory,
            f"{self.scan.id}{self.printing_strategy.get_filename_suffix()}",
        )

        doc = SimpleDocTemplate(
            filename,
            pagesize=A4,
            rightMargin=36,
            leftMargin=36,
            topMargin=60,
            bottomMargin=40,
        )

        base_styles = getSampleStyleSheet()
        theme = ReportTheme(base_styles, self.printing_strategy.color_palette)
        elements: list = []

        self.append_cover_page(
            elements=elements,
            theme=theme,
            title=self.printing_strategy.get_report_title(),
            client_name=client_name,
        )

        self.append_logo(elements, is_cover=False)
        self.printing_strategy.append_body(theme=theme, elements=elements, ai_report=ai_report)

        self.append_consent(elements, theme)
        self.append_footer(elements, theme)

        self._set_pdf_metadata(doc)
        doc.build(elements, onFirstPage=self._on_page, onLaterPages=self._on_page)

        return filename


class NmapPrintingStrategy(_PrintingStrategy):
    """Printing strategy for Nmap scan reports.
    
    Generates PDF reports for Nmap network scans including host information,
    open ports table, and optional AI-powered security analysis.
    
    Color palette: Blue theme for network security reports.
    
    Attributes:
        writer: NmapAIWriter instance for AI analysis.
        color_palette: Blue color palette for the report.
    """

    def __init__(self, scan: NmapScan) -> None:
        """Initialize Nmap printing strategy.
        
        Args:
            scan: NmapScan instance to generate report from.
        """
        super().__init__(scan)
        self.writer = NmapAIWriter()
        
        self.color_palette = {
            ColorType.BLACK: "#121212",
            ColorType.DARK: "#01375A",
            ColorType.MAIN: "#014F86",
            ColorType.SECONDARY: "#555B6E",
            ColorType.LIGHT: "#4A90E2",
            ColorType.WHITE: "#E1E8F0",
        }

    def append_body(self, theme: ReportTheme, elements: list, ai_report: bool = False) -> None:
        """Generate the report body for Nmap scans.
        
        Args:
            theme: Report theme for styling.
            elements: List of flowable elements to append to.
            ai_report: Whether to include AI-generated analysis.
        """
        scan = self.scan
        palette = self.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])
        light = colors.HexColor(palette[ColorType.LIGHT])

        elements.append(Paragraph("Informe de Escaneo Nmap", theme.title))
        elements.append(Spacer(1, 0.1 * inch))

        if getattr(scan, "host", None):
            host: Host = scan.host
            host_info = [
                ["Host analizado:", str(getattr(host, "ip_address", ""))],
                ["Nombre de host:", str(getattr(host, "hostname", ""))],
                ["MAC address:", str(getattr(host, "mac_address", ""))],
                ["Vendedor:", str(getattr(host, "vendor", ""))],
            ]
            host_table = theme.kv_table(host_info, col_widths=[2 * inch, 4 * inch])
            elements.append(host_table)
            elements.append(Spacer(1, 0.1 * inch))

        started = getattr(scan, "started_at", None)
        started_str = started.strftime("%d/%m/%Y %H:%M:%S") if started else "N/A"
        total_ports = len(getattr(scan, "open_ports_relation", []))

        scan_info = [
            ["ID del escaneo:", str(getattr(scan, "id", ""))],
            ["Fecha de inicio:", started_str],
            ["Total de puertos abiertos:", str(total_ports)],
        ]
        scan_table = theme.kv_table(scan_info, col_widths=[2 * inch, 4 * inch])
        elements.append(scan_table)
        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph("Puertos abiertos detectados", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        open_ports = getattr(scan, "open_ports_relation", [])
        if not open_ports:
            elements.append(Paragraph("No se detectaron puertos abiertos.", theme.info))
            return

        port_data = [["#", "Puerto", "Servicio", "Versión del software"]]
        for idx, relation in enumerate(open_ports, start=1):
            port = getattr(relation, "port", None)
            port_id = getattr(port, "port", "") if port else ""
            protocol = getattr(port, "protocol", "") if port else ""
            given_use = str(getattr(relation, "given_use", "") or "").upper()
            product_name = str(getattr(relation, "product", "") or "") or "NO ENCONTRADO"
            product_version = str(getattr(relation, "version", "") or "") or "N/A"

            port_str = f"{port_id}"
            proto_str = protocol.split("/")[0] if protocol else ""

            port_data.append([
                str(idx),
                proto_str,
                given_use,
                f"{product_name} {product_version}".strip(),
            ])

        port_table = Table(
            port_data,
            colWidths=[0.5 * inch, 0.8 * inch, 2.0 * inch, 4.0 * inch],
            repeatRows=1,
        )
        port_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), main),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 1), (-1, -1), white),
            ("TEXTCOLOR", (0, 1), (-1, -1), dark),
            ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("ALIGN", (1, 1), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("TOPPADDING", (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, white]),
            ("GRID", (0, 0), (-1, -1), 0.4, light),
            ("LINEBELOW", (0, 0), (-1, 0), 1.2, main),
        ]))
        elements.append(port_table)

        if ai_report:
            self._append_ai_analysis(elements, theme)

    def get_filename_suffix(self) -> str:
        """Get the PDF filename suffix.
        
        Returns:
            Filename suffix: "_Nmap.pdf"
        """
        return "_Nmap.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        """Get the logo image name for Nmap reports.
        
        Args:
            dark: Whether to use dark variant.
            
        Returns:
            Logo filename.
        """
        picture_name = "SecOps-Logo-Blue"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        """Get the report title for the cover page.
        
        Returns:
            Report title: "Análisis de Seguridad de Red"
        """
        return "Análisis de Seguridad de Red"


class OpenVASPrintingStrategy(_PrintingStrategy):
    """Printing strategy for OpenVAS vulnerability scan reports.
    
    Generates PDF reports for OpenVAS scans including vulnerability summary,
    detailed vulnerability cards with CVSS scores, and optional AI analysis.
    
    Color palette: Green theme for vulnerability management reports.
    
    Attributes:
        color_palette: Green color palette for the report.
    """

    def __init__(self, scan) -> None:
        """Initialize OpenVAS printing strategy.
        
        Args:
            scan: OpenVASScan instance to generate report from.
        """
        super().__init__(scan)
        self.color_palette = {
            ColorType.BLACK: "#0D2818",
            ColorType.DARK: "#1B5E20",
            ColorType.MAIN: "#2E7D32",
            ColorType.SECONDARY: "#43A047",
            ColorType.LIGHT: "#66BB6A",
            ColorType.WHITE: "#E8F5E9",
        }

    def append_body(self, theme: "ReportTheme", elements: list, ai_report: bool = False) -> None:
        """Generate the report body for OpenVAS scans.
        
        Args:
            theme: Report theme for styling.
            elements: List of flowable elements to append to.
            ai_report: Whether to include AI-generated analysis.
        """
        scan = self.scan
        palette = self.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])

        elements.append(Paragraph("Informe de Escaneo OpenVAS", theme.title))
        elements.append(Spacer(1, 0.1 * inch))

        if getattr(scan, "host", None):
            host = scan.host
            host_info = [
                ["Host analizado:", str(getattr(host, "ip_address", ""))],
                ["Nombre de host:", str(getattr(host, "hostname", ""))],
            ]
            host_table = theme.kv_table(host_info, col_widths=[2 * inch, 4 * inch])
            elements.append(host_table)
            elements.append(Spacer(1, 0.1 * inch))
        started_str = started.strftime("%d/%m/%Y %H:%M:%S") if started else "N/A"
        results = getattr(scan, "results", []) or []

        scan_info = [
            ["ID del escaneo:", str(getattr(scan, "id", ""))],
            ["Task ID:", str(getattr(scan, "task_id", ""))],
            ["Report ID:", str(getattr(scan, "report_id", ""))],
            ["Fecha de inicio:", started_str],
            ["Total de vulnerabilidades:", str(len(results))],
        ]
        if getattr(scan, "scan_config_name", None):
            scan_info.append(["Configuración:", str(scan.scan_config_name)])
        if getattr(scan, "scanner_name", None):
            scan_info.append(["Scanner:", str(scan.scanner_name)])

        info_table = theme.kv_table(scan_info, col_widths=[2 * inch, 4 * inch])
        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

        # Resumen de severidad
        if results:
            elements.append(Paragraph("Resumen de severidad", theme.subtitle))
            elements.append(Spacer(1, 0.1 * inch))

            severity_counts: Dict[str, int] = {}
            scores_by_severity: Dict[str, list] = {}

            for result in results:
                vuln = result.vulnerability
                sev_raw = getattr(vuln, "severity_class", None) or "UNKNOWN"
                severity = str(sev_raw).upper()

                severity_counts[severity] = severity_counts.get(severity, 0) + 1

                score = getattr(vuln, "severity_score", None)
                if score is not None:
                    scores_by_severity.setdefault(severity, []).append(float(score))

            header = ["Severidad", "Cantidad", "Score promedio"]
            data = [header]

            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "LOG", "UNKNOWN"]
            for sev in severity_order:
                if sev not in severity_counts:
                    continue
                count = severity_counts[sev]
                scores = scores_by_severity.get(sev, [])
                avg = sum(scores) / len(scores) if scores else 0.0
                data.append([sev, str(count), f"{avg:.1f}"])

            table = Table(data, colWidths=[2.5 * inch, 1.3 * inch, 2.2 * inch], repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), main),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("TOPPADDING", (0, 0), (-1, 0), 8),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("BACKGROUND", (0, 1), (-1, -1), white),
                ("TEXTCOLOR", (0, 1), (-1, -1), dark),
                ("ALIGN", (0, 1), (0, -1), "CENTER"),
                ("ALIGN", (1, 1), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("TOPPADDING", (0, 1), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
                ("GRID", (0, 0), (-1, -1), 0.4, dark),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 0.3 * inch))

        # Detalle de vulnerabilidades
        elements.append(PageBreak())
        elements.append(Paragraph("Vulnerabilidades detectadas", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        if not results:
            elements.append(Paragraph("No se detectaron vulnerabilidades.", theme.info))
            return

        severity_priority = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "LOG": 4,
            "UNKNOWN": 5,
        }

        def sort_key(res):
            vuln = res.vulnerability
            sev_raw = getattr(vuln, "severity_class", None) or "UNKNOWN"
            sev = str(sev_raw).upper()
            score = getattr(vuln, "severity_score", None) or 0.0
            return (severity_priority.get(sev, 5), -float(score))

        sorted_results = sorted(results, key=sort_key)

        # Colores de fondo por severidad
        severity_bg = {
            "CRITICAL": colors.HexColor("#ffcccc"),
            "HIGH": colors.HexColor("#ffe6cc"),
            "MEDIUM": colors.HexColor("#fff4cc"),
            "LOW": colors.HexColor("#e6ffe6"),
            "LOG": colors.HexColor("#e6f7ff"),
            "UNKNOWN": colors.HexColor("#f0f0f0"),
        }

        description_style = ParagraphStyle(
            "OVDescription",
            parent=theme.body,
            fontSize=9,
            leading=12,
        )

        for idx, result in enumerate(sorted_results, start=1):
            elements.append(CondPageBreak(3 * inch))

            vuln = result.vulnerability
            sev_raw = getattr(vuln, "severity_class", None) or "UNKNOWN"
            severity = str(sev_raw).upper()

            bgcolor = severity_bg.get(severity, severity_bg["UNKNOWN"])
            cvss = getattr(vuln, "cvss_base_score", None)
            score_text = f"CVSS: {cvss:.1f}" if cvss is not None else "CVSS: N/A"

            # Cabecera
            header_table = theme.severity_header_table(
                left_text=f"Vulnerabilidad #{idx}",
                right_text=f"Severidad: {severity} | {score_text}",
                bg_color=bgcolor,
            )
            elements.append(header_table)

            # Nombre de la vulnerabilidad en una banda de color principal
            name_para = Paragraph(str(getattr(vuln, "name", "")), ParagraphStyle(
                "OVName",
                parent=theme.styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=10,
                textColor=colors.whitesmoke,
                alignment=TA_LEFT,
            ))
            name_table = Table([[name_para]], colWidths=[6 * inch])
            name_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), main),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("BOX", (0, 0), (-1, -1), 0.6, dark),
            ]))
            elements.append(name_table)

            # Detalles técnicos
            details = [
                ["NVT OID:", str(getattr(vuln, "nvt_oid", ""))],
                ["Host:", str(getattr(result.host, "ip_address", ""))],
            ]
            detected = getattr(result, "detected_at", None)
            if detected:
                details.append(["Detectado:", detected.strftime("%d/%m/%Y %H:%M:%S")])
            if getattr(vuln, "family", None):
                details.append(["Familia:", str(vuln.family)])
            if getattr(vuln, "cvss_vector", None):
                details.append(["Vector CVSS:", str(vuln.cvss_vector)])
            if getattr(vuln, "qod_value", None) is not None:
                qod_type = getattr(vuln, "qod_type", None) or "N/A"
                details.append(["QoD:", f"{vuln.qod_value}% ({qod_type})"])

            details_table = Table(details, colWidths=[1.7 * inch, 4.3 * inch])
            details_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f9f9f9")),
                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
            ]))
            elements.append(details_table)

            # Resumen
            summary = getattr(vuln, "summary", None)
            if summary:
                text = summary[:500] + ("..." if len(summary) > 500 else "")
                para = Paragraph(f"Resumen: {text}", description_style)
                table = Table([[para]], colWidths=[6 * inch])
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
                ]))
                elements.append(table)

            # Impacto
            impact = getattr(vuln, "impact", None)
            if impact:
                text = impact[:400] + ("..." if len(impact) > 400 else "")
                para = Paragraph(f"Impacto: {text}", description_style)
                table = Table([[para]], colWidths=[6 * inch])
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff0f0")),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
                ]))
                elements.append(table)

            # Solución
            solution = getattr(vuln, "solution", None)
            if solution:
                text = solution[:400] + ("..." if len(solution) > 400 else "")
                stype = getattr(vuln, "solution_type", None)
                stype_txt = f" ({stype})" if stype else ""
                para = Paragraph(f"Solución{stype_txt}: {text}", description_style)
                table = Table([[para]], colWidths=[6 * inch])
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), white),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
                ]))
                elements.append(table)

            # Referencias
            refs_parts = []
            if getattr(vuln, "cve_ids", None):
                refs_parts.append(f"CVE: {vuln.cve_ids}")
            if getattr(vuln, "cert_refs", None):
                refs_parts.append(f"CERT: {vuln.cert_refs}")
            if getattr(vuln, "bugtraq_ids", None):
                refs_parts.append(f"BugTraq: {vuln.bugtraq_ids}")
            if getattr(vuln, "other_refs", None):
                refs_parts.append(f"Otros: {vuln.other_refs}")

            if refs_parts:
                full = " | ".join(refs_parts)
                text = full[:400] + ("..." if len(full) > 400 else "")
                para = Paragraph(f"Referencias: {text}", description_style)
                table = Table([[para]], colWidths=[6 * inch])
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f8ff")),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
                ]))
                elements.append(table)

            elements.append(Spacer(1, 0.2 * inch))

    def get_filename_suffix(self) -> str:
        """Get the PDF filename suffix.
        
        Returns:
            Filename suffix: "_OpenVAS.pdf"
        """
        return "_OpenVAS.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        """Get the logo image name for OpenVAS reports.
        
        Args:
            dark: Whether to use dark variant.
            
        Returns:
            Logo filename.
        """
        picture_name = "SecOps-Logo-Green"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        """Get the report title for the cover page.
        
        Returns:
            Report title: "Análisis de Vulnerabilidades OpenVAS"
        """
        return "Análisis de Vulnerabilidades OpenVAS"


class NiktoPrintingStrategy(_PrintingStrategy):
    """Printing strategy for Nikto web vulnerability scan reports.
    
    Generates PDF reports for Nikto scans including incident summary,
    detailed security incident cards, and optional AI analysis.
    
    Color palette: Orange/Salmon theme for web security reports.
    
    Attributes:
        writer: NiktoAIWriter instance for AI analysis.
        color_palette: Orange color palette for the report.
    """

    def __init__(self, scan: NiktoScan) -> None:
        """Initialize Nikto printing strategy.
        
        Args:
            scan: NiktoScan instance to generate report from.
        """
        super().__init__(scan)
        self.writer = NiktoAIWriter()
        self.color_palette = {
            ColorType.BLACK: "#4B2500",
            ColorType.DARK: "#8E3D0A",
            ColorType.MAIN: "#C75B12",
            ColorType.SECONDARY: "#FA8072",
            ColorType.LIGHT: "#F9B49A",
            ColorType.WHITE: "#FFF5F0",
        }

    def append_body(self, theme: "ReportTheme", elements: list, ai_report: bool = False) -> None:
        scan = self.scan
        palette = self.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])

        # Título interno
        elements.append(Paragraph("Informe de Escaneo Nikto", theme.title))
        elements.append(Spacer(1, 0.1 * inch))

        # Host
        if getattr(scan, "host", None):
            host = scan.host
            host_info = [
                ["Host analizado:", str(getattr(host, "ip_address", ""))],
                ["Nombre de host:", str(getattr(host, "hostname", ""))],
            ]
            host_table = theme.kv_table(host_info, col_widths=[2 * inch, 4 * inch])
            elements.append(host_table)
            elements.append(Spacer(1, 0.1 * inch))

        # Info escaneo
        started = getattr(scan, "started_at", None)
        started_str = started.strftime("%d/%m/%Y %H:%M:%S") if started else "N/A"
        incidents = getattr(scan, "incidents", []) or []

        scan_info = [
            ["ID del escaneo:", str(getattr(scan, "id", ""))],
            ["Fecha de inicio:", started_str],
            ["Total de incidentes:", str(len(incidents))],
        ]
        info_table = theme.kv_table(scan_info, col_widths=[2 * inch, 4 * inch])
        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

        # Resumen de severidad
        if incidents:
            elements.append(Paragraph("Resumen de severidad", theme.subtitle))
            elements.append(Spacer(1, 0.1 * inch))

            severity_counts: Dict[str, int] = {}
            for inc in incidents:
                sev_raw = getattr(inc, "severity", None) or "UNKNOWN"
                severity = str(sev_raw).upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            header = ["Severidad", "Cantidad"]
            data = [header]

            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
            for sev in severity_order:
                if sev not in severity_counts:
                    continue
                data.append([sev, str(severity_counts[sev])])

            table = Table(data, colWidths=[3 * inch, 2 * inch], repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(palette[ColorType.SECONDARY])),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("TOPPADDING", (0, 0), (-1, 0), 8),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("BACKGROUND", (0, 1), (-1, -1), white),
                ("TEXTCOLOR", (0, 1), (-1, -1), dark),
                ("ALIGN", (0, 1), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("TOPPADDING", (0, 1), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
                ("GRID", (0, 0), (-1, -1), 0.4, dark),
            ]))
            elements.append(table)
            elements.append(Spacer(1, 0.3 * inch))

        # Detalle de incidentes
        elements.append(Paragraph("Incidentes de seguridad detectados", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        if not incidents:
            elements.append(Paragraph("No se detectaron incidentes de seguridad.", theme.info))
            return

        severity_priority = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
            "UNKNOWN": 5,
        }

        def sort_key(inc):
            sev_raw = getattr(inc, "severity", None) or "UNKNOWN"
            sev = str(sev_raw).upper()
            return severity_priority.get(sev, 5)

        sorted_incidents = sorted(incidents, key=sort_key)

        severity_bg = {
            "CRITICAL": colors.HexColor("#ffcccc"),
            "HIGH": colors.HexColor("#ffe6cc"),
            "MEDIUM": colors.HexColor("#fff4cc"),
            "LOW": colors.HexColor("#e6f7ff"),
            "INFO": colors.HexColor("#e6f7ff"),
            "UNKNOWN": colors.HexColor("#f0f0f0"),
        }

        description_style = ParagraphStyle(
            "NiktoDesc",
            parent=theme.body,
            fontSize=9,
            leading=12,
        )
        url_style = ParagraphStyle(
            "NiktoUrl",
            parent=theme.styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            textColor=colors.HexColor(palette[ColorType.BLACK]),
            wordWrap="CJK",
            alignment=TA_LEFT,
        )

        for idx, incident in enumerate(sorted_incidents, start=1):
            elements.append(CondPageBreak(2.5 * inch))

            sev_raw = getattr(incident, "severity", None) or "UNKNOWN"
            severity = str(sev_raw).upper()
            bgcolor = severity_bg.get(severity, severity_bg["UNKNOWN"])

            # Cabecera simple
            header = Table(
                [[f"Incidente #{idx}", f"Severidad: {severity}"]],
                colWidths=[3 * inch, 3 * inch],
            )
            header.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), bgcolor),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor(palette[ColorType.BLACK])),
                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("BOX", (0, 0), (-1, -1), 0.8, white),
            ]))
            elements.append(header)

            # Detalles
            details = []
            if getattr(incident, "osvdb_id", None):
                details.append(["OSVDB ID:", str(incident.osvdb_id)])
            if getattr(incident, "method", None):
                details.append(["Método:", str(incident.method)])
            if getattr(incident, "url", None):
                details.append(["URL:", Paragraph(str(incident.url), url_style)])
            if getattr(incident, "port", None):
                details.append(["Puerto:", str(incident.port)])
            if getattr(incident, "discovered_at", None):
                discovered = incident.discovered_at.strftime("%d/%m/%Y %H:%M:%S")
                details.append(["Detectado:", discovered])

            if details:
                details_table = Table(details, colWidths=[1.6 * inch, 4.4 * inch])
                details_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f9f9f9")),
                    ("ALIGN", (0, 0), (0, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
                ]))
                elements.append(details_table)

            # Descripción
            desc = getattr(incident, "description", None)
            if desc:
                text = desc[:500] + ("..." if len(desc) > 500 else "")
                para = Paragraph(f"Descripción: {text}", description_style)
                table = Table([[para]], colWidths=[6 * inch])
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
                ]))
                elements.append(table)

            # Referencias
            refs = getattr(incident, "references", None)
            if refs:
                text = refs[:300] + ("..." if len(refs) > 300 else "")
                para = Paragraph(f"Referencias: {text}", description_style)
                table = Table([[para]], colWidths=[6 * inch])
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f8ff")),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
                ]))
                elements.append(table)

            elements.append(Spacer(1, 0.2 * inch))

        if ai_report:
            self._append_ai_analysis(elements, theme)

    def get_filename_suffix(self) -> str:
        return "_Nikto.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        picture_name = "SecOps-Logo-Salmon"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        return "Análisis de Vulnerabilidades Web"


class NmapAIWriter(AIWriter):
    """AI writer for Nmap scan security analysis.
    
    Generates security analysis and recommendations for Nmap network scans
    using Ollama. Provides objective evaluation of attack surfaces,
    distinguishing between exposed services and confirmed vulnerabilities.
    
    The system prompt enforces strict principles:
    - Open port ≠ Vulnerability
    - Prefer underestimation to overestimation
    - Never invent CVEs or assume missing authentication
    
    Attributes:
        model: Ollama model name (from env var or default).
        _client: Ollama client instance.
        _prompts: Prompt configuration from SecConfig.json.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        model: Optional[str] = None
    ) -> None:
        """Initialize Nmap AI writer.
        
        Args:
            host: Ollama host (optional, from env var if not provided).
            model: Ollama model name (optional, from env var if not provided).
        """
        super().__init__()
        self._prompts = ConfigReader().get_prompts_config()

    def _build_system_prompt(self) -> str:
        """Build the system prompt defining analyst persona and principles.
        
        Returns:
            System prompt string with analysis guidelines.
        """
        prompts_config = ConfigReader().get_prompts_config()
        return prompts_config.get("nmap", {}).get("system", "")

    def _build_user_prompt(self, scan_data: dict, open_ports: list) -> str:
        """Build the user prompt with scan data and port analysis.
        
        Args:
            scan_data: Dictionary with scan metadata (target, timestamps).
            open_ports: List of open port dictionaries.
            
        Returns:
            Formatted user prompt string.
        """
        target = scan_data.get("target", "desconocido")
        started = scan_data.get("started_at", "N/A")
        
        analysis_context = self._analyze_port_patterns(open_ports)
        
        ports_info = []
        for op in open_ports:
            port_num = op.get("port", {}).get("port", "N/A")
            protocol = op.get("port", {}).get("protocol", "tcp")
            service = op.get("given_use", "unknown")
            product = op.get("product", "")
            version = op.get("version", "")
            
            port_type = "sistema" if isinstance(port_num, int) and port_num < 1024 else "usuario"
            
            ports_info.append({
                "puerto": f"{port_num}/{protocol}",
                "servicio": service,
                "implementacion": f"{product} {version}".strip() if (product or version) else "No identificada",
                "tipo_puerto": port_type,
                "categoria_funcional": self._infer_functional_category(service, port_num)
            })
        
        # Obtener template aquí dentro usando ConfigReader, igual que NiktoAIWriter
        prompts_config = ConfigReader().get_prompts_config()
        template = prompts_config.get("nmap", {}).get("user_template", "")
        
        # Reemplazar placeholders {{variable}} según el formato del SecConfig.json
        return template.replace("{{target}}", str(target)) \
                    .replace("{{started}}", str(started)) \
                    .replace("{{total_ports}}", str(len(ports_info))) \
                    .replace("{{distribution}}", str(analysis_context["distribution"])) \
                    .replace("{{profile_type}}", str(analysis_context["profile_type"])) \
                    .replace("{{ports_json}}", json.dumps(ports_info, indent=2, ensure_ascii=False))

    def _analyze_port_patterns(self, open_ports: list) -> dict:
        """Analyze port patterns to infer system context.
        
        Args:
            open_ports: List of open port dictionaries.
            
        Returns:
            Dictionary with distribution and profile_type.
        """
        if not open_ports:
            return {"distribution": "ninguno", "profile_type": "Host sin servicios detectados"}
        
        ports = []
        for op in open_ports:
            p = op.get("port", {}).get("port", 0)
            if isinstance(p, int):
                ports.append(p)
        
        priviliged = sum(1 for p in ports if p < 1024)
        userland = sum(1 for p in ports if p >= 1024)
        web_like = any(p in [80, 443, 8080, 8443] for p in ports)
        admin_like = any(p in [22, 23, 3389, 5900] for p in ports)
        
        if priviliged >= 3 and userland <= 2:
            profile = "Servidor de infraestructura (mix privilegiado estándar)"
        elif web_like and admin_like:
            profile = "Servidor web con gestión remota"
        elif userland > priviliged:
            profile = "Aplicación/Servicio específico (puertos dinámicos predominantes)"
        elif priviliged == 1 and not userland:
            profile = "Servicio único dedicado"
        else:
            profile = "Configuración híbrida estándar"
            
        return {
            "distribution": f"{priviliged} sistema / {userland} aplicación",
            "profile_type": profile
        }

    def _infer_functional_category(self, service_name: str, port: int) -> str:
        """Infer functional category based on service behavior.
        
        Args:
            service_name: Service name string.
            port: Port number.
            
        Returns:
            Functional category string.
        """
        service = str(service_name).lower()
        
        if any(x in service for x in ['ssh', 'telnet', 'rdp', 'vnc', 'shell']):
            return "acceso_remoto"
        elif any(x in service for x in ['http', 'www', 'web', 'proxy']):
            return "web_api"
        elif any(x in service for x in ['dns', 'domain', 'dhcp', 'ntp', 'ldap']):
            return "servicio_red"
        elif any(x in service for x in ['sql', 'db', 'mongo', 'redis', 'postgres', 'mysql']):
            return "almacenamiento_datos"
        elif port in [111, 2049, 445, 139, 21]:
            return "comparticion_archivos"
        else:
            return "servicio_especifico"

    def generate(self, scan: NmapScan) -> dict:
        """Generate AI security analysis for an Nmap scan.
        
        Args:
            scan: NmapScan object with scan data.
            
        Returns:
            Dictionary with keys: executive_summary, risk_level, technical_analysis,
            recommendations, conclusions.
        """
        scan_data = {
            "target": scan.target,
            "started_at": scan.started_at.isoformat() if getattr(scan, 'started_at', None) else "N/A",
            "finished_at": scan.finished_at.isoformat() if getattr(scan, 'finished_at', None) else "N/A",
            "status": getattr(scan, 'status', 'unknown'),
        }
        
        open_ports = []
        for relation in (getattr(scan, 'open_ports_relation', None) or []):
            port_obj = getattr(relation, "port", None)
            open_ports.append({
                "port": {
                    "port": getattr(port_obj, "port", "N/A") if port_obj else "N/A",
                    "protocol": getattr(port_obj, "protocol", "") if port_obj else "",
                },
                "given_use": getattr(relation, "given_use", ""),
                "product": getattr(relation, "product", ""),
                "version": getattr(relation, "version", ""),
                "reason": getattr(relation, "reason", ""),
            })
        
        prompt = self._build_user_prompt(scan_data, open_ports)
        
        tools = [{
            "type": "function",
            "function": {
                "name":        "web_search",
                "description": "Buscar CVEs específicos para versiones exactas de software SOLO si se detectan versiones obsoletas o con vulnerabilidades conocidas documentadas.",
                "parameters": {
                    "type":       "object",
                    "properties": {"query": {"type": "string", "description": "Término de búsqueda CVE específico"}},
                    "required":   ["query"],
                },
            },
        }]
        
        raw_response = None
        for attempt in range(3):
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
                        "num_predict":    2048,
                        "temperature":    0.15,  # Muy bajo para máxima precisión factual
                        "top_p":          0.8,
                        "repeat_penalty": 1.2,
                    },
                )
                
                if getattr(resp.message, "tool_calls", None):
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
                        options  = {"num_predict": 2048, "temperature": 0.15},
                    )
                
                raw_response = resp.message.content.strip()
                if raw_response:
                    break
                    
            except Exception as exc:
                if attempt == 2:
                    raise AIFallbackExhaustedError(3, str(exc))
                time.sleep(1.5 ** attempt)
        
        return self._parse_response(raw_response)

    def _parse_response(self, raw: str) -> dict:
        """Parseo robusto de la respuesta JSON con validación de integridad."""
        if not raw:
            raise AIResponseError("Respuesta vacía del modelo", attempt=attempt)
        
        try:
            result = json.loads(raw)
            
            if isinstance(result.get("recommendations"), list):
                for rec in result["recommendations"]:
                    if not isinstance(rec.get("cve_refs"), list):
                        rec["cve_refs"] = []
                    else:
                        rec["cve_refs"] = [
                            cve for cve in rec["cve_refs"] 
                            if isinstance(cve, str) and re.match(r'^CVE-\d{4}-\d{4,}$', cve)
                        ]
            
            valid_levels = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO"]
            if result.get("risk_level", "").upper() not in valid_levels:
                result["risk_level"] = "INFORMATIVO"
                
            return result
            
        except json.JSONDecodeError:
            pass
        
        for pattern in [r'\{[\s\S]*?\}(?=\s*$)', r'```(?:json)?\s*([\s\S]*?)\s*```']:
            match = re.search(pattern, raw, re.MULTILINE)
            if match:
                try:
                    json_str = match.group(1) if match.groups() else match.group()
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    continue
        
        cleaned = re.sub(r'^[^{]*', '', raw)
        cleaned = re.sub(r'[^}]*$', '', cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            raise ValueError(f"No se pudo parsear la respuesta: {raw[:200]}")


class NiktoAIWriter(AIWriter):
    """AI writer for Nikto scan security analysis.
    
    Generates security analysis for Nikto web vulnerability scans using Ollama.
    Analyzes aggregated findings grouped by security controls rather than
    individual incidents, providing calibrated risk assessments.
    
    The system prompt enforces:
    - Controls over counts (one misconfigured control = one issue)
    - Never escalate risk based on number of findings
    - Distinguish between placeholder SSL certs and real invalid certs
    
    Attributes:
        model: Ollama model name (from env var or default).
        _client: Ollama client instance.
        _prompts: Prompt configuration from SecConfig.json.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        model: Optional[str] = None
    ) -> None:
        """Initialize Nikto AI writer.
        
        Args:
            host: Ollama host (optional, from env var if not provided).
            model: Ollama model name (optional, from env var if not provided).
        """
        super().__init__()
        self._prompts = ConfigReader().get_prompts_config()

    def _preprocess_incidents(self, incidents: list) -> dict:
        """Preprocess incidents by grouping them into security controls.
        
        Args:
            incidents: List of incident dictionaries.
            
        Returns:
            Dictionary with controls and metrics.
        """
        if not incidents:
            return {"error": "No incidents"}
        
        controls = {
            "transport_security": [],
            "session_management": [],
            "information_disclosure": [],
            "client_protection": [],
            "access_control": [],
            "configuration": [],
            "noise": []
        }
        
        seen_patterns = set()
        
        for inc in incidents:
            desc = str(inc.get("description", "")).lower()
            url = str(inc.get("url", ""))
            method = str(inc.get("method", "GET"))
            severity = str(inc.get("severity", "INFO")).upper()
            
            if "hash(" in url or "0x" in url or len(url) > 200:
                controls["noise"].append(inc)
                continue
            
            if any(x in desc for x in ["cookie", "session", "httponly", "secure flag"]):
                controls["session_management"].append(inc)
            elif any(x in desc for x in ["certificate", "ssl", "tls", "https", "cn=", "hostname"]):
                controls["transport_security"].append(inc)
            elif any(x in desc for x in ["x-frame-options", "csp", "content-security", "clickjacking", "xss"]):
                controls["client_protection"].append(inc)
            elif any(x in desc for x in ["method", "put", "delete", "trace", "debug", "options"]):
                controls["access_control"].append(inc)
            elif any(x in desc for x in ["banner", "version", "x-powered-by", "server:", "etag", "inode"]):
                controls["information_disclosure"].append(inc)
            elif any(x in desc for x in ["robots.txt", "directory", "index of", "accessible"]):
                controls["configuration"].append(inc)
            else:
                controls["information_disclosure"].append(inc)
        
        total_valid = sum(len(v) for k, v in controls.items() if k != "noise")
        
        return {
            "controls": controls,
            "metrics": {
                "total_raw": len(incidents),
                "noise_filtered": len(controls["noise"]),
                "effective_findings": total_valid,
                "critical_controls_missing": sum(
                    1 for k, v in controls.items() 
                    if k in ["transport_security", "session_management"] and len(v) > 0
                )
            }
        }

    def _build_system_prompt(self) -> str:
        prompts_config = ConfigReader().get_prompts_config()
        return prompts_config.get("nikto", {}).get("system", "")

    def _build_user_prompt(self, scan_data: dict, processed: dict) -> str:
        target = scan_data.get("target", "desconocido")
        started = scan_data.get("started_at", "N/A")
        metrics = processed.get("metrics", {})
        controls = processed.get("controls", {})

        controls_summary = {}
        for control_name, findings in controls.items():
            if control_name == "noise" or not findings:
                continue

            unique_issues = set()
            for f in findings[:3]:
                desc = f.get("description", "")[:120]
                unique_issues.add(desc)

            controls_summary[control_name] = {
                "instancias_detectadas": len(findings),
                "ejemplos_representativos": list(unique_issues),
                "techo_teorico": self._assess_control_severity(control_name, findings)
            }

        prompts_config = ConfigReader().get_prompts_config()
        template = prompts_config.get("nikto", {}).get("user_template", "")

        return template.replace("{{target}}", str(target)) \
                    .replace("{{started}}", str(started)) \
                    .replace("{{total_raw}}", str(metrics.get("total_raw", 0))) \
                    .replace("{{noise_filtered}}", str(metrics.get("noise_filtered", 0))) \
                    .replace("{{effective_findings}}", str(metrics.get("effective_findings", 0))) \
                    .replace("{{controls_json}}", json.dumps(controls_summary, indent=2, ensure_ascii=False))

    def _assess_control_severity(self, control_name: str, findings: list) -> str:
        """Assess the base severity for a security control.
        
        Args:
            control_name: Name of the security control.
            findings: List of findings for that control.
            
        Returns:
            Base severity string (ALTO, MEDIO, or BAJO).
        """
        severity_map = {
            "transport_security": "ALTO",
            "session_management": "MEDIO",
            "access_control": "MEDIO",
            "client_protection": "BAJO",
            "information_disclosure": "BAJO",
            "configuration": "BAJO"
        }
        return severity_map.get(control_name, "BAJO")

    def generate(self, scan: NiktoScan) -> dict:
        """Generate AI security analysis for a Nikto scan.
        
        Args:
            scan: NiktoScan object with scan data.
            
        Returns:
            Dictionary with keys: executive_summary, risk_level, technical_analysis,
            recommendations, conclusions.
        """
        scan_data = {
            "target": scan.target,
            "started_at": scan.started_at.isoformat() if getattr(scan, 'started_at', None) else "N/A",
        }
        
        incidents = []
        for incident in (getattr(scan, 'incidents', None) or []):
            incidents.append({
                "osvdb_id": getattr(incident, "osvdb_id", None),
                "url": getattr(incident, "url", ""),
                "method": getattr(incident, "method", ""),
                "description": getattr(incident, "description", ""),
                "severity": getattr(incident, "severity", "INFO"),
            })
        
        processed = self._preprocess_incidents(incidents)
        
        if processed["metrics"]["effective_findings"] == 0:
            return {
                "executive_summary": "Escaneo con datos insuficientes o ruido técnico predominante. No se detectaron controles de seguridad evaluables.",
                "risk_level": "INFORMATIVO",
                "technical_analysis": "Los hallazgos del escaneo consisten principalmente en datos corruptos o falsos positivos técnicos (URLs malformadas, referencias de memoria). Se recomienda verificar la configuración del escáner.",
                "recommendations": [],
                "conclusions": "Requiere re-escaneo con configuración adecuada."
            }
        
        prompt = self._build_user_prompt(scan_data, processed)
        
        tools = [{
            "type": "function",
            "function": {
                "name": "web_search",
                "description": "Buscar información sobre configuración segura de certificados SSL o mejores prácticas de headers de seguridad.",
                "parameters": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            },
        }]
        
        raw_response = None
        for attempt in range(3):
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
                        "num_predict": 2048,
                        "temperature": 0.1,
                        "top_p": 0.75,
                        "repeat_penalty": 1.3,
                    },
                )
                raw_response = resp.message.content.strip()
                if raw_response:
                    break
            except Exception as exc:
                if attempt == 2:
                    raise AIFallbackExhaustedError(3, str(exc))
                time.sleep(1.5 ** attempt)
        
        return self._parse_response(raw_response)

    def _parse_response(self, raw: str) -> dict:
        """Parse the AI response JSON with validation.
        
        Args:
            raw: Raw response string from AI.
            
        Returns:
            Parsed response dictionary with normalized risk level.
        """
        if not raw:
            raise AIResponseError("Respuesta vacía", attempt=attempt)
        
        try:
            result = json.loads(raw)
            valid = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO"]
            if result.get("risk_level", "").upper() not in valid:
                result["risk_level"] = "BAJO"
            
            if isinstance(result.get("recommendations"), list):
                for rec in result["recommendations"]:
                    rec["cve_refs"] = []
                    
            return result
        except json.JSONDecodeError:
            return {
                "executive_summary": "Error en análisis de IA",
                "risk_level": "INFORMATIVO",
                "technical_analysis": "No se pudo generar el análisis automático.",
                "recommendations": [],
                "conclusions": "Revisar manualmente los hallazgos brutos."
            }