# -*- coding: utf-8 -*-
import os
from datetime import datetime
from abc import ABC, abstractmethod
from enum import Enum
import random
from typing import Optional, Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    Image,
    PageBreak,
    CondPageBreak,  # <- IMPORTANTE
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

from src.misc.configread import ConfigReader, DirectoryType
from src.core.model import NmapScan, NiktoScan, Scan, Host

from dataclasses import dataclass, field
from datetime import datetime, timezone

import ollama

from src.core.model import Topic
from src.misc.logging import SecOpsLogger

# ----------------------------------------------------------------------
# Colores y estrategia base
# ----------------------------------------------------------------------

class ColorType(Enum):
    BLACK = "black"
    DARK = "dark"
    MAIN = "main"
    SECONDARY = "secondary"
    LIGHT = "light"
    WHITE = "white"


class _PrintingStrategy(ABC):
    def __init__(self, scan: Scan) -> None:
        super().__init__()
        self.scan = scan
        self.color_palette: Dict[ColorType, str] = {}

    @abstractmethod
    def append_body(self, theme: "ReportTheme", elements: list) -> None:
        """Añade el cuerpo específico del informe (propio de cada herramienta)."""
        ...

    @abstractmethod
    def get_filename_suffix(self) -> str:
        ...

    @abstractmethod
    def get_picture_name(self, dark: bool = True) -> str:
        ...

    @abstractmethod
    def get_report_title(self) -> str:
        ...


class ReportTheme:
    def __init__(self, base_styles, palette):
        self.palette = palette
        self.styles = base_styles

        main = colors.HexColor(palette[ColorType.MAIN])
        light = colors.HexColor(palette[ColorType.LIGHT])
        white = colors.HexColor(palette[ColorType.WHITE])
        black = colors.HexColor(palette[ColorType.BLACK])

        self._accent_color = light

        # Título principal de sección
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

        # Subtítulo (con mayúsculas espaciadas)
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

        # Texto info / metadatos
        self.pill = ParagraphStyle(
            "Pill",
            parent=base_styles["Normal"],
            fontSize=7,
            leading=9,
            textColor=white,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )

        # Cuerpo
        self.body = ParagraphStyle(
            "Body",
            parent=base_styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=black,
            alignment=TA_JUSTIFY,
            spaceAfter=5,
        )

        # Pequeño label en mayúsculas
        self.label = ParagraphStyle(
            "Label",
            parent=base_styles["Normal"],
            fontSize=7,
            leading=9,
            textColor=main,
            alignment=TA_LEFT,
            fontName="Helvetica-Bold",
        )

        # “Píldora” de severidad u origen (NMAP / OPENVAS / NIKTO)
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

        # Estilo de tabla key-value
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
        t = Table(data, colWidths=col_widths)
        t.setStyle(self.kv_table_style)
        return t

    def section_header(self, title_text: str, tag_text: str) -> list:
        """
        Devuelve [píldora centrada, título centrado, línea de acento].
        """
        main = colors.HexColor(self.palette[ColorType.MAIN])
        accent = self._accent_color

        # Píldora centrada
        pill_para = Paragraph(tag_text.upper(), self.pill)
        pill_table = Table([[pill_para]], colWidths=[1.2 * inch])
        pill_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), main),
            ("BOX", (0, 0), (-1, -1), 0.7, main),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
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
        ]))
        divider_wrapper = Table([[divider]], colWidths=[6 * inch])
        divider_wrapper.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
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
        ]))

        content = Table([[inner_flowables]], colWidths=[5.8 * inch])
        content.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))

        outer = Table([[band, content]], colWidths=[0.12 * inch, 5.88 * inch])
        outer.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.7, border),
            ("BACKGROUND", (0, 0), (-1, -1), white),
        ]))
        return outer

# ----------------------------------------------------------------------
# PDFCreator con maquetación más profesional
# ----------------------------------------------------------------------

class PDFCreator:
    def __init__(self, printing_strategy: _PrintingStrategy) -> None:
        self.config_reader = ConfigReader()
        self.directory = self.config_reader.get_directory_of(DirectoryType.TEMP)
        self.printing_strategy = printing_strategy
        self.scan = printing_strategy.scan

    def _set_pdf_metadata(self, doc) -> None:
        scan = self.scan
        started = getattr(scan, "started_at", None)
        date_str = started.strftime("%d/%m/%Y") if started else datetime.now().strftime("%d/%m/%Y")
        doc.title = f"Informe de Seguridad - {scan.id}"
        doc.author = "SecOps Security Team"
        doc.subject = f"Análisis de seguridad realizado el {date_str}"
        doc.creator = "SecOps PDF Generator v2.0"

    # Cabecera/pie reales, con numeración de página
    def _on_page(self, canv, doc):
        canv.saveState()
        width, height = A4

        palette = self.printing_strategy.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])

        # Barra lateral izquierda
        canv.setFillColor(main)
        canv.rect(20, 20, 6, height - 40, stroke=0, fill=1)

        # Logo / nombre corto arriba
        canv.setFont("Helvetica-Bold", 9)
        canv.setFillColor(dark)
        canv.drawString(40, height - 30, "SecOps Security Report")

        # Línea superior muy fina
        canv.setStrokeColor(colors.HexColor("#e0e0e0"))
        canv.setLineWidth(0.5)
        canv.line(36, height - 42, width - 36, height - 42)

        # Número de página
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
        if date is None:
            date = datetime.now()

        palette = theme.palette
        main = colors.HexColor(palette[ColorType.MAIN])
        light = colors.HexColor(palette[ColorType.LIGHT])
        white = colors.HexColor(palette[ColorType.WHITE])
        black = colors.HexColor(palette[ColorType.BLACK])

        self.append_logo(elements, is_cover=True)

        # Tipo de documento
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

        # Título en bloque de color
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
        resource_directory = self.config_reader.get_directory_of(DirectoryType.RESOURCE)
        picture_name = self.printing_strategy.get_picture_name()
        image_filename = os.path.join(resource_directory, picture_name)

        if not os.path.exists(image_filename):
            return  # De forma silenciosa; podrías loguear en un logger central

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
        # Pie “de contenido”: texto genérico al final del informe
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        footer_text = f"Informe generado automáticamente | {timestamp}"
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph(footer_text, theme.footer))

    def print_pdf(self, client_name: Optional[str] = None) -> str:
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

        # Portada
        self.append_cover_page(
            elements=elements,
            theme=theme,
            title=self.printing_strategy.get_report_title(),
            client_name=client_name,
        )

        # Logo y cuerpo del informe
        self.append_logo(elements, is_cover=False)
        self.printing_strategy.append_body(theme=theme, elements=elements)

        # Consentimiento y pie
        self.append_consent(elements, theme)
        self.append_footer(elements, theme)

        # Generación final
        self._set_pdf_metadata(doc)
        doc.build(elements, onFirstPage=self._on_page, onLaterPages=self._on_page)

        return filename


class NmapPrintingStrategy(_PrintingStrategy):
    def __init__(self, scan: NmapScan) -> None:
        super().__init__(scan)
        # Misma paleta que tenías antes
        self.color_palette = {
            ColorType.BLACK: "#121212",    # negro neutro cálido
            ColorType.DARK: "#01375A",     # azul océano más oscuro
            ColorType.MAIN: "#014F86",     # azul océano principal
            ColorType.SECONDARY: "#555B6E",
            ColorType.LIGHT: "#4A90E2",
            ColorType.WHITE: "#E1E8F0",
        }

    def append_body(self, theme: "ReportTheme", elements: list) -> None:
        scan = self.scan
        palette = self.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])
        light = colors.HexColor(palette[ColorType.LIGHT])

        # Título interno
        elements.append(Paragraph("Informe de Escaneo Nmap", theme.title))
        elements.append(Spacer(1, 0.1 * inch))

        # Información del host
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

        # Información general del escaneo
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

        # Sección de puertos abiertos
        elements.append(Paragraph("Puertos abiertos detectados", theme.subtitle))
        elements.append(Spacer(1, 0.1 * inch))

        open_ports = getattr(scan, "open_ports_relation", [])
        if not open_ports:
            elements.append(Paragraph("No se detectaron puertos abiertos.", theme.info))
            return

        # Cabecera tabla
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
            # Encabezado
            ("BACKGROUND", (0, 0), (-1, 0), main),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            # Cuerpo
            ("BACKGROUND", (0, 1), (-1, -1), white),
            ("TEXTCOLOR", (0, 1), (-1, -1), dark),
            ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("ALIGN", (1, 1), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 9),
            ("TOPPADDING", (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
            # Zebra
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, white]),
            # Bordes
            ("GRID", (0, 0), (-1, -1), 0.4, light),
            ("LINEBELOW", (0, 0), (-1, 0), 1.2, main),
        ]))
        elements.append(port_table)

    def get_filename_suffix(self) -> str:
        return "_Nmap.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        picture_name = "SecOps-Logo-Blue"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        return "Análisis de Seguridad de Red"


class OpenVASPrintingStrategy(_PrintingStrategy):
    def __init__(self, scan) -> None:
        super().__init__(scan)
        self.color_palette = {
            ColorType.BLACK: "#0D2818",
            ColorType.DARK: "#1B5E20",
            ColorType.MAIN: "#2E7D32",
            ColorType.SECONDARY: "#43A047",
            ColorType.LIGHT: "#66BB6A",
            ColorType.WHITE: "#E8F5E9",
        }

    def append_body(self, theme: "ReportTheme", elements: list) -> None:
        scan = self.scan
        palette = self.color_palette
        main = colors.HexColor(palette[ColorType.MAIN])
        dark = colors.HexColor(palette[ColorType.DARK])
        white = colors.HexColor(palette[ColorType.WHITE])

        # Título interno
        elements.append(Paragraph("Informe de Escaneo OpenVAS", theme.title))
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
        return "_OpenVAS.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        picture_name = "SecOps-Logo-Green"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        return "Análisis de Vulnerabilidades OpenVAS"


class NiktoPrintingStrategy(_PrintingStrategy):
    def __init__(self, scan: NiktoScan) -> None:
        super().__init__(scan)
        self.color_palette = {
            ColorType.BLACK: "#4B2500",
            ColorType.DARK: "#8E3D0A",
            ColorType.MAIN: "#C75B12",
            ColorType.SECONDARY: "#FA8072",
            ColorType.LIGHT: "#F9B49A",
            ColorType.WHITE: "#FFF5F0",
        }

    def append_body(self, theme: "ReportTheme", elements: list) -> None:
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

    def get_filename_suffix(self) -> str:
        return "_Nikto.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        picture_name = "SecOps-Logo-Salmon"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        return "Análisis de Vulnerabilidades Web"


@dataclass
class AegisContent:
    """Resultado estructurado de generate_content."""
    topic_id: int
    topic_title: str
    body: str          # Markdown
    language: str
    company: str
    generated_at: str  # ISO-8601 UTC
    topic_note: str


class AegisAIWriter:
    """Responsable solo de generar contenido usando IA (Ollama)."""

    def __init__(self, host: str, model: str, logger: SecOpsLogger):
        self.host = host
        self.model = model
        self.logger = logger

    def _web_search(self, query: str, max_results: int = 5) -> str:
        try:
            from duckduckgo_search import DDGS

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
    ) -> str:
        company  = tweaks.get("company",       "la empresa destinataria")
        sector   = tweaks.get("sector",        "")
        audience = tweaks.get("audienceLevel", "mixed")
        brands   = ", ".join(tweaks.get("associatedBrands", []))
        contact  = tweaks.get("mentionContact", "")
        language = tweaks.get("language",      "es")
        tone     = tweaks.get("tone",          "formal")
        focus    = tweaks.get("topicFocus",    "")

        audience_label = {
            "technical":     "técnico (conocimiento avanzado de seguridad)",
            "mixed":         "mixto (empleados técnicos y no técnicos)",
            "non-technical": "no técnico (empleados de negocio sin perfil IT)",
        }.get(audience, audience)

        context_parts = [f"- Empresa destinataria: {company}"]
        if sector:  context_parts.append(f"- Sector de actividad: {sector}")
        if brands:  context_parts.append(f"- Tecnologías y herramientas en uso: {brands}")
        if focus:   context_parts.append(f"- Enfoque específico solicitado: {focus}")
        if contact: context_parts.append(f"- Contacto de referencia para el lector: {contact}")
        context_parts += [
            f"- Perfil de la audiencia: {audience_label}",
            f"- Tono: {tone}",
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

        role_block = (
            f"Eres un redactor senior especializado en comunicación de ciberseguridad corporativa. "
            f"Tu trabajo es producir píldoras de concienciación en {language.upper()} "
            f"para empleados de empresas españolas, adaptadas al perfil y contexto de cada cliente. "
            f"Escribes de forma clara, directa y práctica: explicas el riesgo, das contexto real "
            f"y ofreces pasos concretos que el empleado puede aplicar de inmediato. "
            f"Nunca usas jerga técnica innecesaria con audiencias no técnicas. "
            f"REGLA ABSOLUTA: empieza a escribir el documento directamente en la primera línea, "
            f"sin preámbulos ni frases introductorias como 'A continuación...', 'En esta píldora...'. "
            f"NUNCA respondas en otro idioma distinto a {language.upper()}."
        )

        example = (
            "# Píldora de concienciación:\n"
            "**Borra bien la información**\n\n"
            "La información sensible de la empresa no solo está en el contenido visible de los "
            "documentos. Los metadatos —características ocultas de un fichero— y una eliminación "
            "incorrecta de archivos pueden exponer datos críticos sin que te des cuenta. "
            "Aquí tienes algunos consejos para proteger adecuadamente la información:\n\n"
            "- **No compartas capturas de pantalla sin revisarlas antes.** Además del contenido "
            "principal, pueden verse nombres de usuario, rutas de archivos u otras ventanas abiertas "
            "que revelen información corporativa.\n"
            "- **Borrar un archivo y vaciar la papelera no es suficiente.** Los datos siguen siendo "
            "recuperables con herramientas especializadas. Para información sensible, usa aplicaciones "
            "de borrado seguro como [Eraser](https://www.incibe.es/ciudadania/herramientas/eraser).\n"
            "- **Antes de deshacerte de un dispositivo, elimina su contenido de forma segura** "
            "o, si es necesario, destruye físicamente el soporte.\n"
            "- **Los documentos en papel también requieren tratamiento adecuado.** No los tires a la "
            "basura común; usa las destructoras o los contenedores de documentación confidencial "
            "que la empresa pone a tu disposición.\n"
            "- **Los metadatos revelan más de lo que crees.** Cada documento contiene información "
            "oculta: autor, fecha de creación, historial de cambios e incluso comentarios eliminados. "
            "Revísalos y límpialos antes de compartir documentos fuera de la organización.\n\n"
            "Si tienes dudas sobre cómo eliminar información de algún dispositivo o soporte, "
            "consúltalo con ciberseguridad@emesa.com. Un error en el proceso puede dejar expuesta "
            "información que creías eliminada.\n\n"
            "Para quienes quieran ampliar el tema, pueden acceder a esta "
            "[guía de INCIBE](https://www.incibe.es/sites/default/files/contenidos/guias/doc/"
            "guia_ciberseguridad_borrado_seguro_metad_0.pdf) sobre borrado seguro de la información."
        )

        format_instruction = (
            "╔══════════════════════════════════════════════════════════════╗\n"
            "║           TAREA: PÍLDORA DE CONCIENCIACIÓN FINAL            ║\n"
            "╚══════════════════════════════════════════════════════════════╝\n\n"
            f"Escribe en {language.upper()} una píldora de concienciación corporativa en Markdown, "
            "lista para distribuir a los empleados. El documento debe poder enviarse tal cual, "
            "sin ninguna edición posterior.\n\n"
            "ESTRUCTURA OBLIGATORIA:\n\n"
            "1. ENCABEZADO\n"
            "   Línea 1: '# Píldora de concienciación:'\n"
            "   Línea 2: subtítulo en negrita con un título atractivo y directo.\n\n"
            "2. PÁRRAFO INTRODUCTORIO (3-5 frases)\n"
            "   - Contextualiza el riesgo y explica por qué importa a los empleados de esta empresa.\n"
            "   - Si el sector o las tecnologías tienen relación con el tema, mencíonalo.\n"
            "   - Anticipa el tipo de consejos que vendrán.\n\n"
            "3. LISTA DE CONSEJOS (5-7 bullets)\n"
            "   Cada bullet debe:\n"
            "   a) Empezar con la acción o el riesgo en negrita.\n"
            "   b) Desarrollar en 2-3 frases el motivo y la consecuencia real si no se aplica.\n"
            "   c) Incluir, si existe, una herramienta o recurso con enlace Markdown.\n"
            "   d) Estar en segunda persona y ser aplicable sin conocimientos técnicos.\n\n"
            "4. FRASE DE CIERRE\n"
            "   - Llamada a la acción clara.\n"
            + (f"   - Incluye el contacto de referencia: {contact}\n" if contact else "") +
            "   - Opcional: enlace a guía externa de ampliación.\n\n"
            "CRITERIOS DE CALIDAD:\n"
            "- Longitud: entre 350 y 550 palabras.\n"
            "- Tono cercano pero profesional.\n"
            "- Sin tecnicismos para audiencia no técnica.\n"
            "- No reproduzcas ninguna frase del ejemplo.\n\n"
            "--- EJEMPLO DE REFERENCIA (imita estructura, tono y extensión; NO copies el contenido) ---\n"
            f"{example}\n"
            "--- FIN DEL EJEMPLO ---"
        )

        prompt_parts = [role_block]
        if reference:
            prompt_parts.append(
                "Píldoras reales publicadas anteriormente por este cliente "
                "(imita su estilo, tono y extensión):\n\n"
                "━━━ PÍLDORAS DE REFERENCIA ━━━\n"
                + reference +
                "\n━━━ FIN DE LAS REFERENCIAS ━━━"
            )
        prompt_parts += [
            f"CONTEXTO DEL CLIENTE:\n{context_block}",
            f"TEMA A DESARROLLAR:\n{topic_block}",
            format_instruction,
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

        # 1ª llamada
        try:
            resp = client.chat(
                model=self.model,
                messages=messages,
                tools=tools,
                options={"num_predict": 4096, "temperature": 0.7},
            )
        except ollama.ResponseError as e:
            self.logger.error(f"Ollama ResponseError (1ª llamada): {e}")
            raise RuntimeError(f"Error del modelo: {e}") from e
        except Exception as e:
            self.logger.error(f"Error conectando Ollama en {self.host}: {e}")
            raise RuntimeError(f"No se pudo conectar con Ollama en {self.host}") from e

        # tool calling
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

            # 2ª llamada
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

    # --- API pública ---------------------------------------------------

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
        """Genera el cuerpo Markdown de una píldora."""
        prompt = self._build_prompt(topic, resolved_topic_id, reference, tweaks)
        self.logger.info(
            f"AegisAIWriter generando píldora | topic_id={resolved_topic_id} "
            f"| modelo={self.model}"
        )
        body = self._call_ollama(prompt)

        return AegisContent(
            topic_id=resolved_topic_id,
            topic_title=topic_title,
            body=body,
            language=tweaks.get("language", "es"),
            company=tweaks.get("company", "la empresa destinataria"),
            generated_at=datetime.now(timezone.utc).isoformat(),
            topic_note=topic_note,
        )


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
