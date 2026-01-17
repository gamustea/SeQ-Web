import os

from datetime import datetime
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional

from src.misc.configread import ConfigReader, DirectoryType
from src.core.model import NmapScan, NiktoScan, Scan

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    Image,
    PageBreak,
    CondPageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_JUSTIFY


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
        self.color_palette: dict
        self.scan = scan


    @abstractmethod
    def append_body(self, scan, styles, elements):
        pass

    @abstractmethod
    def get_filename_suffix(self) -> str:
        pass

    @abstractmethod
    def get_picture_name(self, dark: bool = True) -> str:
        pass

    @abstractmethod
    def get_report_title(self) -> str:
        pass


class NmapPrintingStrategy(_PrintingStrategy):

    def __init__(self, scan: NmapScan) -> None:
        super().__init__(scan)
        self.color_palette = {
            ColorType.BLACK: "#121212",         # negro neutro cálido para contraste
            ColorType.DARK: "#01375A",          # azul océano más oscuro, derivado del principal
            ColorType.MAIN: "#014F86",          # azul océano (oscuro)
            ColorType.SECONDARY: "#555B6E",     # gris oscuro con matiz azulado
            ColorType.LIGHT: "#4A90E2",         # azul océano claro, derivado del principal
            ColorType.WHITE: "#E1E8F0",         # blanco con tintes azulados, derivado del azul claro
        }

    def append_body(self, scan, styles, elements):
        BLACK_COLOR = self.color_palette[ColorType.BLACK]
        DARK_COLOR = self.color_palette[ColorType.DARK]
        MAIN_COLOR = self.color_palette[ColorType.MAIN]
        SECONDARY_COLOR = self.color_palette[ColorType.SECONDARY]
        LIGHT_COLOR = self.color_palette[ColorType.LIGHT]
        WHITE_COLOR = self.color_palette[ColorType.WHITE]

        # Estilo personalizado para el título
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor(BLACK_COLOR),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )

        # Estilo para subtítulos
        subtitle_style = ParagraphStyle(
            "CustomSubtitle",
            parent=styles["Heading2"],
            fontSize=16,
            textColor=colors.HexColor(MAIN_COLOR),
            spaceAfter=12,
            spaceBefore=12,
            fontName="Helvetica-Bold",
        )

        # Estilo para información general
        info_style = ParagraphStyle(
            "InfoStyle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor(SECONDARY_COLOR),
            spaceAfter=6,
        )

        # === ENCABEZADO ===
        title = Paragraph("Informe de Escaneo Nmap", title_style)
        elements.append(title)

        elements.append(Spacer(1, 0.1 * inch))

        if scan.host:
            host_info = [
                ["Host Analizado:", str(scan.host.ip_address)],
                ["Nombre de Host:", str(scan.host.hostname)],
                ["MAC Address:", str(scan.host.mac_address)],
                ["Vendedor:", str(scan.host.vendor)],
            ]

            host_table = Table(host_info, colWidths=[2 * inch, 4 * inch])
            host_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor(WHITE_COLOR)),
                        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor(MAIN_COLOR)),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                        ("FONTSIZE", (0, 0), (-1, -1), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor(WHITE_COLOR)),
                    ]
                )
            )

            elements.append(host_table)
            elements.append(Spacer(1, 0.1 * inch))

        scan_info = [
            ["ID del Escaneo:", str(scan.id)],
            ["Fecha de inicio:", scan.started_at.strftime("%d/%m/%Y %H:%M:%S")],
            ["Total de Puertos:", str(len(scan.open_ports_relation))],
        ]

        info_table = Table(scan_info, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor(WHITE_COLOR)),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor(MAIN_COLOR)),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor(WHITE_COLOR)),
                ]
            )
        )

        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

        subtitle = Paragraph("Puertos Abiertos Detectados", subtitle_style)
        elements.append(subtitle)
        elements.append(Spacer(1, 0.1 * inch))

        if scan.open_ports_relation:
            port_data = [["#", "Puerto", "Protocolo", "Software", "Versión del Software"]]

            for idx, port in enumerate(scan.open_ports_relation, 1):
                protocol = str(port.port.protocol)
                given_use = str(port.given_use)
                product_name = str(port.product)
                product_version = str(port.version)
                
                port_data.append(
                    [
                        str(idx), 
                        protocol.split("/")[0], 
                        given_use.upper(), 
                        product_name if not product_name == "" else "NO ENCONTRADO", 
                        product_version if not product_version == "" else "N/A"
                    ]
                )

            # Crear tabla de puertos
            port_table = Table(port_data, colWidths=[0.5 * inch, 0.75 * inch, 1.25 * inch, 2 * inch, 2 * inch])
            port_table.setStyle(
                TableStyle(
                    [
                        # Encabezado
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(MAIN_COLOR)),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 11),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("TOPPADDING", (0, 0), (-1, 0), 12),
                        # Cuerpo de la tabla
                        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor(DARK_COLOR)),
                        ("ALIGN", (0, 1), (0, -1), "CENTER"),
                        ("ALIGN", (1, 1), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                        ("FONTSIZE", (0, 1), (-1, -1), 10),
                        ("TOPPADDING", (0, 1), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
                        # Alternar colores de filas
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor(WHITE_COLOR)],
                        ),
                        # Bordes
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor(LIGHT_COLOR)),
                        ("LINEBELOW", (0, 0), (-1, 0), 2, colors.HexColor(MAIN_COLOR)),
                    ]
                )
            )

            elements.append(port_table)
        else:
            no_ports = Paragraph("No se detectaron puertos abiertos.", info_style)
            elements.append(no_ports)

    def get_filename_suffix(self) -> str:
        return "_Nmap.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        picture_name = "SecOps-Logo-Blue"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        return "Análisis de Seguridad de Red"


class OpenVASPrintingStrategy(_PrintingStrategy):

    def __init__(self, scan):
        super().__init__(scan)
        self.color_palette = {
            ColorType.BLACK: "#0D2818",         # verde muy oscuro, casi negro
            ColorType.DARK: "#1B5E20",          # verde bosque oscuro
            ColorType.MAIN: "#2E7D32",          # verde principal
            ColorType.SECONDARY: "#43A047",     # verde medio
            ColorType.LIGHT: "#66BB6A",         # verde claro
            ColorType.WHITE: "#E8F5E9",         # blanco con matiz verde
        }

    def append_body(self, scan, styles, elements):
        BLACK_COLOR = self.color_palette[ColorType.BLACK]
        DARK_COLOR = self.color_palette[ColorType.DARK]
        MAIN_COLOR = self.color_palette[ColorType.MAIN]
        SECONDARY_COLOR = self.color_palette[ColorType.SECONDARY]
        LIGHT_COLOR = self.color_palette[ColorType.LIGHT]
        WHITE_COLOR = self.color_palette[ColorType.WHITE]

        # Estilos personalizados
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor(BLACK_COLOR),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )

        subtitle_style = ParagraphStyle(
            "CustomSubtitle",
            parent=styles["Heading2"],
            fontSize=16,
            textColor=colors.HexColor(MAIN_COLOR),
            spaceAfter=12,
            spaceBefore=12,
            fontName="Helvetica-Bold",
        )

        info_style = ParagraphStyle(
            "InfoStyle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor(SECONDARY_COLOR),
            spaceAfter=6,
        )

        description_style = ParagraphStyle(
            "DescriptionStyle",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor(BLACK_COLOR),
            alignment=TA_JUSTIFY,
            leading=12,
        )

        # === ENCABEZADO ===
        title = Paragraph("Informe de Escaneo OpenVAS", title_style)
        elements.append(title)
        elements.append(Spacer(1, 0.1 * inch))

        # Información del host
        if scan.host:
            host_info = [
                ["Host Analizado:", str(scan.host.ip_address)],
                ["Nombre de Host:", str(scan.host.hostname)]
            ]

            host_table = Table(host_info, colWidths=[2 * inch, 4 * inch])
            host_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor(WHITE_COLOR)),
                        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor(MAIN_COLOR)),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                        ("FONTSIZE", (0, 0), (-1, -1), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor(LIGHT_COLOR)),
                    ]
                )
            )
            elements.append(host_table)
            elements.append(Spacer(1, 0.1 * inch))

        # Información del escaneo
        scan_info = [
            ["ID del Escaneo:", str(scan.id)],
            ["Task ID:", str(scan.task_id)],
            ["Report ID:", str(scan.report_id)],
            ["Fecha de inicio:", scan.started_at.strftime("%d/%m/%Y %H:%M:%S")],
            ["Total de Vulnerabilidades:", str(len(scan.results))],
        ]

        if scan.scan_config_name:
            scan_info.append(["Configuración:", str(scan.scan_config_name)])
        if scan.scanner_name:
            scan_info.append(["Scanner:", str(scan.scanner_name)])

        info_table = Table(scan_info, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor(WHITE_COLOR)),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor(MAIN_COLOR)),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor(LIGHT_COLOR)),
                ]
            )
        )
        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

        # === RESUMEN DE SEVERIDAD ===
        if scan.results:
            severity_counts = {}
            for result in scan.results:
                severity = result.vulnerability.severity_class if result.vulnerability.severity_class else "UNKNOWN"
                severity_counts[severity.upper()] = severity_counts.get(severity, 0) + 1

            if severity_counts:
                subtitle = Paragraph("Resumen de Severidad", subtitle_style)
                elements.append(subtitle)
                elements.append(Spacer(1, 0.1 * inch))

                severity_data = [["Severidad", "Cantidad", "Score Promedio"]]

                severity_colors = {
                    "CRITICAL": colors.HexColor("#8b0000"),
                    "HIGH": colors.HexColor("#c0392b"),
                    "MEDIUM": colors.HexColor("#e67e22"),
                    "LOW": colors.HexColor("#f39c12"),
                    "LOG": colors.HexColor("#3498db"),
                    "UNKNOWN": colors.HexColor("#95a5a6"),
                }

                severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "LOG", "UNKNOWN"]

                for severity in severity_order:
                    if severity in severity_counts:
                        
                        scores = [
                            r.vulnerability.severity_score
                            for r in scan.results
                            if (r.vulnerability.severity_class.upper() == severity or 
                                (not r.vulnerability.severity_class.upper() and severity == "UNKNOWN"))
                            and r.vulnerability.severity_score is not None
                        ]
                        avg_score = sum(scores) / len(scores) if scores else 0.0

                        severity_data.append([
                            severity.upper(),
                            str(severity_counts[severity]),
                            f"{avg_score:.1f}"
                        ])

                severity_table = Table(severity_data, colWidths=[2.5 * inch, 1.5 * inch, 2 * inch])
                severity_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(MAIN_COLOR)),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, 0), 11),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                            ("TOPPADDING", (0, 0), (-1, 0), 12),
                            ("FONTNAME", (0, 1), (-1, -1), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 1), (-1, -1), 10),
                            ("TOPPADDING", (0, 1), (-1, -1), 8),
                            ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor(DARK_COLOR)),
                        ]
                    )
                )
                elements.append(severity_table)
                elements.append(Spacer(1, 0.3 * inch))

        # === VULNERABILIDADES DETECTADAS ===
        elements.append(PageBreak())
        subtitle = Paragraph("Vulnerabilidades Detectadas", subtitle_style)
        elements.append(subtitle)
        elements.append(Spacer(1, 0.1 * inch))

        if scan.results:
            severity_priority = {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
                "LOG": 4,
                "UNKNOWN": 5,
            }

            sorted_results = sorted(
                scan.results,
                key=lambda x: (
                    severity_priority.get(
                        x.vulnerability.severity_class if x.vulnerability.severity_class else "UNKNOWN",
                        5
                    ),
                    -(x.vulnerability.severity_score or 0)
                ),
            )

            for idx, result in enumerate(sorted_results, 1):
                elements.append(CondPageBreak(3 * inch))

                vuln = result.vulnerability
                severity = vuln.severity_class if vuln.severity_class else "UNKNOWN"

                severity_bg_colors = {
                    "CRITICAL": colors.HexColor("#ffcccc"),
                    "HIGH": colors.HexColor("#ffe6cc"),
                    "MEDIUM": colors.HexColor("#fff4cc"),
                    "LOW": colors.HexColor("#e6ffe6"),
                    "LOG": colors.HexColor("#e6f7ff"),
                    "UNKNOWN": colors.HexColor("#f0f0f0"),
                }
                bgcolor = severity_bg_colors.get(severity, colors.HexColor("#f0f0f0"))

                # ENCABEZADO DE LA VULNERABILIDAD
                score_text = f"CVSS: {vuln.cvss_base_score:.1f}" if vuln.cvss_base_score else "CVSS: N/A"
                
                name_style = ParagraphStyle(
                    "VulnName",
                    parent=styles["Normal"],
                    fontName="Helvetica-Bold",
                    fontSize=11,
                    textColor=colors.whitesmoke,
                    alignment=TA_LEFT,
                )
                
                vuln_name_paragraph = Paragraph(str(vuln.name), name_style)
                
                incident_data = [
                    [f"Vulnerabilidad #{idx}", f"Severidad: {severity.upper()} | {score_text}"],
                    [vuln_name_paragraph, ""]
                ]

                incident_header = Table(incident_data, colWidths=[4.5 * inch, 1.5 * inch])
                incident_header.setStyle(
                    TableStyle([
                        # Primera fila (encabezado)
                        ('BACKGROUND', (0, 0), (-1, 0), bgcolor),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor(BLACK_COLOR)),
                        ('ALIGN', (0, 0), (0, 0), 'LEFT'),
                        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('TOPPADDING', (0, 0), (-1, 0), 6),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                        # Segunda fila (nombre de vulnerabilidad)
                        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor(MAIN_COLOR)),
                        ('SPAN', (0, 1), (-1, 1)),
                        ('ALIGN', (0, 1), (-1, 1), 'LEFT'),
                        ('TOPPADDING', (0, 1), (-1, 1), 8),
                        ('BOTTOMPADDING', (0, 1), (-1, 1), 8),
                        ('LEFTPADDING', (0, 1), (-1, 1), 8),
                        # Bordes
                        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor(DARK_COLOR)),
                        ('LINEBELOW', (0, 0), (-1, 0), 1, colors.HexColor(DARK_COLOR)),
                    ])
                )
                elements.append(incident_header)

                # DETALLES TÉCNICOS
                details = [
                    ["NVT OID:", str(vuln.nvt_oid)],
                    ["Host:", str(result.host.ip_address)],
                    ["Detectado:", result.detected_at.strftime("%d/%m/%Y %H:%M:%S")],
                ]

                if vuln.family:
                    details.append(["Familia:", str(vuln.family)])
                if vuln.cvss_vector:
                    details.append(["Vector CVSS:", str(vuln.cvss_vector)])
                if vuln.qod_value:
                    details.append(["QoD:", f"{vuln.qod_value}% ({vuln.qod_type or 'N/A'})"])

                details_table = Table(details, colWidths=[1.5 * inch, 4.5 * inch])
                details_table.setStyle(
                    TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f9f9f9")),
                        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                        ('LEFTPADDING', (0, 0), (-1, -1), 8),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                    ])
                )
                elements.append(details_table)

                # RESUMEN/DESCRIPCIÓN
                if vuln.summary:
                    summary_text = vuln.summary[:500]
                    if len(vuln.summary) > 500:
                        summary_text += "..."
                    summary = [
                        [Paragraph(f"<b>Resumen:</b> {summary_text}", description_style)]
                    ]
                    summary_table = Table(summary, colWidths=[6 * inch])
                    summary_table.setStyle(
                        TableStyle([
                            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                            ('TOPPADDING', (0, 0), (-1, -1), 8),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                            ('LEFTPADDING', (0, 0), (-1, -1), 8),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                        ])
                    )
                    elements.append(summary_table)

                # IMPACTO
                if vuln.impact:
                    impact_text = vuln.impact[:400]
                    if len(vuln.impact) > 400:
                        impact_text += "..."
                    impact = [
                        [Paragraph(f"<b>Impacto:</b> {impact_text}", description_style)]
                    ]
                    impact_table = Table(impact, colWidths=[6 * inch])
                    impact_table.setStyle(
                        TableStyle([
                            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#fff0f0")),
                            ('TOPPADDING', (0, 0), (-1, -1), 8),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                            ('LEFTPADDING', (0, 0), (-1, -1), 8),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                        ])
                    )
                    elements.append(impact_table)

                # SOLUCIÓN
                if vuln.solution:
                    solution_text = vuln.solution[:400]
                    if len(vuln.solution) > 400:
                        solution_text += "..."
                    solution_type_text = f" ({vuln.solution_type})" if vuln.solution_type else ""
                    solution = [
                        [Paragraph(f"<b>Solución{solution_type_text}:</b> {solution_text}", description_style)]
                    ]
                    solution_table = Table(solution, colWidths=[6 * inch])
                    solution_table.setStyle(
                        TableStyle([
                            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(WHITE_COLOR)),
                            ('TOPPADDING', (0, 0), (-1, -1), 8),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                            ('LEFTPADDING', (0, 0), (-1, -1), 8),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                        ])
                    )
                    elements.append(solution_table)

                # REFERENCIAS (CVEs, etc.)
                references_text = []
                if vuln.cve_ids:
                    references_text.append(f"CVE: {vuln.cve_ids}")
                if vuln.cert_refs:
                    references_text.append(f"CERT: {vuln.cert_refs}")
                if vuln.bugtraq_ids:
                    references_text.append(f"BugTraq: {vuln.bugtraq_ids}")
                if vuln.other_refs:
                    references_text.append(f"Otros: {vuln.other_refs}")

                if references_text:
                    ref_combined = " | ".join(references_text)[:400]
                    if len(" | ".join(references_text)) > 400:
                        ref_combined += "..."
                    references = [
                        [Paragraph(f"<b>Referencias:</b> {ref_combined}", description_style)]
                    ]
                    ref_table = Table(references, colWidths=[6 * inch])
                    ref_table.setStyle(
                        TableStyle([
                            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f0f8ff")),
                            ('TOPPADDING', (0, 0), (-1, -1), 8),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                            ('LEFTPADDING', (0, 0), (-1, -1), 8),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                        ])
                    )
                    elements.append(ref_table)

                # Espaciador entre vulnerabilidades
                elements.append(Spacer(1, 0.2 * inch))

        else:
            no_vulns = Paragraph("No se detectaron vulnerabilidades.", info_style)
            elements.append(no_vulns)

    def get_filename_suffix(self) -> str:
        return "_OpenVAS.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        picture_name = "SecOps-Logo-Green"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        return "Análisis de Vulnerabilidades OpenVAS"


class NiktoPrintingStrategy(_PrintingStrategy):

    def __init__(self, scan: NiktoScan):
        super().__init__(scan)
        self.color_palette = {
            ColorType.BLACK: "#4B2500",         # marrón muy oscuro, derivado cálido del naranja
            ColorType.DARK: "#8E3D0A",          # naranja oscuro más intenso, derivado del principal
            ColorType.MAIN: "#C75B12",          # naranja oscuro
            ColorType.SECONDARY: "#FA8072",     # salmón
            ColorType.LIGHT: "#F9B49A",         # salmón claro, derivado del secundario
            ColorType.WHITE: "#FFF5F0",         # blanco con matiz cálido, derivado del naranja claro
        }

    def append_body(self, scan, styles, elements):
        BLACK_COLOR = self.color_palette[ColorType.BLACK]
        DARK_COLOR = self.color_palette[ColorType.DARK]
        MAIN_COLOR = self.color_palette[ColorType.MAIN]
        SECONDARY_COLOR = self.color_palette[ColorType.SECONDARY]
        LIGHT_COLOR = self.color_palette[ColorType.LIGHT]
        WHITE_COLOR = self.color_palette[ColorType.WHITE]

        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor(BLACK_COLOR),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )

        # Estilo para subtítulos
        subtitle_style = ParagraphStyle(
            "CustomSubtitle",
            parent=styles["Heading2"],
            fontSize=16,
            textColor=colors.HexColor(MAIN_COLOR),  # Rojo para vulnerabilidades
            spaceAfter=12,
            spaceBefore=12,
            fontName="Helvetica-Bold",
        )

        # Estilo para información general
        info_style = ParagraphStyle(
            "InfoStyle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor(LIGHT_COLOR),
            spaceAfter=6,
        )

        # Estilo para descripciones
        description_style = ParagraphStyle(
            "DescriptionStyle",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor(BLACK_COLOR),
            alignment=TA_JUSTIFY,
            leading=12,
        )

        # === ENCABEZADO ===
        title = Paragraph("Informe de Escaneo Nikto", title_style)
        elements.append(title)

        # Línea decorativa
        elements.append(Spacer(1, 0.1 * inch))

        if scan.host:
            host_info = [
                ["Host Analizado:", str(scan.host.ip_address)],
                ["Nombre de Host:", str(scan.host.hostname)],
            ]

            host_table = Table(host_info, colWidths=[2 * inch, 4 * inch])
            host_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor(WHITE_COLOR)),
                        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor(MAIN_COLOR)),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                        ("FONTSIZE", (0, 0), (-1, -1), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor(DARK_COLOR)),
                    ]
                )
            )

            elements.append(host_table)
            elements.append(Spacer(1, 0.1 * inch))

        scan_info = [
            ["ID del Escaneo:", str(scan.id)],
            ["Fecha de Inicio:", scan.started_at.strftime("%d/%m/%Y %H:%M:%S") if scan.started_at else "N/A"],  # type: ignore
            ["Total de Incidentes:", str(len(scan.incidents))],
        ]

        info_table = Table(scan_info, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor(WHITE_COLOR)),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor(MAIN_COLOR)),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor(DARK_COLOR)),
                ]
            )
        )

        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

        # === RESUMEN DE SEVERIDAD ===
        if scan.incidents:
            # Contar incidentes por severidad
            severity_counts = {}
            for incident in scan.incidents:
                severity = incident.severity if incident.severity else "unknown"
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Crear tabla de resumen
            if severity_counts:
                subtitle = Paragraph("Resumen de Severidad", subtitle_style)
                elements.append(subtitle)
                elements.append(Spacer(1, 0.1 * inch))

                severity_data = [["Severidad", "Cantidad"]]

                # Definir colores por severidad
                severity_colors = {
                    "CRITICAL": colors.HexColor("#8b0000"),
                    "HIGH": colors.HexColor("#c0392b"),
                    "MEDIUM": colors.HexColor("#e67e22"),
                    "LOW": colors.HexColor("#f39c12"),
                    "UNKNOWN": colors.HexColor("#95a5a6"),
                    "INFO": colors.HexColor("#10DD10"),
                }

                # Orden de prioridad
                severity_order = [
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                    "INFO",
                    "UNKNOWN",
                ]

                for severity in severity_order:
                    if severity in severity_counts:
                        severity_data.append(
                            [severity.upper(), str(severity_counts[severity])]
                        )

                severity_table = Table(severity_data, colWidths=[3 * inch, 2 * inch])
                severity_table.setStyle(
                    TableStyle(
                        [
                            # Encabezado
                            (
                                "BACKGROUND",
                                (0, 0),
                                (-1, 0),
                                colors.HexColor(SECONDARY_COLOR),
                            ),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, 0), 11),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                            ("TOPPADDING", (0, 0), (-1, 0), 12),
                            # Cuerpo
                            ("FONTNAME", (0, 1), (-1, -1), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 1), (-1, -1), 10),
                            ("TOPPADDING", (0, 1), (-1, -1), 8),
                            ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
                            (
                                "GRID",
                                (0, 0),
                                (-1, -1),
                                0.5,
                                colors.HexColor(DARK_COLOR),
                            ),
                        ]
                    )
                )

                elements.append(severity_table)
                elements.append(Spacer(1, 0.3 * inch))

        # === SECCIÓN DE INCIDENTES DETECTADOS ===
        # SECCIÓN DE INCIDENTES DETECTADOS
        subtitle = Paragraph("Incidentes de Seguridad Detectados", subtitle_style)
        elements.append(subtitle)
        elements.append(Spacer(1, 0.1 * inch))
        
        if scan.incidents:
            severity_priority = {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 3,
                "INFO": 4,
                "UNKNOWN": 5,
            }
            sorted_incidents = sorted(
                scan.incidents,
                key=lambda x: severity_priority.get(
                    x.severity if x.severity else "unknown", 5
                ),
            )
            
            for idx, incident in enumerate(sorted_incidents, 1):
                elements.append(CondPageBreak(2.5 * inch))
                
                severity = incident.severity if incident.severity else "unknown"
                severity_colors = {
                    "CRITICAL": colors.HexColor("#ffcccc"),
                    "HIGH": colors.HexColor("#ffe6cc"),
                    "MEDIUM": colors.HexColor("#fff4cc"),
                    "LOW": colors.HexColor("#e6f7ff"),
                    "UNKNOWN": colors.HexColor("#f0f0f0"),
                }
                bgcolor = severity_colors.get(severity, colors.HexColor("#f0f0f0"))
                
                # ENCABEZADO DEL INCIDENTE
                incident_data = [
                    [f"Incidente #{idx}", f"Severidad: {severity.upper() if severity else 'UNKNOWN'}"]
                ]
                
                incident_header = Table(incident_data, colWidths=[3 * inch, 3 * inch])
                incident_header.setStyle(
                    TableStyle([
                        ('BACKGROUND', (0, 0), (-1, -1), bgcolor),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor(BLACK_COLOR)),
                        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('TOPPADDING', (0, 0), (-1, -1), 6),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor(WHITE_COLOR)),
                    ])
                )
                elements.append(incident_header)

                url_style = ParagraphStyle(
                    "UrlStyle",
                    parent=styles["Normal"],
                    fontName="Helvetica",
                    fontSize=9,
                    textColor=colors.HexColor(BLACK_COLOR),
                    wordWrap="CJK",  # CLAVE: Permite cortar la URL en cualquier carácter si es necesario
                    alignment=TA_LEFT
                )
                
                # DETALLES DEL INCIDENTE
                details = []
                if incident.osvdb_id:
                    details.append(["OSVDB ID:", str(incident.osvdb_id)])
                if incident.method:
                    details.append(["Método:", str(incident.method)])
                if incident.url:
                    details.append(["URL:", Paragraph(str(incident.url), url_style)])
                if incident.port:
                    details.append(["Puerto:", str(incident.port)])
                if incident.discovered_at:
                    discovered = incident.discovered_at.strftime("%d/%m/%Y %H:%M:%S")
                    details.append(["Detectado:", discovered])
                
                if details:
                    details_table = Table(details, colWidths=[1.5 * inch, 4.5 * inch])
                    details_table.setStyle(
                        TableStyle([
                            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f9f9f9")),
                            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('TOPPADDING', (0, 0), (-1, -1), 4),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                            ('LEFTPADDING', (0, 0), (-1, -1), 8),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                        ])
                    )
                    elements.append(details_table)
                
                # DESCRIPCIÓN
                if incident.description:
                    desc_text = incident.description[:500]
                    if len(incident.description) > 500:
                        desc_text += "..."
                    description = [
                        [Paragraph(f"<b>Descripción:</b> {desc_text}", description_style)]
                    ]
                    desc_table = Table(description, colWidths=[6 * inch])
                    desc_table.setStyle(
                        TableStyle([
                            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                            ('TOPPADDING', (0, 0), (-1, -1), 8),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                            ('LEFTPADDING', (0, 0), (-1, -1), 8),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                        ])
                    )
                    elements.append(desc_table)
                
                # REFERENCIAS
                if incident.references:
                    ref_text = incident.references[:300]
                    if len(incident.references) > 300:
                        ref_text += "..."
                    references = [
                        [Paragraph(f"<b>Referencias:</b> {ref_text}", description_style)]
                    ]
                    ref_table = Table(references, colWidths=[6 * inch])
                    ref_table.setStyle(
                        TableStyle([
                            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f0f8ff")),
                            ('TOPPADDING', (0, 0), (-1, -1), 8),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                            ('LEFTPADDING', (0, 0), (-1, -1), 8),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                        ])
                    )
                    elements.append(ref_table)
                
                # Espaciador entre incidentes
                elements.append(Spacer(1, 0.2 * inch))
        
        else:
            no_incidents = Paragraph(
                "No se detectaron incidentes de seguridad.", info_style
            )
            elements.append(no_incidents)

    def get_filename_suffix(self) -> str:
        return "_Nikto.pdf"

    def get_picture_name(self, dark: bool = False) -> str:
        picture_name = "SecOps-Logo-Salmon"
        return picture_name + "Dark.png" if dark else picture_name + "Light.png"

    def get_report_title(self) -> str:
        return "Análisis de Vulnerabilidades Web"


class PDFCreator:

    def __init__(self, printing_strategy: _PrintingStrategy) -> None:
        self.config_reader = ConfigReader()
        self.directory = self.config_reader.get_directory_of(DirectoryType.TEMP)
        self.printing_strategy = printing_strategy
        self.scan = printing_strategy.scan

    def set_pdf_metadata(self, doc, scan):
        """Configura metadatos del PDF"""
        doc.title = f"Informe de Seguridad - {scan.id}"
        doc.author = "SecOps Security Team"
        doc.subject = (
            f"Análisis de seguridad realizado el {scan.started_at.strftime('%d/%m/%Y')}"
        )
        doc.creator = "SecOps PDF Generator v1.0"

    def append_cover_page(
        self,
        elements,
        styles,
        title: str = "Análisis de seguridad",
        subtitle: str = "",
        client_name: Optional[str] = None,
        document_type: str = "Informe de Seguridad",
        date: datetime = datetime.now(),
    ):
        """
        Crea una portada profesional usando la paleta de colores de la estrategia actual.

        Args:
            elements: Lista de elementos del PDF donde se añadirá la portada
            styles: Estilos de reportlab
            title: Título principal del documento
            subtitle: Subtítulo opcional
            client_name: Nombre del cliente (opcional)
            document_type: Tipo de documento
            date: Fecha del documento (por defecto, fecha actual)
        """
        if date is None:
            date = datetime.now()

        color_palette = self.printing_strategy.color_palette
        MAIN_COLOR = color_palette[ColorType.MAIN]
        DARK_COLOR = color_palette[ColorType.DARK]
        LIGHT_COLOR = color_palette[ColorType.LIGHT]
        WHITE_COLOR = color_palette[ColorType.WHITE]
        BLACK_COLOR = color_palette[ColorType.BLACK]

        self.append_logo(elements, is_cover=True)

        doc_type_style = ParagraphStyle(
            "CoverDocType",
            parent=styles["Normal"],
            fontSize=12,
            textColor=colors.HexColor(MAIN_COLOR),
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
            letterSpacing=2,
        )
        elements.append(Paragraph(document_type.upper(), doc_type_style))
        elements.append(Spacer(1, 0.3 * inch))

        title_style = ParagraphStyle(
            "CoverTitle",
            parent=styles["Heading1"],
            fontSize=32,
            textColor=colors.HexColor(WHITE_COLOR),
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
            leading=38,
        )

        title_paragraph = Paragraph(title, title_style)
        title_table = Table([[title_paragraph]], colWidths=[6 * inch])
        title_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(MAIN_COLOR)),
                    ("TOPPADDING", (0, 0), (-1, -1), 20),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 20),
                    ("LEFTPADDING", (0, 0), (-1, -1), 20),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 20),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        elements.append(title_table)

        if subtitle:
            elements.append(Spacer(1, 0.3 * inch))
            subtitle_style = ParagraphStyle(
                "CoverSubtitle",
                parent=styles["Normal"],
                fontSize=14,
                textColor=colors.HexColor(DARK_COLOR),
                alignment=TA_CENTER,
                fontName="Helvetica",
            )
            elements.append(Paragraph(subtitle, subtitle_style))

        elements.append(Spacer(1, 1.5 * inch))

        info_style = ParagraphStyle(
            "CoverInfo",
            parent=styles["Normal"],
            fontSize=11,
            textColor=colors.HexColor(BLACK_COLOR),
            alignment=TA_CENTER,
            fontName="Helvetica",
        )

        info_data = []
        if client_name:
            info_data.append(["Cliente:", client_name])
        info_data.append(["Fecha:", date.strftime("%d/%m/%Y")])

        info_table = Table(info_data, colWidths=[1.5 * inch, 3 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(WHITE_COLOR)),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor(MAIN_COLOR)),
                    ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor(BLACK_COLOR)),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 11),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor(LIGHT_COLOR)),
                ]
            )
        )
        elements.append(info_table)

        # Barra decorativa inferior
        elements.append(Spacer(1, 1 * inch))
        decoration_table = Table([[""]], colWidths=[6 * inch], rowHeights=[0.1 * inch])
        decoration_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(LIGHT_COLOR)),
                ]
            )
        )
        elements.append(decoration_table)

        # Salto de página después de la portada
        elements.append(PageBreak())

    def append_consent(self, elements, color_palette: dict):
        elements.append(PageBreak())

        # Estilo para el texto de consentimiento
        consent_style = ParagraphStyle(
            "ConsentStyle",
            fontSize=9,
            textColor=colors.HexColor(color_palette[ColorType.DARK]),
            alignment=TA_JUSTIFY,
            leading=12,
            spaceBefore=6,
            spaceAfter=6,
        )

        # Título de la sección
        consent_title_style = ParagraphStyle(
            "ConsentTitle",
            fontSize=11,
            textColor=colors.HexColor(color_palette[ColorType.MAIN]),
            spaceAfter=8,
            fontName="Helvetica-Bold",
        )

        consent_title = Paragraph(
            "DECLARACIÓN DE CONFORMIDAD Y CONSENTIMIENTO", consent_title_style
        )
        elements.append(consent_title)

        # Texto de consentimiento
        consent_text = """
        El usuario declara y confirma que ha otorgado su consentimiento expreso e 
        inequívoco para la realización del escaneo de seguridad sobre el sitio web 
        y/o sistema informático objeto del presente informe. El usuario acepta y 
        reconoce que es el titular legítimo o cuenta con la autorización necesaria 
        de los equipos, sistemas y redes escaneados.
        <br/><br/>
        El usuario asume la plena responsabilidad sobre las consecuencias derivadas 
        del escaneo realizado, incluyendo cualquier resultado, hallazgo o 
        vulnerabilidad identificada en el proceso. Asimismo, el usuario exonera 
        de toda responsabilidad a los ejecutores del análisis de seguridad respecto 
        al uso que se haga de la información contenida en este documento.
        <br/><br/>
        Este documento contiene información sensible de carácter confidencial y 
        debe ser tratado con las medidas de seguridad apropiadas conforme a la 
        normativa vigente en materia de protección de datos.
        """

        consent_paragraph = Paragraph(consent_text, consent_style)

        # Tabla para el texto de consentimiento con fondo destacado
        consent_table = Table([[consent_paragraph]], colWidths=[6 * inch])
        consent_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        colors.HexColor(color_palette[ColorType.WHITE]),
                    ),
                    ("TOPPADDING", (0, 0), (-1, -1), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                    ("LEFTPADDING", (0, 0), (-1, -1), 12),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        1.5,
                        colors.HexColor(color_palette[ColorType.MAIN]),
                    ),
                ]
            )
        )

        elements.append(consent_table)
        elements.append(Spacer(1, 0.3 * inch))

    def append_logo(self, elements, is_cover: bool = False):
        """
        Añade el logo al documento. El tamaño y posicionamiento dependen de si es portada o no.

        Args:
            elements: Lista de elementos del PDF donde se añadirá el logo
            is_cover: Si True, muestra el logo centrado y grande para portada.
                    Si False, muestra el logo pequeño alineado a la izquierda (comportamiento original)
        """
        resource_directory = self.config_reader.get_directory_of(DirectoryType.RESOURCE)
        picture_name = self.printing_strategy.get_picture_name()
        image_filename = f"{resource_directory}/{picture_name}"

        if os.path.exists(image_filename):
            try:
                if is_cover:
                    # LOGO PARA PORTADA: centrado y más grande
                    logo = Image(image_filename, width=3 * inch, height=3 * inch)
                    logo.hAlign = "CENTER"
                    elements.append(logo)
                    elements.append(Spacer(1, 0.3 * inch))
                else:
                    # LOGO PARA CONTENIDO: pequeño y alineado a la izquierda (original)
                    logo = Image(image_filename, width=1.4 * inch, height=1.4 * inch)
                    logo.hAlign = "LEFT"
                    elements.append(logo)
                    elements.append(Spacer(1, 0.1 * inch))
            except Exception as e:
                print(f"Error al cargar la imagen: {e}")

    def append_footer(self, elements, styles):
        footer_style = ParagraphStyle(
            "Footer",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#cfcfcf"),
            alignment=TA_CENTER,
        )

        footer = Paragraph(
            f"Generado automáticamente | {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            footer_style,
        )
        elements.append(footer)

    def print_pdf(self):
        os.makedirs(self.directory, exist_ok=True)

        directory = self.directory
        id = self.scan.id
        suffix = self.printing_strategy.get_filename_suffix()
        filename = f"{directory}/{id}{suffix}"

        # Crear el documento
        doc = SimpleDocTemplate(
            filename,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        # Contenedor para los elementos del PDF
        elements = []

        # Estilos
        styles = getSampleStyleSheet()

        self.append_cover_page(
            elements=elements,
            styles=styles,
            title=self.printing_strategy.get_report_title(),
        )

        self.append_logo(elements)
        self.printing_strategy.append_body(scan=self.scan, styles=styles, elements=elements)

        # Espaciador final
        elements.append(Spacer(1, 0.5 * inch))

        self.append_consent(elements, self.printing_strategy.color_palette)
        self.append_footer(elements, styles)

        # Construir el PDF
        self.set_pdf_metadata(doc=doc, scan=self.scan)

        doc.build(elements)

        return filename
