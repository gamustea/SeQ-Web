import os

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

from src.misc.configread import ConfigReader
from src.model import NmapScan

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
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
from datetime import datetime


class PDFCreator:
    def __init__(self) -> None:
        self.directory = ConfigReader().get_directory_of("tempdir")  # type: ignore

    def print_nmap_pdf(self, scan: NmapScan):
        # Crear el directorio si no existe
        os.makedirs(self.directory, exist_ok=True)

        filename = f"{self.directory}/{scan.id}_NmapScan.pdf"

        # Crear el documento
        doc = SimpleDocTemplate(
            filename,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )

        # Contenedor para los elementos del PDF
        elements = []

        # Estilos
        styles = getSampleStyleSheet()

        # Estilo personalizado para el título
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#1a1a1a"),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        )

        # Estilo para subtítulos
        subtitle_style = ParagraphStyle(
            "CustomSubtitle",
            parent=styles["Heading2"],
            fontSize=16,
            textColor=colors.HexColor("#2c3e50"),
            spaceAfter=12,
            spaceBefore=12,
            fontName="Helvetica-Bold",
        )

        # Estilo para información general
        info_style = ParagraphStyle(
            "InfoStyle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#555555"),
            spaceAfter=6,
        )

        # === ENCABEZADO ===
        title = Paragraph("Informe de Escaneo Nmap", title_style)
        elements.append(title)

        # Línea decorativa
        elements.append(Spacer(1, 0.1 * inch))

        # Información del escaneo
        scan_info = [
            ["ID del Escaneo:", str(scan.id)],
            ["Fecha:", datetime.now().strftime("%d/%m/%Y %H:%M:%S")],
            ["Total de Puertos:", str(len(scan.open_ports_relation))],
        ]

        info_table = Table(scan_info, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8f4f8")),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#2c3e50")),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                ]
            )
        )

        elements.append(info_table)
        elements.append(Spacer(1, 0.3 * inch))

        # === SECCIÓN DE PUERTOS ABIERTOS ===
        subtitle = Paragraph("Puertos Abiertos Detectados", subtitle_style)
        elements.append(subtitle)
        elements.append(Spacer(1, 0.1 * inch))

        # Preparar datos para la tabla de puertos
        if scan.open_ports_relation:
            port_data = [["#", "Puerto", "Protocolo"]]

            for idx, port in enumerate(scan.open_ports_relation, 1):
                # Separar puerto y protocolo (formato: "80/tcp")
                protocol_str = str(port.port.protocol)
                if "/" in protocol_str:
                    port_num, protocol_type = protocol_str.split("/", 1)
                else:
                    port_num = protocol_str
                    protocol_type = "N/A"

                port_data.append([str(idx), port_num, protocol_type.upper()])

            # Crear tabla de puertos
            port_table = Table(port_data, colWidths=[0.5 * inch, 2 * inch, 2 * inch])
            port_table.setStyle(
                TableStyle(
                    [
                        # Encabezado
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 11),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("TOPPADDING", (0, 0), (-1, 0), 12),
                        # Cuerpo de la tabla
                        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#333333")),
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
                            [colors.white, colors.HexColor("#f9f9f9")],
                        ),
                        # Bordes
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                        ("LINEBELOW", (0, 0), (-1, 0), 2, colors.HexColor("#2c3e50")),
                    ]
                )
            )

            elements.append(port_table)
        else:
            no_ports = Paragraph("No se detectaron puertos abiertos.", info_style)
            elements.append(no_ports)

        # Espaciador final
        elements.append(Spacer(1, 0.5 * inch))

        # Pie de página informativo
        footer_style = ParagraphStyle(
            "Footer",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#888888"),
            alignment=TA_CENTER,
        )

        footer = Paragraph(
            f"Generado automáticamente | {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            footer_style,
        )
        elements.append(footer)

        # Construir el PDF
        doc.build(elements)

        return filename
