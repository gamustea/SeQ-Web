import os

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

from src.misc.configread import ConfigReader, DirectoryType
from src.model import NmapScan, NiktoScan

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
from reportlab.lib.enums import TA_JUSTIFY
from datetime import datetime


def append_logo(elements, image_filename: str):
    # Verificar si el archivo existe antes de intentar cargarlo
    if os.path.exists(image_filename):
        try:
            logo = Image(image_filename, width=1 * inch, height=1 * inch)
            logo.hAlign = "LEFT"
            elements.append(logo)
            elements.append(Spacer(1, 0.1 * inch))
        except Exception as e:
            print(f"Error al cargar la imagen: {e}")


def append_consent(elements, main_color):
    # Estilo para el texto de consentimiento
    consent_style = ParagraphStyle(
        "ConsentStyle",
        fontSize=9,
        textColor=colors.HexColor("#333333"),
        alignment=TA_JUSTIFY,
        leading=12,
        spaceBefore=6,
        spaceAfter=6,
    )

    # Título de la sección
    consent_title_style = ParagraphStyle(
        "ConsentTitle",
        fontSize=11,
        textColor=colors.HexColor(main_color),
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
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff9e6")),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor(main_color)),
            ]
        )
    )

    elements.append(consent_table)
    elements.append(Spacer(1, 0.3 * inch))


class PDFCreator:
    def __init__(self) -> None:
        self.config_reader = ConfigReader()
        self.directory = self.config_reader.get_directory_of(DirectoryType.TEMP)  # type: ignore

    def print_nmap_pdf(self, scan: NmapScan):
        # Crear el directorio si no existe
        os.makedirs(self.directory, exist_ok=True)

        filename = f"{self.directory}/{scan.id}_NmapScan.pdf"

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

        image_filename = f"{self.config_reader.get_directory_of(DirectoryType.RESOURCE)}/SecOps-Logo-BlueLight.png"
        append_logo(elements, image_filename)

        # === ENCABEZADO ===
        title = Paragraph("Informe de Escaneo Nmap", title_style)
        elements.append(title)

        # Línea decorativa
        elements.append(Spacer(1, 0.1 * inch))

        # Información del escaneo
        scan_info = [
            ["ID del Escaneo:", str(scan.id)],
            ["Fecha de inicio:", scan.started_at.strftime("%d/%m/%Y %H:%M:%S")],
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

        append_consent(elements, "#2c3e50")

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

    def print_nikto_pdf(self, scan: NiktoScan):
        """
        Genera un PDF profesional con los resultados de un escaneo Nikto.

        Args:
            scan: Instancia de NiktoScan con los resultados del escaneo

        Returns:
            str: Ruta del archivo PDF generado
        """
        # Crear el directorio si no existe
        os.makedirs(self.directory, exist_ok=True)

        filename = f"{self.directory}/{scan.id}_NiktoScan.pdf"

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
            textColor=colors.HexColor("#c0392b"),  # Rojo para vulnerabilidades
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

        # Estilo para descripciones
        description_style = ParagraphStyle(
            "DescriptionStyle",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#333333"),
            alignment=TA_JUSTIFY,
            leading=12,
        )

        # === LOGO SECOPS ===
        image_filename = f"{self.config_reader.get_directory_of(DirectoryType.RESOURCE)}/SecOps-Logo-SalmonLight.png"
        append_logo(elements, image_filename)

        # === ENCABEZADO ===
        title = Paragraph("Informe de Escaneo Nikto", title_style)
        elements.append(title)

        # Línea decorativa
        elements.append(Spacer(1, 0.1 * inch))

        # Información del escaneo
        scan_info = [
            ["ID del Escaneo:", str(scan.id)],
            ["Objetivo:", str(scan.target)],
            ["Fecha de Inicio:", scan.started_at.strftime("%d/%m/%Y %H:%M:%S") if scan.started_at else "N/A"],  # type: ignore
            ["Total de Incidentes:", str(len(scan.incidents))],
        ]

        info_table = Table(scan_info, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ffe6e6")),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#c0392b")),
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
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#c0392b")),
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
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                        ]
                    )
                )

                elements.append(severity_table)
                elements.append(Spacer(1, 0.3 * inch))

        # === SECCIÓN DE INCIDENTES DETECTADOS ===
        subtitle = Paragraph("Incidentes de Seguridad Detectados", subtitle_style)
        elements.append(subtitle)
        elements.append(Spacer(1, 0.1 * inch))

        if scan.incidents:
            # Ordenar incidentes por severidad
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
                # Color de fondo según severidad
                severity = incident.severity if incident.severity else "unknown"
                severity_colors = {
                    "CRITICAL": colors.HexColor("#ffcccc"),
                    "HIGH": colors.HexColor("#ffe6cc"),
                    "MEDIUM": colors.HexColor("#fff4cc"),
                    "LOW": colors.HexColor("#e6f7ff"),
                    "UNKNOWN": colors.HexColor("#f0f0f0"),
                }
                bg_color = severity_colors.get(severity, colors.HexColor("#f0f0f0"))

                # Crear datos del incidente
                incident_data = [
                    [
                        f"Incidente #{idx}",
                        f"Severidad: {severity.upper() if severity else 'UNKNOWN'}",
                    ],
                ]

                # Tabla de encabezado del incidente
                incident_header = Table(incident_data, colWidths=[3 * inch, 3 * inch])
                incident_header.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1a1a1a")),
                            ("ALIGN", (0, 0), (0, -1), "LEFT"),
                            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 10),
                            ("TOPPADDING", (0, 0), (-1, -1), 6),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
                        ]
                    )
                )

                elements.append(incident_header)

                # Detalles del incidente
                details = []

                if incident.osvdb_id:
                    details.append(["OSVDB ID:", str(incident.osvdb_id)])

                if incident.method:
                    details.append(["Método:", str(incident.method)])

                if incident.url:
                    details.append(["URL:", str(incident.url)])

                if incident.ip_address:
                    details.append(["IP:", str(incident.ip_address)])

                if incident.port:
                    details.append(["Puerto:", str(incident.port)])

                if incident.discovered_at:
                    discovered = incident.discovered_at.strftime("%d/%m/%Y %H:%M:%S")
                    details.append(["Detectado:", discovered])

                # Tabla de detalles
                if details:
                    details_table = Table(details, colWidths=[1.5 * inch, 4.5 * inch])
                    details_table.setStyle(
                        TableStyle(
                            [
                                (
                                    "BACKGROUND",
                                    (0, 0),
                                    (0, -1),
                                    colors.HexColor("#f9f9f9"),
                                ),
                                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                                ("FONTSIZE", (0, 0), (-1, -1), 9),
                                ("TOPPADDING", (0, 0), (-1, -1), 4),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                                (
                                    "GRID",
                                    (0, 0),
                                    (-1, -1),
                                    0.5,
                                    colors.HexColor("#dddddd"),
                                ),
                            ]
                        )
                    )

                    elements.append(details_table)

                # Descripción
                if incident.description:
                    desc_text = incident.description[:500]  # Limitar longitud
                    if len(incident.description) > 500:
                        desc_text += "..."

                    description = Paragraph(
                        f"<b>Descripción:</b> {desc_text}", description_style
                    )
                    desc_table = Table([[description]], colWidths=[6 * inch])
                    desc_table.setStyle(
                        TableStyle(
                            [
                                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                                ("TOPPADDING", (0, 0), (-1, -1), 8),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                                (
                                    "BOX",
                                    (0, 0),
                                    (-1, -1),
                                    0.5,
                                    colors.HexColor("#dddddd"),
                                ),
                            ]
                        )
                    )

                    elements.append(desc_table)

                # Referencias
                if incident.references:
                    ref_text = incident.references[:300]  # Limitar longitud
                    if len(incident.references) > 300:
                        ref_text += "..."

                    references = Paragraph(
                        f"<b>Referencias:</b> {ref_text}", description_style
                    )
                    ref_table = Table([[references]], colWidths=[6 * inch])
                    ref_table.setStyle(
                        TableStyle(
                            [
                                (
                                    "BACKGROUND",
                                    (0, 0),
                                    (-1, -1),
                                    colors.HexColor("#f0f8ff"),
                                ),
                                ("TOPPADDING", (0, 0), (-1, -1), 8),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                                (
                                    "BOX",
                                    (0, 0),
                                    (-1, -1),
                                    0.5,
                                    colors.HexColor("#dddddd"),
                                ),
                            ]
                        )
                    )

                    elements.append(ref_table)

                # Espaciador entre incidentes
                elements.append(Spacer(1, 0.2 * inch))
        else:
            no_incidents = Paragraph(
                "No se detectaron incidentes de seguridad.", info_style
            )
            elements.append(no_incidents)

        # Espaciador final
        elements.append(Spacer(1, 0.3 * inch))

        append_consent(elements, "#c0392b")

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
