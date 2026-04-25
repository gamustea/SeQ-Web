from datetime import datetime
from enum import Enum

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from src.modules.shared import Base, Document


# ── Tablas de asociación ───────────────────────────────────────────────────────

TargetPort = Table(
    "TargetPort",
    Base.metadata,
    Column("port_id",      Integer, ForeignKey("Port.id"),    primary_key=True),
    Column("nmap_scan_id", Integer, ForeignKey("NmapScan.id"), primary_key=True),
)

ScanIncident = Table(
    "ScanIncident",
    Base.metadata,
    Column("nikto_scan_id",     Integer, ForeignKey("NiktoScan.id"),     primary_key=True),
    Column("nikto_incident_id", Integer, ForeignKey("NiktoIncident.id"), primary_key=True),
)


# ── Modelos de escaneo ─────────────────────────────────────────────────────────

class Host(Base):

    __tablename__ = "Host"

    id          = Column(Integer,    primary_key=True, autoincrement=True)
    hostname    = Column(String(64), unique=True, nullable=False)
    ip_address  = Column(String(15), nullable=False)
    mac_address = Column(String(17), nullable=False)
    vendor      = Column(String(64))

    scans = relationship("Scan", back_populates="host", cascade="all, delete-orphan")


class ScanStatus(Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    FINISHED  = "finished"
    FAILED    = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    """
    Clase base para todos los tipos de escaneos de seguridad.
    Utiliza herencia polimórfica para diferentes tipos de escaneo.

    Columnas:
        id (int): Identificador único del escaneo.
        target (str): Objetivo del escaneo (IP o dominio, máx. 255 caracteres).
        started_at (datetime): Fecha y hora de inicio del escaneo.
        user_id (int): ID del usuario que ejecuta el escaneo (clave foránea).
        scan_type (str): Tipo de escaneo (para discriminador polimórfico).

    Relaciones:
        user: Usuario que ejecutó el escaneo
        host: Host analizado
    """

    __tablename__ = "Scan"

    id          = Column(Integer,    primary_key=True, autoincrement=True)
    target      = Column(String(255), nullable=False)
    started_at  = Column(DateTime,   nullable=False, default=datetime.utcnow)
    status      = Column(String(20), nullable=False, default=ScanStatus.PENDING.value)
    user_id     = Column(Integer,    ForeignKey("User.id"), nullable=False)
    scan_type   = Column(String(50))
    frecuent    = Column(Boolean,    nullable=False, default=True)
    host_id     = Column(Integer,    ForeignKey("Host.id"))
    finished_at = Column(DateTime,   nullable=True)

    user = relationship("User", back_populates="scans")
    host = relationship("Host", back_populates="scans")

    # Un escaneo puede tener como mucho un SentinelDocument asociado
    sentinel_document = relationship(
        "SentinelDocument",
        back_populates="scan",
        uselist=False,
    )

    __mapper_args__ = {
        "polymorphic_identity": "scan",
        "polymorphic_on":       scan_type,
    }

    def __str__(self):
        started = self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "N/A"
        return f"Scan(id={self.id}, tipo='{self.scan_type}', target='{self.target}', inicio={started})"

    def __repr__(self):
        return f"<Scan(id={self.id}, type='{self.scan_type}', target='{self.target}')>"


class Port(Base):

    __tablename__ = "Port"

    id       = Column(Integer,     primary_key=True, autoincrement=True)
    protocol = Column(String(255), unique=True, nullable=False)

    nmap_target_scans = relationship(
        "NmapScan",
        secondary=TargetPort,
        back_populates="target_ports",
        overlaps="target_ports",
    )
    open_port_entries = relationship(
        "OpenPort", back_populates="port", cascade="all, delete-orphan"
    )

    def __str__(self):
        return f"Port(id={self.id}, protocol='{self.protocol}')"

    def __repr__(self):
        return f"<Port(id={self.id}, {self.protocol})>"


class NmapScan(Scan):

    __tablename__ = "NmapScan"

    id = Column(Integer, ForeignKey("Scan.id"), primary_key=True)

    target_ports = relationship(
        "Port",
        secondary=TargetPort,
        back_populates="nmap_target_scans",
        overlaps="target_ports",
    )
    open_ports_relation = relationship(
        "OpenPort", back_populates="nmap_scan", cascade="all, delete-orphan"
    )

    __mapper_args__ = {"polymorphic_identity": "nmap"}

    def __str__(self):
        started   = self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "N/A"
        num_ports = len(self.open_ports_relation) if self.open_ports_relation else 0
        return f"NmapScan(id={self.id}, target='{self.target}', puertos_abiertos={num_ports}, inicio={started})"

    def __repr__(self):
        return f"<NmapScan(id={self.id}, target='{self.target}')>"


class OpenPort(Base):

    __tablename__ = "OpenPort"

    port_id      = Column(Integer, ForeignKey("Port.id"),    primary_key=True)
    nmap_scan_id = Column(Integer, ForeignKey("NmapScan.id"), primary_key=True)
    reason       = Column(String(255), nullable=False)
    product      = Column(String(255))
    version      = Column(String(64))
    given_use    = Column(String(255))

    port     = relationship("Port",     back_populates="open_port_entries")
    nmap_scan = relationship("NmapScan", back_populates="open_ports_relation")

    def __repr__(self):
        return f"<OpenPort(port_id={self.port_id}, scan_id={self.nmap_scan_id})>"


class NiktoScan(Scan):

    __tablename__ = "NiktoScan"

    id = Column(Integer, ForeignKey("Scan.id"), primary_key=True)

    incidents = relationship(
        "NiktoIncident", secondary=ScanIncident, back_populates="nikto_scans"
    )

    __mapper_args__ = {"polymorphic_identity": "nikto"}

    def __repr__(self):
        return f"<NiktoScan(id={self.id}, target='{self.target}')>"


class NiktoIncident(Base):

    __tablename__ = "NiktoIncident"

    id           = Column(Integer,    primary_key=True, autoincrement=True)
    osvdb_id     = Column(String(20), nullable=True)
    method       = Column(String(10), nullable=True)
    url          = Column(String(512), nullable=False)
    description  = Column(Text,       nullable=False)
    severity     = Column(String(20), nullable=True)
    port         = Column(Integer,    nullable=True)
    references   = Column(Text,       nullable=True)
    discovered_at = Column(DateTime,  nullable=False, default=datetime.utcnow)

    nikto_scans = relationship(
        "NiktoScan", secondary=ScanIncident, back_populates="incidents"
    )

    def __repr__(self):
        return f"<NiktoIncident(id={self.id}, osvdb='{self.osvdb_id}', severity='{self.severity}')>"


class OpenVASScan(Scan):

    __tablename__ = "OpenVASScan"

    id               = Column(Integer,     ForeignKey("Scan.id"), primary_key=True)
    task_id          = Column(String(255), nullable=False)
    report_id        = Column(String(255), nullable=False)
    scan_config_name = Column(String(255))
    scanner_name     = Column(String(255))

    results = relationship(
        "OpenVASScanResult", back_populates="openvas_scan", cascade="all, delete-orphan"
    )

    __mapper_args__ = {"polymorphic_identity": "openvas"}

    __table_args__ = (
        UniqueConstraint("task_id", "report_id", name="unique_task_report"),
    )


class OpenVASVulnerability(Base):

    __tablename__ = "OpenVASVulnerability"

    id                = Column(Integer,     primary_key=True, autoincrement=True)
    nvt_oid           = Column(String(255), unique=True, nullable=False, index=True)
    name              = Column(Text,        nullable=False)
    severity_score    = Column(Float(3))
    severity_class    = Column(String(20),  index=True)
    cvss_base_score   = Column(Float(3))
    cvss_vector       = Column(String(255))
    cve_ids           = Column(Text)
    cert_refs         = Column(Text)
    bugtraq_ids       = Column(Text)
    other_refs        = Column(Text)
    summary           = Column(Text)
    description       = Column(Text)
    impact            = Column(Text)
    insight           = Column(Text)
    affected_software = Column(Text)
    solution_type     = Column(String(50))
    solution          = Column(Text)
    qod_value         = Column(Integer)
    qod_type          = Column(String(100))
    family            = Column(String(255))
    category          = Column(String(255))
    created_at        = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at        = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan_results = relationship("OpenVASScanResult", back_populates="vulnerability")

    def __repr__(self):
        return f"<OpenVASVulnerability(nvt_oid='{self.nvt_oid}')>"


class OpenVASScanResult(Base):

    __tablename__ = "OpenVASScanResult"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    openvas_scan_id = Column(Integer, ForeignKey("OpenVASScan.id", ondelete="CASCADE"), nullable=False, index=True)
    vulnerability_id = Column(Integer, ForeignKey("OpenVASVulnerability.id"), nullable=False, index=True)
    host_id         = Column(Integer, ForeignKey("Host.id"), nullable=False, index=True)
    detected_at     = Column(DateTime, nullable=False, default=datetime.utcnow)

    openvas_scan  = relationship("OpenVASScan",          back_populates="results")
    vulnerability = relationship("OpenVASVulnerability",  back_populates="scan_results")
    host          = relationship("Host")


# ── Documento de informe ───────────────────────────────────────────────────────

class SentinelDocument(Document):
    """
    Informe PDF generado a partir de un escaneo Sentinel.

    Hereda de Document (general_model.py):
        id, document_type, filename, format, status,
        created_at, generated_at, user_id, user

    Campos propios:
        scan_id         — FK al escaneo origen (Scan)
        scan_type       — 'nmap' | 'nikto' | 'openvas'
                          Redundante con Scan.scan_type, pero evita joins
                          en listados y queries de estado.
        enrichment_json — resultado cacheado de Ollama (JSONB, nullable).

    Estructura de enrichment_json por scan_type:

        nmap:
        {
          "summary": "...",
          "risk_table": [
            {"port": 80, "service": "http", "risk": "...", "recommendation": "..."}
          ],
          "global_recommendations": ["...", "..."]
        }

        nikto / openvas:
        [
          {"item_id": <int>, "recommendation": "..."},
          ...
        ]

    Notas:
        - enrichment_json es nullable: los PDFs sin IA también usan este modelo.
        - Se escribe una sola vez por el worker; nunca se sobreescribe en 'done'.
        - El campo scan_type permite filtrar sin join a Scan.
    """

    __tablename__ = "SentinelDocument"

    id        = Column(Integer, ForeignKey("Document.id"), primary_key=True)
    scan_id   = Column(Integer, ForeignKey("Scan.id", ondelete="CASCADE"), nullable=False)
    scan_type = Column(String(20),  nullable=False)

    enrichment_json = Column(JSONB, nullable=True)

    scan = relationship("Scan", back_populates="sentinel_document")

    __mapper_args__ = {
        "polymorphic_identity": "sentinel",
    }

    @property
    def is_enriched(self) -> bool:
        """True si el enriquecimiento IA ya está disponible."""
        return self.enrichment_json is not None

    def __repr__(self) -> str:
        return (
            f"<SentinelDocument(id={self.id}, scan_id={self.scan_id}, "
            f"scan_type='{self.scan_type}', status='{self.status}')>"
        )