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
from sqlalchemy.orm import relationship

from ._base import Base

# ── Tablas de asociación ───────────────────────────────────────────────────────

TargetPort = Table(
    "TargetPort",
    Base.metadata,
    Column("port_id", Integer, ForeignKey("Port.id"), primary_key=True),
    Column("nmap_scan_id", Integer, ForeignKey("NmapScan.id"), primary_key=True),
)

ScanIncident = Table(
    "ScanIncident",
    Base.metadata,
    Column("nikto_scan_id", Integer, ForeignKey("NiktoScan.id"), primary_key=True),
    Column(
        "nikto_incident_id", Integer, ForeignKey("NiktoIncident.id"), primary_key=True
    ),
)


# ── Modelos ────────────────────────────────────────────────────────────────────

class Host(Base):

    __tablename__ = "Host"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(64), unique=True, nullable=False)
    ip_address = Column(String(15), nullable=False)
    mac_address = Column(String(17), nullable=False)
    vendor = Column(String(64))
    scans = relationship("Scan", back_populates="host", cascade="all, delete-orphan")

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    FINISHED = "finished"
    FAILED = "failed"
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

    Campos obligatorios al crear:
        - target (dirección IP o dominio a escanear)
        - user_id (debe existir en la tabla User)

    Campos autogenerados (NO asignar):
        - id (autoincremental)
        - started_at (fecha actual)
        - scan_type (asignado automáticamente según la subclase)

    Campos a mostrar:
        - id, target, started_at, user_id, scan_type

    Relaciones:
        - user: Usuario que ejecutó el escaneo
        - finished_scan: Información de finalización del escaneo (opcional)
    """

    __tablename__ = "Scan"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), nullable=False)
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    status = Column(String(20), nullable=False, default=ScanStatus.PENDING.value)
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    scan_type = Column(String(50))
    frecuent = Column(Boolean, nullable=False, default=True)
    host_id = Column(Integer, ForeignKey("Host.id"))
    finished_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="scans")
    host = relationship("Host", back_populates="scans")

    __mapper_args__ = {
        "polymorphic_identity": "scan",
        "polymorphic_on": scan_type
    }

    def __str__(self):
        started = (
            self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "N/A"  # type: ignore
        )
        return f"Scan(id={self.id}, tipo='{self.scan_type}', target='{self.target}', inicio={started})"

    def __repr__(self):
        return f"<Scan(id={self.id}, type='{self.scan_type}', target='{self.target}')>"


class Port(Base):
    """
    Representa un puerto de red con su protocolo.

    Columnas:
        id (int): Identificador único del puerto.
        protocol (str): Protocolo del puerto (ej: "80/tcp", máx. 255 caracteres).

    Campos obligatorios al crear:
        - protocol (formato: "número/protocolo", debe ser único)

    Campos autogenerados (NO asignar):
        - id (autoincremental)

    Campos a mostrar:
        - id, protocol

    Relaciones:
        - nmap_target_scans: Escaneos Nmap que tienen este puerto como objetivo
        - open_port_entries: Entradas de OpenPort asociadas (puerto encontrado abierto)
    """

    __tablename__ = "Port"

    id = Column(Integer, primary_key=True, autoincrement=True)
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
    """
    Escaneo de puertos utilizando la herramienta Nmap.
    Hereda de Scan y añade funcionalidad específica para puertos.
    """

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

    __mapper_args__ = {
        "polymorphic_identity": "nmap",
    }

    def __str__(self):
        started = (
            self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "N/A"  # type: ignore
        )
        num_ports = len(self.open_ports_relation) if self.open_ports_relation else 0
        return f"NmapScan(id={self.id}, target='{self.target}', puertos_abiertos={num_ports}, inicio={started})"

    def __repr__(self):
        return f"<NmapScan(id={self.id}, target='{self.target}')>"


class OpenPort(Base):
    """
    Tabla de asociación con atributos adicionales entre Port y NmapScan.
    Representa un puerto encontrado abierto durante un escaneo Nmap.

    Columnas:
        port_id (int): ID del puerto (clave primaria compuesta, foránea).
        nmap_scan_id (int): ID del escaneo Nmap (clave primaria compuesta, foránea).
        reason (str): Razón por la cual el puerto está abierto (máx. 255 caracteres).
    """

    __tablename__ = "OpenPort"

    port_id = Column(Integer, ForeignKey("Port.id"), primary_key=True)
    nmap_scan_id = Column(Integer, ForeignKey("NmapScan.id"), primary_key=True)
    reason = Column(String(255), nullable=False)
    product = Column(String(255))
    version = Column(String(64))
    given_use = Column(String(255))

    port = relationship("Port", back_populates="open_port_entries")
    nmap_scan = relationship("NmapScan", back_populates="open_ports_relation")

    def __str__(self):
        protocol = self.port.protocol if self.port else "N/A"
        return f"OpenPort(puerto={protocol}, scan_id={self.nmap_scan_id}, razón='{self.reason}')"

    def __repr__(self):
        return f"<OpenPort(port_id={self.port_id}, scan_id={self.nmap_scan_id})>"


class NiktoScan(Scan):
    """
    Escaneo de vulnerabilidades web utilizando la herramienta Nikto.
    Hereda de Scan y añade funcionalidad específica para incidentes web.
    """

    __tablename__ = "NiktoScan"

    id = Column(Integer, ForeignKey("Scan.id"), primary_key=True)

    incidents = relationship(
        "NiktoIncident", secondary=ScanIncident, back_populates="nikto_scans"
    )

    __mapper_args__ = {
        "polymorphic_identity": "nikto",
    }

    def __str__(self):
        started = (
            self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "N/A"  # type: ignore
        )
        num_incidents = len(self.incidents) if self.incidents else 0
        return f"NiktoScan(id={self.id}, target='{self.target}', incidentes={num_incidents}, inicio={started})"

    def __repr__(self):
        return f"<NiktoScan(id={self.id}, target='{self.target}')>"


class NiktoIncident(Base):
    """
    Representa un incidente de seguridad encontrado por Nikto.
    """

    __tablename__ = "NiktoIncident"

    id = Column(Integer, primary_key=True, autoincrement=True)

    osvdb_id = Column(String(20), nullable=True)
    method = Column(String(10), nullable=True)
    url = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)

    severity = Column(String(20), nullable=True)
    port = Column(Integer, nullable=True)

    references = Column(Text, nullable=True)
    discovered_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    nikto_scans = relationship(
        "NiktoScan", secondary=ScanIncident, back_populates="incidents"
    )

    def __str__(self):
        severity_str = f" [{self.severity.upper()}]" if self.severity else ""  # type: ignore
        desc_preview = self.description[:50] + "..." if len(self.description) > 50 else self.description  # type: ignore
        return (
            f"NiktoIncident(id={self.id}, "
            f"OSVDB={self.osvdb_id or 'N/A'}{severity_str}, "
            f"url='{self.url}', "
            f"descripción='{desc_preview}')"
        )

    def __repr__(self):
        return f"<NiktoIncident(id={self.id}, osvdb='{self.osvdb_id}', severity='{self.severity}')>"


class OpenVASScan(Scan):
    __tablename__ = 'OpenVASScan'

    id = Column(Integer, ForeignKey('Scan.id'), primary_key=True)
    task_id = Column(String(255), nullable=False)
    report_id = Column(String(255), nullable=False)
    scan_config_name = Column(String(255))
    scanner_name = Column(String(255))

    results = relationship('OpenVASScanResult', back_populates='openvas_scan', cascade='all, delete-orphan')

    __mapper_args__ = {
        'polymorphic_identity': 'openvas',
    }

    __table_args__ = (
        UniqueConstraint('task_id', 'report_id', name='unique_task_report'),
    )


class OpenVASVulnerability(Base):
    """Catálogo de vulnerabilidades"""
    __tablename__ = 'OpenVASVulnerability'

    id = Column(Integer, primary_key=True, autoincrement=True)
    nvt_oid = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(Text, nullable=False)

    severity_score = Column(Float(3))
    severity_class = Column(String(20), index=True)
    cvss_base_score = Column(Float(3))
    cvss_vector = Column(String(255))

    cve_ids = Column(Text)
    cert_refs = Column(Text)
    bugtraq_ids = Column(Text)
    other_refs = Column(Text)

    summary = Column(Text)
    description = Column(Text)
    impact = Column(Text)
    insight = Column(Text)
    affected_software = Column(Text)

    solution_type = Column(String(50))
    solution = Column(Text)

    qod_value = Column(Integer)
    qod_type = Column(String(100))

    family = Column(String(255))
    category = Column(String(255))

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan_results = relationship('OpenVASScanResult', back_populates='vulnerability')

    def __str__(self):
        return f"OpenVAS Vulnerability: {self.nvt_oid}\n\t - Description: {self.description}"


class OpenVASScanResult(Base):
    """Resultados específicos de vulnerabilidades encontradas"""
    __tablename__ = 'OpenVASScanResult'

    id = Column(Integer, primary_key=True, autoincrement=True)
    openvas_scan_id = Column(Integer, ForeignKey('OpenVASScan.id', ondelete='CASCADE'), nullable=False, index=True)
    vulnerability_id = Column(Integer, ForeignKey('OpenVASVulnerability.id'), nullable=False, index=True)
    host_id = Column(Integer, ForeignKey('Host.id'), nullable=False, index=True)
    detected_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    openvas_scan = relationship('OpenVASScan', back_populates='results')
    vulnerability = relationship('OpenVASVulnerability', back_populates='scan_results')
    host = relationship('Host')