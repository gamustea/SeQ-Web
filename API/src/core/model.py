from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table, Text
from sqlalchemy.orm import relationship, declarative_base


Base = declarative_base()


# Tabla de asociación simple para TargetPort (muchos a muchos)
TargetPort = Table(
    "TargetPort",
    Base.metadata,
    Column("port_id", Integer, ForeignKey("Port.id"), primary_key=True),
    Column("nmap_scan_id", Integer, ForeignKey("NmapScan.id"), primary_key=True),
)


# Tabla de asociación simple para ScanIncident (muchos a muchos)
ScanIncident = Table(
    "ScanIncident",
    Base.metadata,
    Column("nikto_scan_id", Integer, ForeignKey("NiktoScan.id"), primary_key=True),
    Column(
        "nikto_incident_id", Integer, ForeignKey("NiktoIncident.id"), primary_key=True
    ),
)


class Person(Base):
    """
    Representa una persona en el sistema.

    Columnas:
        id (int): Identificador único de la persona.
        first_name (str): Nombre de la persona (máx. 64 caracteres).
        last_name (str): Apellidos de la persona (máx. 64 caracteres).
        email (str): Correo electrónico de la persona (máx. 128 caracteres).
        created_at (datetime): Fecha y hora de creación del registro.

    Campos obligatorios al crear:
        - first_name
        - last_name
        - email

    Campos autogenerados (NO asignar):
        - id (autoincremental)
        - created_at (fecha actual UTC)

    Campos a mostrar:
        - id, first_name, last_name, email, created_at

    Relaciones:
        - user: Usuario asociado a esta persona (relación uno a uno)
    """

    __tablename__ = "Person"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_name = Column(String(64), nullable=False)
    last_name = Column(String(64), nullable=False)
    email = Column(String(128), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relación uno a uno con User
    user = relationship("User", back_populates="person", uselist=False)

    def __str__(self):
        return f"Person(id={self.id}, nombre='{self.first_name} {self.last_name}', email='{self.email}')"

    def __repr__(self):
        return f"<Person(id={self.id}, {self.first_name} {self.last_name})>"


class User(Base):
    """
    Representa un usuario del sistema con credenciales de acceso.

    Columnas:
        id (int): Identificador único del usuario.
        username (str): Nombre de usuario único (máx. 64 caracteres).
        password (str): Contraseña encriptada (máx. 128 caracteres).
        person_id (int): ID de la persona asociada (clave foránea).

    Campos obligatorios al crear:
        - username (debe ser único en el sistema)
        - password (debe estar previamente encriptada)
        - person_id (debe existir en la tabla Person)

    Campos autogenerados (NO asignar):
        - id (autoincremental)

    Campos a mostrar:
        - id, username, person_id
        - NO MOSTRAR: password (información sensible)

    Relaciones:
        - person: Persona asociada a este usuario
        - scans: Lista de escaneos realizados por este usuario
    """

    __tablename__ = "User"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    password_salt = Column(String(128), nullable=False)
    person_id = Column(Integer, ForeignKey("Person.id"), nullable=False)

    # Relaciones
    person = relationship("Person", back_populates="user")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")

    def __str__(self):
        return f"User(id={self.id}, username='{self.username}', person_id={self.person_id})"

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}')>"


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
    started_at = Column(DateTime, nullable=False, default=datetime.now())
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    scan_type = Column(String(50))

    # Relaciones
    user = relationship("User", back_populates="scans")
    finished_scan = relationship(
        "FinishedScan",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )

    # Configuración de herencia con polimorfismo
    __mapper_args__ = {"polymorphic_identity": "scan", "polymorphic_on": scan_type}

    def __str__(self):
        started = (
            self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "N/A" # type: ignore
        )
        return f"Scan(id={self.id}, tipo='{self.scan_type}', target='{self.target}', inicio={started})"

    def __repr__(self):
        return f"<Scan(id={self.id}, type='{self.scan_type}', target='{self.target}')>"


class FinishedScan(Base):
    """
    Almacena información sobre la finalización de un escaneo.

    Columnas:
        id (int): ID del escaneo asociado (clave primaria y foránea).
        finished_at (datetime): Fecha y hora de finalización del escaneo.

    Campos obligatorios al crear:
        - id (debe existir en la tabla Scan)
        - finished_at (fecha y hora de finalización)

    Campos autogenerados (NO asignar):
        - Ninguno

    Campos a mostrar:
        - id, finished_at

    Relaciones:
        - scan: Escaneo al que pertenece esta finalización
    """

    __tablename__ = "FinishedScan"

    id = Column(Integer, ForeignKey("Scan.id"), primary_key=True)
    finished_at = Column(DateTime, nullable=False)

    # Relación con Scan
    scan = relationship("Scan", back_populates="finished_scan")

    def __str__(self):
        finished = (
            self.finished_at.strftime("%Y-%m-%d %H:%M:%S")
            if self.finished_at # type: ignore
            else "N/A"
        )
        return f"FinishedScan(scan_id={self.id}, finalizado={finished})"

    def __repr__(self):
        return f"<FinishedScan(scan_id={self.id})>"


class NmapScan(Scan):
    """
    Escaneo de puertos utilizando la herramienta Nmap.
    Hereda de Scan y añade funcionalidad específica para puertos.

    Columnas propias:
        id (int): ID del escaneo (hereda de Scan).

    Columnas heredadas de Scan:
        - target, started_at, user_id, scan_type

    Campos obligatorios al crear:
        - target (heredado)
        - user_id (heredado)

    Campos autogenerados (NO asignar):
        - id (autoincremental)
        - started_at (fecha actual)
        - scan_type (se asigna automáticamente como 'nmap')

    Campos a mostrar:
        - id, target, started_at, user_id, scan_type

    Relaciones:
        - target_ports: Puertos objetivo del escaneo (muchos a muchos)
        - open_ports_relation: Puertos abiertos encontrados con detalles
    """

    __tablename__ = "NmapScan"

    id = Column(Integer, ForeignKey("Scan.id"), primary_key=True)

    # Relaciones con Port a través de las tablas de asociación
    target_ports = relationship(
        "Port",
        secondary=TargetPort,
        back_populates="nmap_target_scans",
        overlaps="target_ports",
    )

    # Para OpenPort necesitamos una relación especial porque tiene el campo 'reason'
    open_ports_relation = relationship(
        "OpenPort", back_populates="nmap_scan", cascade="all, delete-orphan"
    )

    __mapper_args__ = {
        "polymorphic_identity": "nmap",
    }

    def __str__(self):
        started = (
            self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "N/A" # type: ignore
        )
        num_ports = len(self.open_ports_relation) if self.open_ports_relation else 0
        return f"NmapScan(id={self.id}, target='{self.target}', puertos_abiertos={num_ports}, inicio={started})"

    def __repr__(self):
        return f"<NmapScan(id={self.id}, target='{self.target}')>"


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

    # Relación con NmapScan a través de TargetPort
    nmap_target_scans = relationship(
        "NmapScan",
        secondary=TargetPort,
        back_populates="target_ports",
        overlaps="target_ports",
    )

    # Relación con OpenPort (que tiene el campo reason)
    open_port_entries = relationship(
        "OpenPort", back_populates="port", cascade="all, delete-orphan"
    )

    def __str__(self):
        return f"Port(id={self.id}, protocol='{self.protocol}')"

    def __repr__(self):
        return f"<Port(id={self.id}, {self.protocol})>"


class OpenPort(Base):
    """
    Tabla de asociación con atributos adicionales entre Port y NmapScan.
    Representa un puerto encontrado abierto durante un escaneo Nmap.

    Columnas:
        port_id (int): ID del puerto (clave primaria compuesta, foránea).
        nmap_scan_id (int): ID del escaneo Nmap (clave primaria compuesta, foránea).
        reason (str): Razón por la cual el puerto está abierto (máx. 255 caracteres).

    Campos obligatorios al crear:
        - port_id (debe existir en la tabla Port)
        - nmap_scan_id (debe existir en la tabla NmapScan)
        - reason (ej: "syn-ack", "echo-reply")

    Campos autogenerados (NO asignar):
        - Ninguno

    Campos a mostrar:
        - port_id, nmap_scan_id, reason

    Relaciones:
        - port: Puerto al que hace referencia
        - nmap_scan: Escaneo Nmap al que pertenece
    """

    __tablename__ = "OpenPort"

    port_id = Column(Integer, ForeignKey("Port.id"), primary_key=True)
    nmap_scan_id = Column(Integer, ForeignKey("NmapScan.id"), primary_key=True)
    reason = Column(String(255), nullable=False)

    # Relaciones
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

    Columnas propias:
        id (int): ID del escaneo (hereda de Scan).

    Columnas heredadas de Scan:
        - target, started_at, user_id, scan_type

    Campos obligatorios al crear:
        - target (heredado, debe ser una URL o IP con puerto web)
        - user_id (heredado)

    Campos autogenerados (NO asignar):
        - id (autoincremental)
        - started_at (fecha actual)
        - scan_type (se asigna automáticamente como 'nikto')

    Campos a mostrar:
        - id, target, started_at, user_id, scan_type

    Relaciones:
        - incidents: Lista de incidentes de seguridad encontrados (muchos a muchos)
    """

    __tablename__ = "NiktoScan"

    id = Column(Integer, ForeignKey("Scan.id"), primary_key=True)

    # Relación muchos a muchos con NiktoIncident
    incidents = relationship(
        "NiktoIncident", secondary=ScanIncident, back_populates="nikto_scans"
    )

    __mapper_args__ = {
        "polymorphic_identity": "nikto",
    }

    def __str__(self):
        started = (
            self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "N/A" # type: ignore
        )
        num_incidents = len(self.incidents) if self.incidents else 0
        return f"NiktoScan(id={self.id}, target='{self.target}', incidentes={num_incidents}, inicio={started})"

    def __repr__(self):
        return f"<NiktoScan(id={self.id}, target='{self.target}')>"


class NiktoIncident(Base):
    """
    Representa un incidente de seguridad encontrado por Nikto.

    Columnas:
        id (int): Identificador único del incidente.
        osvdb_id (str): Identificador OSVDB del incidente (ej: "OSVDB-3268").
        method (str): Método HTTP usado (GET, POST, PUT, etc.).
        url (str): URL completa donde se detectó el incidente.
        description (str): Descripción detallada del incidente de seguridad.
        severity (str): Nivel de severidad (low, medium, high, critical).
        ip_address (str): Dirección IP del host afectado.
        port (int): Puerto donde se detectó la vulnerabilidad.
        references (str): Enlaces a CVE, documentación u otras referencias.
        discovered_at (datetime): Fecha y hora del descubrimiento.

    Campos obligatorios al crear:
        - url (URL donde se detectó el incidente)
        - description (descripción del incidente)
        - discovered_at (timestamp del descubrimiento)

    Campos opcionales:
        - osvdb_id (identificador de OSVDB)
        - method (método HTTP)
        - severity (nivel de criticidad)
        - ip_address (IP afectada)
        - port (puerto afectado)
        - references (enlaces de referencia)

    Campos autogenerados (NO asignar):
        - id (autoincremental)

    Campos a mostrar:
        - id, osvdb_id, method, url, description,
          severity, ip_address, port, references, discovered_at

    Relaciones:
        - nikto_scans: Lista de escaneos Nikto que detectaron este incidente
    """

    __tablename__ = "NiktoIncident"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Información del incidente
    osvdb_id = Column(String(20), nullable=True)
    method = Column(String(10), nullable=True)
    url = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)

    # Clasificación y contexto
    severity = Column(String(20), nullable=True)  # low, medium, high, critical
    ip_address = Column(String(45), nullable=True)
    port = Column(Integer, nullable=True)

    # Referencias y timestamp
    references = Column(Text, nullable=True)
    discovered_at = Column(DateTime, nullable=False, default=datetime.now)

    # Relación muchos a muchos con NiktoScan
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
    """
    Escaneo de vulnerabilidades utilizando la herramienta OpenVAS.
    Hereda de Scan sin añadir columnas adicionales por el momento.

    Columnas propias:
        id (int): ID del escaneo (hereda de Scan).

    Columnas heredadas de Scan:
        - target, started_at, user_id, scan_type

    Campos obligatorios al crear:
        - target (heredado, dirección IP o rango a escanear)
        - user_id (heredado)

    Campos autogenerados (NO asignar):
        - id (autoincremental)
        - started_at (fecha actual)
        - scan_type (se asigna automáticamente como 'openvas')

    Campos a mostrar:
        - id, target, started_at, user_id, scan_type

    Relaciones:
        - Ninguna adicional (hereda las de Scan)

    Nota:
        Esta clase probablemente se extenderá en el futuro para almacenar
        resultados específicos de OpenVAS (vulnerabilidades, CVEs, etc.).
    """

    __tablename__ = "OpenVASScan"

    id = Column(Integer, ForeignKey("Scan.id"), primary_key=True)

    __mapper_args__ = {
        "polymorphic_identity": "openvas",
    }

    def __str__(self):
        started = self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "N/A"  # type: ignore
        return f"OpenVASScan(id={self.id}, target='{self.target}', inicio={started})"

    def __repr__(self):
        return f"<OpenVASScan(id={self.id}, target='{self.target}')>"
