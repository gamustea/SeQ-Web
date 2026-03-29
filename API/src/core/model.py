from datetime import datetime
from sqlalchemy import (
    Column, 
    Integer, 
    String, 
    DateTime, 
    ForeignKey, 
    Table, 
    Text, 
    Boolean, 
    UniqueConstraint, 
    Float,
    create_engine)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

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
    alias = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    users = relationship("User", back_populates="person", uselist=True)

    def __str__(self):
        return f"Person(id={self.id}, nombre='{self.first_name} {self.last_name}')"

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
    rol_id = Column(Integer, ForeignKey("Rol.id"), nullable=False, default=1)
    email = Column(String(128), nullable=False)

    # Relaciones
    person = relationship("Person", back_populates="users")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    rol = relationship("Rol")

    tokens = relationship("AccessToken", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    vaults = relationship("Vault", back_populates="user")
    aegis_documents = relationship("AegisDocument", back_populates="user", cascade="all, delete-orphan")


    def __str__(self):
        return f"User(id={self.id}, username='{self.username}', person_id={self.person_id})"

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}')>"


class Rol(Base):
    
    __tablename__ = "Rol"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(32), unique=True, nullable=False)
    description = Column(String(128))
    hierarchy_level = Column(Integer, nullable=False)


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
    status = Column(String(20), nullable=False, default="pending")
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    scan_type = Column(String(50))
    frecuent = Column(Boolean, nullable=False, default=True)
    host_id = Column(Integer, ForeignKey("Host.id"))
    finished_at = Column(DateTime, nullable=True)


    user = relationship("User", back_populates="scans")
    host = relationship("Host", back_populates="scans")

    # Configuración de herencia con polimorfismo
    __mapper_args__ = {
        "polymorphic_identity": "scan", 
        "polymorphic_on": scan_type
    }

    def __str__(self):
        started = (
            self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "N/A" # type: ignore
        )
        return f"Scan(id={self.id}, tipo='{self.scan_type}', target='{self.target}', inicio={started})"

    def __repr__(self):
        return f"<Scan(id={self.id}, type='{self.scan_type}', target='{self.target}')>"


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


class Host(Base):

    __tablename__ = "Host"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(64), unique=True, nullable=False)
    ip_address = Column(String(15), nullable=False)
    mac_address = Column(String(17), nullable=False)
    vendor = Column(String(64))
    scans = relationship("Scan", back_populates="host", cascade="all, delete-orphan")


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
    product = Column(String(255))
    version = Column(String(64))
    given_use = Column(String(255))

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
        - severity, ip_address, port, references, discovered_at

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
    port = Column(Integer, nullable=True)

    # Referencias y timestamp
    references = Column(Text, nullable=True)
    discovered_at = Column(DateTime, nullable=False, default=datetime.utcnow)

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
    )  # ⭐ FALTABA ESTO
    

class OpenVASVulnerability(Base):
    """Catálogo de vulnerabilidades"""
    __tablename__ = 'OpenVASVulnerability'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    nvt_oid = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(Text, nullable=False)
    
    # Severidad
    severity_score = Column(Float(3))
    severity_class = Column(String(20), index=True)
    cvss_base_score = Column(Float(3))
    cvss_vector = Column(String(255))
    
    # Referencias (JSON strings o CSV)
    cve_ids = Column(Text)
    cert_refs = Column(Text)
    bugtraq_ids = Column(Text)
    other_refs = Column(Text)
    
    # Descripción
    summary = Column(Text)
    description = Column(Text)
    impact = Column(Text)
    insight = Column(Text)
    affected_software = Column(Text)
    
    # Solución
    solution_type = Column(String(50))
    solution = Column(Text)
    
    # Quality of Detection
    qod_value = Column(Integer)
    qod_type = Column(String(100))
    
    # Categorización
    family = Column(String(255))
    category = Column(String(255))
    
    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relaciones
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
    
    # Relaciones
    openvas_scan = relationship('OpenVASScan', back_populates='results')
    vulnerability = relationship('OpenVASVulnerability', back_populates='scan_results')
    host = relationship('Host')
    

class AccessToken(Base):
    """
    Almacena tokens de acceso OAuth 2.0 emitidos a usuarios.
    """
    __tablename__ = "AccessToken"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String(512), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    revoked = Column(Integer, default=0)  # 0=activo, 1=revocado
    
    # Relación con User
    user = relationship("User", back_populates="tokens")
    
    def is_valid(self) -> bool:
        """Verifica si el token es válido (no revocado y no expirado)"""
        return not self.revoked and datetime.utcnow() < self.expires_at #type: ignore  
    
    def __str__(self):
        return f"AccessToken(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})"


class RefreshToken(Base):
    """
    Almacena tokens de refresco para renovar access tokens.
    """
    __tablename__ = "RefreshToken"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String(512), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    revoked = Column(Integer, default=0)
    
    user = relationship("User", back_populates="refresh_tokens")
    
    def is_valid(self) -> bool:
        return not self.revoked and datetime.utcnow() < self.expires_at #type: ignore   
    
    def __str__(self):
        return f"RefreshToken(id={self.id}, user_id={self.user_id})"


class Vault(Base):
    __tablename__ = "Vault"

    id = Column(Integer, primary_key=True, autoincrement=True)

    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    is_recovery = Column(Boolean, nullable=False, default=False)

    checker = Column(String(512), nullable=False)
    vault_key = Column(String(512), nullable=False)

    transformation = Column(String(64), nullable=False)   # p.ej. "AES/GCM/NoPadding"
    kdf = Column(String(64), nullable=False)              # "Argon2"
    kdf_iterations = Column(Integer, nullable=False)
    kdf_memory = Column(Integer, nullable=False)
    kdf_parallelism = Column(Integer, nullable=False)
    salt = Column(String(128), nullable=False)

    # Relaciones
    user = relationship("User", back_populates="vaults")
    storables = relationship(
        "Storable",
        back_populates="vault",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Vault id={self.id} user_id={self.user_id} is_recovery={self.is_recovery}>"


class Storable(Base):
    __tablename__ = "Storable"

    id = Column(Integer, primary_key=True, autoincrement=True)

    internal_id = Column(String(128), nullable=True)
    title = Column(String(128), nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    vault_id = Column(Integer, ForeignKey("Vault.id"), nullable=False)

    # discriminador polimórfico
    type = Column(String(50), nullable=False)

    vault = relationship("Vault", back_populates="storables")

    __mapper_args__ = {
        "polymorphic_on": type,
        "polymorphic_identity": "storable",
        "with_polymorphic": "*",
    }

    __table_args__ = (
        UniqueConstraint("vault_id", "internal_id", name="uq_storable_vault_internal"),
        UniqueConstraint("title", "vault_id", name="uq_storable_vault_title"),
    )

    def __repr__(self) -> str:
        return f"<Storable id={self.id} type={self.type} title={self.title!r}>"


class Account(Storable):
    __tablename__ = "Account"

    # PK = FK a storable.id (joined-table inheritance)
    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)

    username = Column(String(512), nullable=False)
    domain = Column(String(512), nullable=False)
    password = Column(String(512), nullable=False)  # normalmente cifrado/base64

    __mapper_args__ = {
        "polymorphic_identity": "account",
    }

    def __repr__(self) -> str:
        return f"<Account id={self.id} {self.username}@{self.domain}>"


class CreditCard(Storable):
    __tablename__ = "CreditCard"

    # PK = FK a storable.id (joined-table inheritance)
    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)

    cardholder_name = Column(String(512), nullable=False)
    card_number = Column(String(512), nullable=False)      # cifrado / enmascarado
    expiration_date = Column(String(512), nullable=False)  # p.ej. "12/27"
    postal_code = Column(String(512), nullable=False)
    cvv = Column(String(512), nullable=False)              # cifrado

    __mapper_args__ = {
        "polymorphic_identity": "creditcard",
    }

    def __repr__(self) -> str:
        return f"<CreditCard id={self.id} holder={self.cardholder_name!r}>"


class Topic(Base):
    """
    Representa un tema de ciberseguridad para la generación de newsletters (Aegis).

    Columnas:
    id (int): Identificador único del tema.
    title (str): Título del tema (máx. 64 caracteres).

    Campos obligatorios al crear:
    - title

    Campos autogenerados (NO asignar):
    - id (autoincremental)

    Campos a mostrar:
    - id, title

    Relaciones:
    - documents: Lista de documentos generados sobre este tema
    """

    __tablename__ = "Topic"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(64), nullable=False)

    documents = relationship("AegisDocument", back_populates="topic")

    def __str__(self):
        return f"Topic(id={self.id}, title='{self.title}')"

    def __repr__(self):
        return f"<Topic id={self.id} title='{self.title}'>"


class AegisDocument(Base):
    """
    Representa un documento de newsletter generado por Aegis para un usuario.

    Columnas:
    id (int): Identificador único del documento.
    title (str): Título del documento (máx. 64 caracteres, único).
    filename (str): Nombre del fichero generado en disco (máx. 128 caracteres, único).
    format (str): Formato del documento ('script' o 'newsletter', máx. 16 caracteres).
    generated_at (datetime): Fecha y hora de generación del documento.
    topic_id (int): ID del tema asociado (clave foránea).
    user_id (int): ID del usuario que generó el documento (clave foránea).

    Campos obligatorios al crear:
    - title
    - filename (nombre del fichero en data/aegis/output/)
    - format ('script' o 'newsletter')
    - topic_id (debe existir en la tabla Topic)
    - user_id (debe existir en la tabla User)

    Campos autogenerados (NO asignar):
    - id (autoincremental)
    - generated_at (fecha actual UTC)

    Campos a mostrar:
    - id, title, filename, format, generated_at, topic_id, user_id

    Relaciones:
    - topic: Tema sobre el que se generó el documento
    - user: Usuario que solicitó la generación
    """

    __tablename__ = "AegisDocument"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(64), unique=True, nullable=False)
    filename = Column(String(128), unique=True, nullable=False)
    status = Column(String(32), unique=False, default="pending")
    generated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    topic_id = Column(Integer, ForeignKey("Topic.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)

    topic = relationship("Topic", back_populates="documents")
    user = relationship("User", back_populates="aegis_documents")

    def __str__(self):
        return (
            f"AegisDocument(id={self.id}, title='{self.title}', "
            f"format='{self.format}', generated_at={self.generated_at})"
        )

    def __repr__(self):
        return f"<AegisDocument id={self.id} filename='{self.filename}'>"