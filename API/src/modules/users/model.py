
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from src.modules.shared import Base


class AccessToken(Base):
    """
    Almacena tokens de acceso OAuth 2.0 emitidos a usuarios.
    """
    __tablename__ = "AccessToken"

    id         = Column(Integer,     primary_key=True, autoincrement=True)
    token      = Column(String(512), unique=True, nullable=False, index=True)
    user_id    = Column(Integer,     ForeignKey("User.id"), nullable=False)
    expires_at = Column(DateTime,    nullable=False)
    created_at = Column(DateTime,    nullable=False, default=datetime.utcnow)
    revoked    = Column(Integer,     default=0)  # 0=activo, 1=revocado

    user = relationship("User", back_populates="tokens")

    def is_valid(self) -> bool:
        return not self.revoked and datetime.utcnow() < self.expires_at  # type: ignore

    def __str__(self):
        return f"AccessToken(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})"


class RefreshToken(Base):
    """
    Almacena tokens de refresco para renovar access tokens.
    """
    __tablename__ = "RefreshToken"

    id         = Column(Integer,     primary_key=True, autoincrement=True)
    token      = Column(String(512), unique=True, nullable=False, index=True)
    user_id    = Column(Integer,     ForeignKey("User.id"), nullable=False)
    expires_at = Column(DateTime,    nullable=False)
    created_at = Column(DateTime,    nullable=False, default=datetime.utcnow)
    revoked    = Column(Integer,     default=0)

    user = relationship("User", back_populates="refresh_tokens")

    def is_valid(self) -> bool:
        return not self.revoked and datetime.utcnow() < self.expires_at  # type: ignore

    def __str__(self):
        return f"RefreshToken(id={self.id}, user_id={self.user_id})"


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

    Relaciones:
        - users: Usuarios asociados a esta persona
    """

    __tablename__ = "Person"

    id         = Column(Integer,    primary_key=True, autoincrement=True)
    first_name = Column(String(64), nullable=False)
    last_name  = Column(String(64), nullable=False)
    alias      = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime,   nullable=False, default=datetime.utcnow)

    users = relationship("User", back_populates="person", uselist=True)

    def __str__(self):
        return f"Person(id={self.id}, nombre='{self.first_name} {self.last_name}')"

    def __repr__(self):
        return f"<Person(id={self.id}, {self.first_name} {self.last_name})>"


class Rol(Base):

    __tablename__ = "Rol"

    id              = Column(Integer,     primary_key=True, autoincrement=True)
    name            = Column(String(32),  unique=True, nullable=False)
    description     = Column(String(128))
    hierarchy_level = Column(Integer,     nullable=False)


class User(Base):
    """
    Representa un usuario del sistema con credenciales de acceso.

    Columnas:
        id (int): Identificador único del usuario.
        username (str): Nombre de usuario único (máx. 64 caracteres).
        password_hash / password_salt: Credenciales hasheadas.
        person_id (int): ID de la persona asociada (clave foránea).
        email (str): Correo electrónico (máx. 128 caracteres).

    Relaciones:
        person          → Person
        scans           → lista de Scan
        tokens          → AccessToken
        refresh_tokens  → RefreshToken
        vaults          → Vault
        aegis_documents → AegisDocument
        documents       → Document (todos los documentos, polimórfico)
    """

    __tablename__ = "User"

    id            = Column(Integer,     primary_key=True, autoincrement=True)
    username      = Column(String(64),  unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    password_salt = Column(String(128), nullable=False)
    person_id     = Column(Integer,     ForeignKey("Person.id"), nullable=False)
    rol_id        = Column(Integer,     ForeignKey("Rol.id"), nullable=False, default=1)
    email         = Column(String(128), nullable=False)

    person         = relationship("Person",       back_populates="users")
    scans          = relationship("Scan",         back_populates="user", cascade="all, delete-orphan")
    rol            = relationship("Rol")
    tokens         = relationship("AccessToken",  back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    vaults         = relationship("Vault",        back_populates="user")

    # Relación polimórfica: devuelve todos los documentos del usuario
    # independientemente del tipo (AegisDocument, SentinelDocument…)
    documents = relationship(
        "Document",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    # Acceso directo a documentos Aegis para compatibilidad con código existente
    # (AegisManager referencia user.aegis_documents en varios puntos)
    aegis_documents = relationship(
        "AegisDocument",
        primaryjoin="and_(Document.user_id == User.id, Document.document_type == 'aegis')",
        viewonly=True,
        overlaps="documents",
    )

    def __str__(self):
        return f"User(id={self.id}, username='{self.username}', person_id={self.person_id})"

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}')>"