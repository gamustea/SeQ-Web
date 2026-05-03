"""
Database models for user authentication and authorization.

This module contains SQLAlchemy models for managing users, access tokens,
and refresh tokens for OAuth 2.0 authentication.

Classes:
    User: Main user entity with credentials and relationships.
    AccessToken: OAuth 2.0 access token for API authentication.
    RefreshToken: OAuth 2.0 refresh token for token renewal.

Example:
>>> from src.modules.users.model import User, AccessToken
>>> user = User(username="admin", email="admin@example.com")
>>> print(user)
'User(id=None, username='admin', person_id=None)'
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from src.modules.shared import Base


# =========================================================================
# TOKEN MODELS
# =========================================================================

class AccessToken(Base):
    """
    OAuth 2.0 access token issued to users for API authentication.

    Stores access tokens with expiration times and revocation status.
    Tokens are validated against expiry and revocation state.

    Attributes:
        id: Primary key, auto-incrementing integer.
        token: Unique token string (indexed for fast lookup).
        user_id: Foreign key to User.id.
        expires_at: Token expiration timestamp.
        created_at: Token creation timestamp (automatic).
        revoked: Revocation status (0=active, 1=revoked).

    Relationships:
        user: User that owns this token.

    Example:
    >>> token = AccessToken(token="abc123...", user_id=1, expires_at=datetime(2025,1,1))
    >>> token.is_valid()
    True
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
        """
        Check if the token is still valid.

        Returns:
            True if token is not revoked and has not expired.
        """
        return not self.revoked and datetime.utcnow() < self.expires_at

    def __str__(self):
        return f"AccessToken(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})"


class RefreshToken(Base):
    """
    OAuth 2.0 refresh token for renewing access tokens.

    Stores refresh tokens with expiration times and revocation status.
    Used to obtain new access tokens when the current one expires.

    Attributes:
        id: Primary key, auto-incrementing integer.
        token: Unique token string (indexed for fast lookup).
        user_id: Foreign key to User.id.
        expires_at: Token expiration timestamp.
        created_at: Token creation timestamp (automatic).
        revoked: Revocation status (0=active, 1=revoked).

    Relationships:
        user: User that owns this token.

    Example:
    >>> token = RefreshToken(token="refresh123...", user_id=1, expires_at=datetime(2025,1,1))
    >>> token.is_valid()
    True
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
        """
        Check if the token is still valid.

        Returns:
            True if token is not revoked and has not expired.
        """
        return not self.revoked and datetime.utcnow() < self.expires_at  # type: ignore

    def __str__(self):
        return f"RefreshToken(id={self.id}, user_id={self.user_id})"


# =========================================================================
# USER MODEL
# =========================================================================

class User(Base):
    """
    Represents a user in the system with authentication credentials.

    Stores user identity information including username, email, and
    hashed passwords. Maintains relationships to all user data
    including scans, documents, tokens, and vaults.

    Attributes:
        id: Primary key, auto-incrementing integer.
        username: Unique username (max 64 characters).
        email: Unique email address (max 128 characters).
        first_name: User's first name (max 64 characters).
        last_name: User's last name (max 64 characters).
        created_at: Account creation timestamp (automatic).
        password_hash: Hashed password (max 128 characters).
        password_salt: Salt used for password hashing (max 128 characters).

    Relationships:
        scans: List of Scan objects (security scans performed).
        tokens: List of AccessToken objects (active OAuth tokens).
        refresh_tokens: List of RefreshToken objects (token refresh tokens).
        vaults: List of Vault objects (encrypted secrets vaults).
        documents: List of all Document objects (polymorphic relationship).

    Columnas:
        id (int): Identificador único del usuario.
        username (str): Nombre de usuario único (máx. 64 caracteres).
        password_hash / password_salt: Credenciales hasheadas.
        email (str): Correo electrónico (máx. 128 caracteres).

    Relationships:
        scans           → lista de Scan
        tokens          → AccessToken
        refresh_tokens  → RefreshToken
        vaults          → Vault
        aegis_documents → AegisDocument
        documents       → Document (todos los documentos, polimórfico)
    """

    __tablename__ = "User"

    id              = Column(Integer,       primary_key=True, autoincrement=True)
    username        = Column(String(64),    unique=True, nullable=False)
    email           = Column(String(128),   unique=True, nullable=False)
    first_name      = Column(String(64),    nullable=False)
    last_name       = Column(String(64),    nullable=False)
    created_at      = Column(DateTime,      nullable=False, default=datetime.utcnow)
    password_hash   = Column(String(128),   nullable=False)
    password_salt   = Column(String(128),   nullable=False)
    
    scans          = relationship("Scan",         back_populates="user", cascade="all, delete-orphan")
    tokens         = relationship("AccessToken",  back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    vaults         = relationship("Vault",        back_populates="user")

    documents = relationship(
        "Document",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    attributes = relationship(
        "UserAttribute",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def __str__(self):
        """
        Return a string representation of the User instance.

        Returns:
            String with id, username, and person_id.
        """
        return f"User(id={self.id}, username='{self.username}', person_id={self.person_id})"

    def __repr__(self):
        """
        Return a debug representation of the User instance.

        Returns:
            String with id and username.
        """
        return f"<User(id={self.id}, username='{self.username}')>"


# =========================================================================
# USER ATTRIBUTE MODEL
# =========================================================================


class UserAttribute(Base):
    """
    Many-to-many relationship between users and attributes.

    Links users to the attributes they possess. Each user can have multiple
    attributes, stored as strings matching AttributeType enum values.

    Attributes:
        user_id: Foreign key to User.id (part of composite PK).
        attribute_name: Attribute identifier (e.g., "sentinel_read", "role_admin").

    Relationships:
        user: User that owns this attribute assignment.

    Example:
        >>> ua = UserAttribute(user_id=1, attribute_name="sentinel_read")
        >>> print(ua)
        'UserAttribute(user_id=1, attribute_name='sentinel_read')'
    """
    __tablename__ = "UserAttribute"

    user_id = Column(Integer, ForeignKey("User.id"), primary_key=True)
    attribute_name = Column(String(64), primary_key=True)

    user = relationship("User", back_populates="attributes")

    def __str__(self):
        return f"UserAttribute(user_id={self.user_id}, attribute_name='{self.attribute_name}')"

    def __repr__(self):
        return f"<UserAttribute(user_id={self.user_id}, attribute_name='{self.attribute_name}')>"