"""
Database models for Acheron encrypted vault module.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from src.modules.shared import Base


# =========================================================================
# VAULT MODEL
# =========================================================================

class Vault(Base):
    """
    Encrypted vault for storing secrets.

    Each vault belongs to a user and contains encrypted storables.
    Stores cryptographic parameters used for encryption and key derivation.

    Attributes:
        id: Primary key, auto-incrementing integer.
        user_id: Foreign key to User.id.
        is_recovery: Whether this is a recovery vault (for password reset).
        checker: URL used to verify vault access (obfuscated).
        vault_key: Encrypted vault master key.
        transformation: Encryption algorithm (e.g., "AES/GCM/NoPadding").
        kdf: Key derivation function (e.g., "Argon2").
        kdf_iterations: Number of KDF iterations.
        kdf_memory: Memory in KB for Argon2.
        kdf_parallelism: Parallel threads for Argon2.
        salt: Cryptographic salt (max 128 characters).

    Relationships:
        user: User who owns the vault.
        storables: List of Storable objects in this vault.
    """
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

    user = relationship("User", back_populates="vaults")
    storables = relationship(
        "Storable",
        back_populates="vault",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        """
        Return a debug representation of the Vault instance.

        Returns:
            String with id, user_id, and is_recovery flag.
        """
        return f"<Vault id={self.id} user_id={self.user_id} is_recovery={self.is_recovery}>"


# =========================================================================
# STORABLE MODELS
# =========================================================================

class Storable(Base):
    """
    Base class for storable secrets (polymorphic).

    Abstract base for different types of secrets that can be stored
    in a vault. Uses polymorphic inheritance for Account and CreditCard.

    Attributes:
        id: Primary key, auto-incrementing integer.
        internal_id: Optional internal identifier within the vault.
        title: Optional title/name for the storable.
        created_at: Creation timestamp (automatic).
        updated_at: Last update timestamp (automatic, updated on change).
        vault_id: Foreign key to Vault.id.
        type: Polymorphic discriminator for storable type.

    Relationships:
        vault: Vault containing this storable.

    Table Constraints:
        Unique constraint on (vault_id, internal_id).
        Unique constraint on (title, vault_id).
    """
    __tablename__ = "Storable"

    id = Column(Integer, primary_key=True, autoincrement=True)

    internal_id = Column(String(128), nullable=True)
    title = Column(String(128), nullable=True)

    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    updated_at = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
    )

    vault_id = Column(Integer, ForeignKey("Vault.id"), nullable=False)

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
        """
        Return a debug representation of the Storable instance.

        Returns:
            String with id, type, and title.
        """
        return f"<Storable id={self.id} type={self.type} title={self.title!r}>"


class Account(Storable):
    """
    Username/password account credential.

    Inherits from Storable and adds fields for storing account
    authentication credentials.

    Attributes:
        id: Primary key (foreign key to Storable.id).
        username: Account username or email.
        domain: Service/domain the account belongs to.
        password: Encrypted password.
    """
    __tablename__ = "Account"

    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)

    username = Column(String(512), nullable=False)
    domain = Column(String(512), nullable=False)
    password = Column(String(512), nullable=False)

    __mapper_args__ = {
        "polymorphic_identity": "account",
    }

    def __repr__(self) -> str:
        """
        Return a debug representation of the Account instance.

        Returns:
            String with id and username@domain.
        """
        return f"<Account id={self.id} {self.username}@{self.domain}>"


class CreditCard(Storable):
    """
    Credit card information.

    Inherits from Storable and adds fields for storing credit card
    payment information.

    Attributes:
        id: Primary key (foreign key to Storable.id).
        cardholder_name: Name on the card.
        card_number: Encrypted card number.
        expiration_date: Encrypted expiration date (MM/YY).
        postal_code: Encrypted billing postal code.
        cvv: Encrypted CVV/CVC code.
    """
    __tablename__ = "CreditCard"

    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)

    cardholder_name = Column(String(512), nullable=False)
    card_number = Column(String(512), nullable=False)
    expiration_date = Column(String(512), nullable=False)
    postal_code = Column(String(512), nullable=False)
    cvv = Column(String(512), nullable=False)

    __mapper_args__ = {
        "polymorphic_identity": "creditcard",
    }

    def __repr__(self) -> str:
        """
        Return a debug representation of the CreditCard instance.

        Returns:
            String with id and cardholder name.
        """
        return f"<CreditCard id={self.id} holder={self.cardholder_name!r}>"