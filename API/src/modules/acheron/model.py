from datetime import datetime

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

    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)

    username = Column(String(512), nullable=False)
    domain = Column(String(512), nullable=False)
    password = Column(String(512), nullable=False)

    __mapper_args__ = {
        "polymorphic_identity": "account",
    }

    def __repr__(self) -> str:
        return f"<Account id={self.id} {self.username}@{self.domain}>"


class CreditCard(Storable):
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
        return f"<CreditCard id={self.id} holder={self.cardholder_name!r}>"