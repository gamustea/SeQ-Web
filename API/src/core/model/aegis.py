from datetime import datetime

from sqlalchemy import (
    ARRAY,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from ._base import Base


class Topic(Base):
    __tablename__ = "Topic"

    id    = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(64), nullable=False)

    documents = relationship("AegisDocument", back_populates="topic")


class AegisDocument(Base):
    """
    Registro maestro de un documento Aegis generado.

    Columnas nuevas respecto a la versión anterior:
        format (str): 'json' (nuevo, por defecto) o 'md' (legacy).

    Relaciones nuevas:
        pill     → AegisPill (uno a uno, joined-table)
        alerts   → AegisDocumentAlert (uno a muchos)
    """

    __tablename__ = "AegisDocument"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    title        = Column(String(64),  unique=True, nullable=False)
    filename     = Column(String(128), unique=True, nullable=False)
    status       = Column(String(32),  nullable=False, default="pending")
    format       = Column(String(8),   nullable=False, default="json")
    generated_at = Column(DateTime,    nullable=False, default=datetime.utcnow)
    topic_id     = Column(Integer, ForeignKey("Topic.id"),  nullable=False)
    user_id      = Column(Integer, ForeignKey("User.id"),   nullable=False)

    topic  = relationship("Topic", back_populates="documents")
    user   = relationship("User",  back_populates="aegis_documents")

    pill   = relationship(
        "AegisPill",
        back_populates="document",
        uselist=False,
        cascade="all, delete-orphan",
    )
    alerts = relationship(
        "AegisDocumentAlert",
        back_populates="document",
        order_by="AegisDocumentAlert.position",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<AegisDocument id={self.id} status={self.status!r} format={self.format!r}>"


class AegisPill(Base):
    """
    Contenido estructurado de la píldora de concienciación.

    Hereda la PK de AegisDocument (joined-table inheritance, igual que
    NmapScan → Scan), de modo que siempre hay un registro 1:1.

    Columnas:
        id            → FK + PK a AegisDocument.id
        subtitle      → Título atractivo generado por la IA (negrita en el .md)
        intro         → Párrafo introductorio (3-5 frases)
        closing       → Frase de cierre con llamada a la acción
        contact_email → Email de contacto mencionado en el cierre (opcional)

    Relaciones:
        tips     → AegisTip (lista ordenada de consejos)
        document → AegisDocument (padre)

    Campos a mostrar en API:
        subtitle, intro, closing, contact_email, tips
    """

    __tablename__ = "AegisPill"

    id            = Column(Integer, ForeignKey("AegisDocument.id"), primary_key=True)
    subtitle      = Column(String(128), nullable=False)
    intro         = Column(Text,        nullable=False)
    closing       = Column(Text,        nullable=True)
    contact_email = Column(String(128), nullable=True)

    document = relationship("AegisDocument", back_populates="pill")
    tips     = relationship(
        "AegisTip",
        back_populates="pill",
        order_by="AegisTip.position",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> dict:
        return {
            "subtitle":     self.subtitle,
            "intro":        self.intro,
            "tips":         [t.to_dict() for t in self.tips],
            "closing":      self.closing,
            "contactEmail": self.contact_email,
        }

    def __repr__(self) -> str:
        return f"<AegisPill id={self.id} subtitle={self.subtitle!r}>"


class AegisTip(Base):
    """
    Un consejo individual dentro de una AegisPill.

    Columnas:
        id        → autoincremental
        pill_id   → FK a AegisPill.id
        position  → orden del consejo dentro de la píldora (1-based)
        headline  → acción o riesgo resumido en una frase (negrita en .md)
        body      → desarrollo del consejo (2-3 frases)
        links_json→ JSONB con lista de {text, url} mencionados en el consejo.
                    Puede ser NULL o lista vacía si el consejo no incluye enlaces.

    Ejemplo de links_json:
        [{"text": "uBlock Origin", "url": "https://github.com/gorhill/uBlock"}]

    Campos a mostrar en API:
        position, headline, body, links (deserializado de links_json)
    """

    __tablename__ = "AegisTip"

    id         = Column(Integer,      primary_key=True, autoincrement=True)
    pill_id    = Column(Integer,      ForeignKey("AegisPill.id"), nullable=False)
    position   = Column(SmallInteger, nullable=False)
    headline   = Column(Text,         nullable=False)
    body       = Column(Text,         nullable=False)
    links_json = Column(JSONB,        nullable=True)

    pill = relationship("AegisPill", back_populates="tips")

    __table_args__ = (
        UniqueConstraint("pill_id", "position", name="uq_tip_pill_position"),
    )

    def to_dict(self) -> dict:
        return {
            "position": self.position,
            "headline": self.headline,
            "body":     self.body,
            "links":    self.links_json or [],
        }

    def __repr__(self) -> str:
        return f"<AegisTip id={self.id} pill={self.pill_id} pos={self.position}>"


class AegisDocumentAlert(Base):
    """
    Aviso de vulnerabilidad asociado a un documento Aegis.

    Persiste los datos que antes solo existían en el .md generado.
    Cada alerta proviene de INCIBE o CIRCL/NVD.

    Columnas:
        id              → autoincremental
        document_id     → FK a AegisDocument.id
        position        → orden de aparición en el documento (1-based)
        source          → 'incibe' | 'circl'
        source_label    → texto legible: 'INCIBE-CERT' | 'NVD/CVE'
        title           → título del aviso (ej: "CVE-2025-20363 — IOS")
        published       → fecha de publicación (DATE de PostgreSQL)
        severity        → 'crítica' | 'alta' | 'media' | 'baja' | NULL
        affected_brands → array nativo de PostgreSQL con las marcas afectadas
        description     → resumen del aviso (≤ 500 chars)
        url             → enlace al aviso original

    Campos a mostrar en API:
        todos excepto document_id (se infiere del contexto)
    """

    __tablename__ = "AegisDocumentAlert"

    id              = Column(Integer,      primary_key=True, autoincrement=True)
    document_id     = Column(Integer,      ForeignKey("AegisDocument.id"), nullable=False)
    position        = Column(SmallInteger, nullable=False)
    source          = Column(String(16),   nullable=False)
    source_label    = Column(String(32),   nullable=False)
    title           = Column(String(256),  nullable=False)
    published       = Column(Date,         nullable=True)
    severity        = Column(String(16),   nullable=True)
    affected_brands = Column(ARRAY(String), nullable=True)
    description     = Column(Text,         nullable=True)
    url             = Column(String(512),  nullable=False)

    document = relationship("AegisDocument", back_populates="alerts")

    __table_args__ = (
        UniqueConstraint("document_id", "position", name="uq_alert_document_position"),
    )

    def to_dict(self) -> dict:
        return {
            "position":       self.position,
            "source":         self.source,
            "sourceLabel":    self.source_label,
            "title":          self.title,
            "published":      self.published.isoformat() if self.published else None,
            "severity":       self.severity,
            "affectedBrands": self.affected_brands or [],
            "description":    self.description,
            "url":            self.url,
        }

    def __repr__(self) -> str:
        return (
            f"<AegisDocumentAlert id={self.id} "
            f"doc={self.document_id} pos={self.position} src={self.source!r}>"
        )