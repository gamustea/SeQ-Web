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
    Registro maestro de un documento Aegis.

    Contiene tanto los metadatos del documento como el contenido de la píldora
    (anteriormente repartido entre AegisDocument y AegisPill en joined-table
    inheritance). La fusión elimina el JOIN innecesario y simplifica las
    operaciones de lectura y escritura.

    Columnas de metadatos:
        id, title, filename, status, format, generated_at, topic_id, user_id

    Columnas de contenido (antes en AegisPill):
        subtitle      — Título atractivo generado por la IA
        intro         — Párrafo introductorio (3-5 frases)
        closing       — Frase de cierre con llamada a la acción
        contact_email — Email de contacto mencionado en el cierre (opcional)
        company       — Nombre de la empresa destinataria

    Relaciones:
        tips   → AegisTip (lista ordenada de consejos, FK directa)
        alerts → AegisDocumentAlert (avisos de vulnerabilidad)
        topic  → Topic
        user   → User
    """

    __tablename__ = "AegisDocument"

    # ── Metadatos ──────────────────────────────────────────────────────────────
    id           = Column(Integer,     primary_key=True, autoincrement=True)
    title        = Column(String(64),  unique=True, nullable=False)
    filename     = Column(String(128), unique=True, nullable=False)
    status       = Column(String(32),  nullable=False, default="pending")
    format       = Column(String(8),   nullable=False, default="json")
    generated_at = Column(DateTime,    nullable=False, default=datetime.utcnow)
    topic_id     = Column(Integer, ForeignKey("Topic.id"), nullable=False)
    user_id      = Column(Integer, ForeignKey("User.id"),  nullable=False)

    # ── Contenido de la píldora ────────────────────────────────────────────────
    subtitle      = Column(String(128), nullable=True)
    intro         = Column(Text,        nullable=True)
    closing       = Column(Text,        nullable=True)
    contact_email = Column(String(128), nullable=True)
    company       = Column(String(128), nullable=True)

    # ── Relaciones ─────────────────────────────────────────────────────────────
    topic  = relationship("Topic", back_populates="documents")
    user   = relationship("User",  back_populates="aegis_documents")

    tips = relationship(
        "AegisTip",
        back_populates="document",
        order_by="AegisTip.position",
        cascade="all, delete-orphan",
    )
    alerts = relationship(
        "AegisDocumentAlert",
        back_populates="document",
        order_by="AegisDocumentAlert.position",
        cascade="all, delete-orphan",
    )

    def pill_to_dict(self) -> dict:
        """Serializa el contenido de la píldora para respuestas de API."""
        return {
            "subtitle":     self.subtitle or "",
            "intro":        self.intro or "",
            "tips":         [t.to_dict() for t in self.tips],
            "closing":      self.closing or "",
            "contactEmail": self.contact_email or "",
            "company":      self.company or "",
        }

    def __repr__(self) -> str:
        return f"<AegisDocument id={self.id} status={self.status!r} format={self.format!r}>"


class AegisTip(Base):
    """
    Un consejo individual dentro de un AegisDocument.

    Columnas:
        id         — autoincremental
        document_id — FK a AegisDocument.id (antes pill_id → AegisPill.id)
        position   — orden del consejo dentro de la píldora (1-based)
        headline   — acción o riesgo resumido en una frase
        body       — desarrollo del consejo (2-3 frases)
        links_json — JSONB con lista de {text, url}; NULL o [] si no hay enlaces

    Ejemplo de links_json:
        [{"text": "uBlock Origin", "url": "https://github.com/gorhill/uBlock"}]
    """

    __tablename__ = "AegisTip"

    id          = Column(Integer,      primary_key=True, autoincrement=True)
    document_id = Column(Integer,      ForeignKey("AegisDocument.id"), nullable=False)
    position    = Column(SmallInteger, nullable=False)
    headline    = Column(Text,         nullable=False)
    body        = Column(Text,         nullable=False)
    links_json  = Column(JSONB,        nullable=True)

    document = relationship("AegisDocument", back_populates="tips")

    __table_args__ = (
        UniqueConstraint("document_id", "position", name="uq_tip_document_position"),
    )

    def to_dict(self) -> dict:
        return {
            "position": self.position,
            "headline": self.headline,
            "body":     self.body,
            "links":    self.links_json or [],
        }

    def __repr__(self) -> str:
        return f"<AegisTip id={self.id} doc={self.document_id} pos={self.position}>"


class AegisDocumentAlert(Base):
    """
    Aviso de vulnerabilidad asociado a un documento Aegis.

    Proviene de INCIBE o CIRCL/NVD. Cada alerta tiene posición explícita
    para preservar el orden de aparición en el documento generado.

    Columnas:
        id              — autoincremental
        document_id     — FK a AegisDocument.id
        position        — orden de aparición (1-based)
        source          — 'incibe' | 'circl'
        source_label    — texto legible: 'INCIBE-CERT' | 'NVD/CVE'
        title           — título del aviso
        published       — fecha de publicación
        severity        — 'crítica' | 'alta' | 'media' | 'baja' | NULL
        affected_brands — array de marcas afectadas
        description     — resumen (≤ 500 chars)
        url             — enlace al aviso original
    """

    __tablename__ = "AegisDocumentAlert"

    id              = Column(Integer,       primary_key=True, autoincrement=True)
    document_id     = Column(Integer,       ForeignKey("AegisDocument.id"), nullable=False)
    position        = Column(SmallInteger,  nullable=False)
    source          = Column(String(16),    nullable=False)
    source_label    = Column(String(32),    nullable=False)
    title           = Column(String(256),   nullable=False)
    published       = Column(Date,          nullable=True)
    severity        = Column(String(16),    nullable=True)
    affected_brands = Column(ARRAY(String), nullable=True)
    description     = Column(Text,          nullable=True)
    url             = Column(String(512),   nullable=False)

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