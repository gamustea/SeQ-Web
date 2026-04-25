from datetime import datetime

from sqlalchemy import (
    ARRAY,
    Column,
    Date,
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
from .general_model import Document


# ============================================================================
# TOPIC
# ============================================================================

class Topic(Base):
    __tablename__ = "Topic"

    id    = Column(Integer,     primary_key=True, autoincrement=True)
    title = Column(String(64),  nullable=False)

    documents = relationship("AegisDocument", back_populates="topic")


# ============================================================================
# AEGIS DOCUMENT
# ============================================================================

class AegisDocument(Document):
    """
    Documento de concienciación en ciberseguridad generado por Aegis.

    Hereda de Document (general_model.py):
        id, document_type, filename, format, status,
        created_at, generated_at, user_id, user

    Campos propios (contenido de la píldora):
        title         — identificador interno / placeholder durante pending
        subtitle      — título creativo generado por la IA (visible al usuario)
        intro         — introducción extensa
        closing       — conclusión / llamada a la acción
        company       — empresa destinataria
        contact_email — email de contacto mostrado en el documento
        topic_id      — tema de la base de datos (FK → Topic)

    Relaciones:
        topic  → Topic
        tips   → AegisTip  (consejos ordenados)
        alerts → AegisDocumentAlert (alertas de vulnerabilidad)

    Nota sobre 'generated_at':
        En el modelo anterior AegisDocument tenía generated_at propio con
        default=datetime.utcnow (siempre relleno). Ahora vive en Document
        como nullable=True y se asigna al finalizar la generación, igual
        que el campo 'status'. AegisManager debe asignarlo en
        _update_document_status cuando status pasa a 'done'.
    """

    __tablename__ = "AegisDocument"

    id            = Column(Integer,     ForeignKey("Document.id"), primary_key=True)

    # Identificación interna
    title         = Column(String(64), nullable=False)

    # Contenido de la píldora
    subtitle      = Column(String(128), nullable=True)
    intro         = Column(Text,        nullable=True)
    closing       = Column(Text,        nullable=True)
    contact_email = Column(String(128), nullable=True)
    company       = Column(String(128), nullable=True)

    # Relación con el tema
    topic_id      = Column(Integer, ForeignKey("Topic.id"), nullable=False)
    topic         = relationship("Topic", back_populates="documents")

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

    __mapper_args__ = {
        "polymorphic_identity": "aegis",
    }

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
        return (
            f"<AegisDocument(id={self.id}, topic_id={self.topic_id}, "
            f"status='{self.status}')>"
        )


# ============================================================================
# TIPS Y ALERTAS
# ============================================================================

class AegisTip(Base):
    """
    Un consejo individual dentro de un AegisDocument.

    Columnas:
        id          — autoincremental
        document_id — FK a AegisDocument.id
        position    — orden del consejo dentro de la píldora (1-based)
        headline    — acción o riesgo resumido en una frase
        body        — desarrollo del consejo (2-3 frases)
        links_json  — JSONB con lista de {text, url}; NULL o [] si no hay enlaces

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
        return f"<AegisTip(id={self.id}, doc={self.document_id}, pos={self.position})>"


class AegisDocumentAlert(Base):
    """
    Aviso de vulnerabilidad asociado a un AegisDocument.

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
            f"<AegisDocumentAlert(id={self.id}, "
            f"doc={self.document_id}, pos={self.position}, src='{self.source}')>"
        )