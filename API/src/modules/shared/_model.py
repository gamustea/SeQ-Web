from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship, declarative_base


Base = declarative_base()

class Document(Base):
    """
    Metadatos comunes a cualquier documento generado por el sistema.

    Utiliza joined-table inheritance (igual que Scan): cada subclase define
    su propia tabla con los campos específicos y hereda estos mediante FK.

    Subclases:
        AegisDocument       — píldoras de concienciación
        SentinelDocument    — informes de escaneo

    Columnas:
        id            — PK autoincremental
        document_type — discriminador polimórfico ('aegis' | 'sentinel')
        filename      — ruta relativa al archivo en disco
        format        — 'pdf' | 'json' | 'md'
        status        — 'pending' | 'running' | 'done' | 'error'
        created_at    — momento de creación del registro (automático)
        generated_at  — momento en que terminó la generación (nullable)
        user_id       — FK a User

    Campos autogenerados (NO asignar manualmente):
        id, document_type, created_at
    """

    __tablename__ = "Document"

    id            = Column(Integer,     primary_key=True, autoincrement=True)
    document_type = Column(String(30),  nullable=False)

    filename      = Column(String(256), nullable=False)
    format        = Column(String(10),  nullable=False)

    status          = Column(String(20),  nullable=False, default="pending")
    created_at      = Column(DateTime,    nullable=False, default=datetime.utcnow)
    generated_at    = Column(DateTime,    nullable=True)
    is_ai_generated = Column(Integer,     nullable=False, default=1)

    user_id       = Column(Integer, ForeignKey("User.id"), nullable=False)
    user          = relationship("User", back_populates="documents")

    __mapper_args__ = {
        "polymorphic_identity": "document",
        "polymorphic_on":       document_type,
    }

    def __repr__(self) -> str:
        return (
            f"<Document(id={self.id}, type='{self.document_type}', "
            f"status='{self.status}', user_id={self.user_id})>"
        )