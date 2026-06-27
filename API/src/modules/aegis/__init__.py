"""
src.modules.aegis - Módulo de concienciación en ciberseguridad

Exponente:
    - AegisManager: Generación de píldoras
    - Modelos: AegisDocument, AegisTip, Topic
    - Endpoints: aegis_bp
"""

from src.modules.system.taskqueue import QueueRegistry

from .model import (
    AegisDocument,
    AegisDocumentAlert,
    AegisTip,
    Topic,
)
from .managers import AegisManager
from .endpoints import aegis_blp

# Registro de la categoría de cola de este módulo (OCP).
QueueRegistry.register("aegis.generate")

__all__ = [
    "AegisDocument",
    "AegisDocumentAlert",
    "AegisTip",
    "Topic",
    "AegisManager",
    "aegis_blp",
]