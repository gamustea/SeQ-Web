"""
src.modules.aegis - Módulo de concienciación en ciberseguridad

Exponente:
    - AegisManager: Generación de píldoras
    - Modelos: AegisDocument, AegisTip, Topic
    - Endpoints: aegis_bp
"""

from .model import (
    AegisDocument,
    AegisDocumentAlert,
    AegisTip,
    Topic,
)
from .managers import AegisManager
from .endpoints import aegis_bp
from .pills import (
    AegisAIWriter,
    AegisContent,
    AegisAlert,
    AegisAlertFetcher,
)
from .exporters import (
    ExportFormat,
    ExportData,
    get_exporter_for_format,
)

__all__ = [
    # Models
    "AegisDocument",
    "AegisDocumentAlert",
    "AegisTip",
    "Topic",
    # Managers
    "AegisManager",
    # Endpoints
    "aegis_bp",
    # Pills
    "AegisAIWriter",
    "AegisContent",
    "AegisAlert",
    "AegisAlertFetcher",
    # Exporters
    "ExportFormat",
    "ExportData",
]