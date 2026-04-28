"""
src.modules.shared - Paquete de utilidades compartidas

Contiene las base classes y utilities que otros módulos necesitan:
    - BaseManager + initialize_engine
    - Base (SQLAlchemy)
    - Document
    - OAuth decorators y helpers
    - AIWriter base class

Este paquete no contiene endpoints, models específicos de módulos,
ni managers concretos. Esas responsabilidades viven en sus módulos respectivos.
"""

from ._model        import Base, Document
from ._managers     import BaseManager
from ._documents    import AIWriter
from ._endpoints    import _get_limiter, get_current_user_id, get_current_username, normalize_target

limiter = _get_limiter()

__all__ = [
    # Base
    "Base",
    "Document",
    # Managers
    "BaseManager",
    # AI
    "AIWriter",
    # Endpoints
    "limiter",
    "get_current_user_id", 
    "get_current_username",
    "normalize_target"
]