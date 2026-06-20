"""src.modules.shared - Paquete de utilidades compartidas.

Contiene las base classes y utilities que otros módulos necesitan:
    - BaseManager + initialize_engine
    - Base (SQLAlchemy)
    - Document
    - OAuth decorators y helpers

La generación con IA vive ahora en el módulo `scribe`, no aquí.

Este paquete no contiene endpoints, models específicos de módulos,
ni managers concretos. Esas responsabilidades viven en sus módulos respectivos.
"""

from ._model        import Base, Document
from ._managers     import BaseManager
from ._exceptions   import handle_exceptions, ExceptionHandler
from ._endpoints    import (
    current_actor,
    normalize_target,
    require_json,
    require_str,
    require_arg,
    limiter
)
from .schemas import ErrorSchema, SuccessMessageSchema, PaginationQuerySchema

__all__ = [
    "Base",
    "Document",
    "BaseManager",
    "handle_exceptions",
    "ExceptionHandler",
    "current_actor",
    "normalize_target",
    "require_json",
    "require_str",
    "require_arg",
    "limiter",
    "ErrorSchema",
    "SuccessMessageSchema",
    "PaginationQuerySchema"
]