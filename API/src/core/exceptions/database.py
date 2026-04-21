from typing import Any, Optional

from .base import SecOpsException, ErrorCode, ErrorSeverity


class DatabaseError(SecOpsException):
    default_code = ErrorCode.DATABASE_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.HIGH


class EntityNotFoundError(DatabaseError):
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, entity_type: str, identifier: Any):
        super().__init__(
            message=f"{entity_type} con identificador {identifier} no encontrado",
            details={"entity_type": entity_type, "identifier": str(identifier)},
            user_message=f"{entity_type} no encontrado."
        )


class EntityAlreadyExistsError(DatabaseError):
    default_code = ErrorCode.ENTITY_ALREADY_EXISTS
    default_status_code = 409
    default_severity = ErrorSeverity.LOW

    def __init__(self, entity_type: str, identifier: str):
        super().__init__(
            message=f"{entity_type} con identificador '{identifier}' ya existe",
            details={"entity_type": entity_type, "identifier": identifier},
            user_message=f"El {entity_type} ya existe."
        )


class DatabaseConnectionError(DatabaseError):
    default_code = ErrorCode.DATABASE_CONNECTION_ERROR
    default_severity = ErrorSeverity.CRITICAL

    def __init__(self, message: str, host: Optional[str] = None):
        details = {"host": host} if host else {}
        super().__init__(
            message=f"Error de conexión a base de datos: {message}",
            details=details,
            user_message="No se pudo conectar a la base de datos."
        )


class TransactionError(DatabaseError):
    default_code = ErrorCode.TRANSACTION_ERROR
    default_severity = ErrorSeverity.HIGH