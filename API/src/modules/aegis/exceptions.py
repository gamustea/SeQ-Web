from src.modules.shared._exceptions import (
    SecOpsException,
    ErrorCode,
    ErrorSeverity,
    ValidationError,
    DatabaseError,
    EntityAlreadyExistsError,
)


class AegisValidationError(ValidationError):
    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 400

    def __init__(self, message: str, field: str | None = None, value: str | None = None):
        details = {}
        if field:
            details["field"] = field
        if value:
            details["value"] = value
        super().__init__(
            message=message,
            details=details,
            user_message=f"Error de validación: {message}"
        )


class AegisInsufficientContentError(AegisValidationError):
    default_code = ErrorCode.VALIDATION_ERROR

    def __init__(self, expected: int, found: int):
        super().__init__(
            message=f"Contenido insuficiente: esperados {expected}, encontrados {found}",
            field="tips",
            value=str(found)
        )


class AegisFetchError(SecOpsException):
    default_code = ErrorCode.INTERNAL_SERVER_ERROR

    def __init__(self, source: str, message: str):
        super().__init__(
            message=f"Error fetching {source}: {message}",
            details={"source": source},
            user_message=f"Error al obtener alertas de {source}."
        )


class DocumentError(SecOpsException):
    default_code = ErrorCode.REPORT_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class DocumentNotFoundError(DocumentError):
    default_code = ErrorCode.REPORT_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, doc_id: int):
        super().__init__(
            message=f"Documento {doc_id} no encontrado",
            details={"document_id": doc_id},
            user_message=f"Documento {doc_id} no encontrado."
        )


class DocumentNotReadyError(DocumentError):
    default_code = ErrorCode.SCAN_NOT_FINISHED
    default_status_code = 409

    def __init__(self, doc_id: int, status: str):
        super().__init__(
            message=f"Documento {doc_id} no disponible (estado: {status})",
            details={"document_id": doc_id, "status": status},
            user_message="El documento aún no está listo."
        )


class DocumentGenerationError(DocumentError):
    default_code = ErrorCode.REPORT_GENERATION_ERROR


class AIConnectionError(DocumentError):
    default_code = ErrorCode.INTERNAL_SERVER_ERROR
    default_severity = ErrorSeverity.HIGH

    def __init__(self, message: str, model: str | None = None):
        details = {"model": model} if model else {}
        super().__init__(
            message=f"Error de conexión con IA: {message}",
            details=details,
            user_message="Error al conectar con el servicio de IA."
        )


class AIResponseError(DocumentError):
    default_code = ErrorCode.INTERNAL_SERVER_ERROR

    def __init__(self, message: str, attempt: int = 0):
        super().__init__(
            message=f"Error en respuesta de IA (intento {attempt}): {message}",
            details={"attempt": attempt},
            user_message="La IA generó una respuesta inválida."
        )


class AIFallbackExhaustedError(DocumentError):
    default_code = ErrorCode.INTERNAL_SERVER_ERROR
    default_severity = ErrorSeverity.HIGH

    def __init__(self, attempts: int, last_error: str):
        super().__init__(
            message=f"Fallo tras {attempts} intentos: {last_error}",
            details={"attempts": attempts, "last_error": last_error},
            user_message="No se pudo generar el contenido tras varios intentos."
        )


class CircuitBreakerOpenError(DocumentError):
    default_code = ErrorCode.INTERNAL_SERVER_ERROR

    def __init__(self, service: str):
        super().__init__(
            message=f"Circuit breaker abierto para {service}",
            details={"service": service},
            user_message="El servicio está temporalmente no disponible."
        )


class ExporterError(DocumentError):
    default_code = ErrorCode.REPORT_ERROR


class ExporterFormatError(ExporterError):
    default_code = ErrorCode.INVALID_PARAMETER
    default_status_code = 400

    def __init__(self, format: str):
        super().__init__(
            message=f"Formato de exportación no soportado: {format}",
            details={"format": format},
            user_message=f"El formato '{format}' no es soportado."
        )


class ExporterConfigurationError(ExporterError):
    default_code = ErrorCode.CONFIGURATION_ERROR
    default_status_code = 500

    def __init__(self, missing_fields: list[str]):
        super().__init__(
            message=f"Exportador mal configurado. Faltan: {missing_fields}",
            details={"missing_fields": missing_fields},
            user_message="Error de configuración del exportador."
        )