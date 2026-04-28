from typing import Any, Dict, Optional
from datetime import datetime
from enum import Enum
import traceback
import sys


class ErrorCode(Enum):
    """Códigos de error estandarizados para la API"""

    UNKNOWN_ERROR = 1000
    INTERNAL_SERVER_ERROR = 1001
    NOT_IMPLEMENTED = 1002

    VALIDATION_ERROR = 1100
    INVALID_PORT_SPEC = 1101
    INVALID_IP_SPEC = 1102
    INVALID_URL = 1103
    INVALID_PARAMETER = 1104
    MISSING_PARAMETER = 1105

    DATABASE_ERROR = 1200
    ENTITY_NOT_FOUND = 1201
    ENTITY_ALREADY_EXISTS = 1202
    DATABASE_CONNECTION_ERROR = 1203
    TRANSACTION_ERROR = 1204
    CONSTRAINT_VIOLATION = 1205

    SCAN_ERROR = 1300
    SCAN_NOT_FOUND = 1301
    SCAN_ALREADY_RUNNING = 1302
    SCAN_NOT_FINISHED = 1303
    SCAN_EXECUTION_ERROR = 1304
    SCAN_TIMEOUT = 1305
    MAX_CONCURRENT_SCANS = 1306

    REPORT_ERROR = 1400
    REPORT_GENERATION_ERROR = 1401
    REPORT_NOT_FOUND = 1402

    CONFIGURATION_ERROR = 1500
    MISSING_CONFIG = 1501
    INVALID_CONFIG = 1502

    AUTHENTICATION_ERROR = 1600
    AUTHORIZATION_ERROR = 1601
    INVALID_CREDENTIALS = 1602
    USER_NOT_FOUND = 1603
    TOKEN_EXPIRED = 1604
    USER_ALREADY_EXISTS = 1605
    UNBINDABLE_USER = 1606
    DUPLICATED_CREDENTIALS = 1607
    PROFILE_UPDATE_ERROR = 1608
    PARSING_ERROR = 1700
    XML_PARSING_ERROR = 1701
    JSON_PARSING_ERROR = 1702


class ErrorSeverity(Enum):
    """Severidad del error para logging y alertas"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecOpsException(Exception):
    default_code = ErrorCode.UNKNOWN_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM

    def __init__(
        self,
        message: str,
        code: Optional[ErrorCode] = None,
        details: Optional[Dict[str, Any]] = None,
        original_exception: Optional[Exception] = None,
        severity: Optional[ErrorSeverity] = None,
        status_code: Optional[int] = None,
        user_message: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code or self.default_code
        self.details = details or {}
        self.original_exception = original_exception
        self.severity = severity or self.default_severity
        self.status_code = status_code or self.default_status_code
        self.user_message = user_message or self._generate_user_message()

        self.timestamp = datetime.utcnow()
        self.traceback = self._capture_traceback()

    def _generate_user_message(self) -> str:
        user_messages = {
            ErrorCode.VALIDATION_ERROR: "Los datos proporcionados no son válidos.",
            ErrorCode.MISSING_PARAMETER: "Falta un parámetro requerido.",
            ErrorCode.DATABASE_ERROR: "Error al acceder a la base de datos.",
            ErrorCode.SCAN_ERROR: "Error durante el escaneo.",
            ErrorCode.AUTHENTICATION_ERROR: "Error de autenticación.",
            ErrorCode.INVALID_CREDENTIALS: "Usuario o contraseña incorrectos.",
            ErrorCode.INTERNAL_SERVER_ERROR: "Ha ocurrido un error interno.",
        }
        return user_messages.get(self.code, "Ha ocurrido un error inesperado.")

    def _capture_traceback(self) -> str:
        if sys.exc_info()[0] is not None:
            return ''.join(traceback.format_exception(*sys.exc_info()))
        return traceback.format_stack()[-1] if traceback.format_stack() else ""

    def to_dict(self, include_traceback: bool = False) -> Dict[str, Any]:
        result = {
            "error": self.__class__.__name__,
            "code": self.code.value,
            "message": self.user_message,
            "timestamp": self.timestamp.isoformat(),
        }

        if self.details:
            result["details"] = self.details

        if include_traceback:
            result["technical_message"] = self.message
            result["traceback"] = self.traceback
            if self.original_exception:
                result["original_error"] = str(self.original_exception)

        return result

    def __str__(self) -> str:
        return f"[{self.code.name}] {self.message}"

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"code={self.code.name}, "
            f"message='{self.message}', "
            f"severity={self.severity.value})"
        )