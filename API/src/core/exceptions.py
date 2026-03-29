"""
Sistema completo de excepciones personalizadas para SecOps.
Incluye jerarquía de excepciones, context, helpers y manejo centralizado.

Autor: SecOps Team
Versión: 2.0 - Mejorada y corregida
"""

from typing import Any, Dict, Optional, Type
from datetime import datetime
from enum import Enum
import traceback
import sys

# ============================================================================
# ENUMS PARA CÓDIGOS DE ERROR
# ============================================================================

class ErrorCode(Enum):
    """Códigos de error estandarizados para la API"""

    # Errores generales (1000-1099)
    UNKNOWN_ERROR = 1000
    INTERNAL_SERVER_ERROR = 1001
    NOT_IMPLEMENTED = 1002

    # Errores de validación (1100-1199)
    VALIDATION_ERROR = 1100
    INVALID_PORT_SPEC = 1101
    INVALID_IP_SPEC = 1102
    INVALID_URL = 1103
    INVALID_PARAMETER = 1104
    MISSING_PARAMETER = 1105

    # Errores de base de datos (1200-1299)
    DATABASE_ERROR = 1200
    ENTITY_NOT_FOUND = 1201
    ENTITY_ALREADY_EXISTS = 1202
    DATABASE_CONNECTION_ERROR = 1203
    TRANSACTION_ERROR = 1204
    CONSTRAINT_VIOLATION = 1205

    # Errores de escaneo (1300-1399)
    SCAN_ERROR = 1300
    SCAN_NOT_FOUND = 1301
    SCAN_ALREADY_RUNNING = 1302
    SCAN_NOT_FINISHED = 1303
    SCAN_EXECUTION_ERROR = 1304
    SCAN_TIMEOUT = 1305
    MAX_CONCURRENT_SCANS = 1306

    # Errores de reportes (1400-1499)
    REPORT_ERROR = 1400
    REPORT_GENERATION_ERROR = 1401
    REPORT_NOT_FOUND = 1402

    # Errores de configuración (1500-1599)
    CONFIGURATION_ERROR = 1500
    MISSING_CONFIG = 1501
    INVALID_CONFIG = 1502

    # Errores de autenticación/autorización (1600-1699)
    AUTHENTICATION_ERROR = 1600
    AUTHORIZATION_ERROR = 1601
    INVALID_CREDENTIALS = 1602
    USER_NOT_FOUND = 1603
    TOKEN_EXPIRED = 1604
    USER_ALREADY_EXISTS = 1605
    UNBINDABLE_USER = 1606
    DUPLICATED_CREDENTIALS = 1607

    # Errores de parsing (1700-1799)
    PARSING_ERROR = 1700
    XML_PARSING_ERROR = 1701
    JSON_PARSING_ERROR = 1702


class ErrorSeverity(Enum):
    """Severidad del error para logging y alertas"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# CLASE BASE DE EXCEPCIÓN
# ============================================================================

class SecOpsException(Exception):
    """
    Excepción base mejorada para SecOps.

    Características:
    - Código de error estandarizado
    - Contexto adicional
    - Severidad
    - Stack trace capturado
    - Serialización a dict/JSON
    - HTTP status code sugerido
    """

    # Valores por defecto (pueden ser sobreescritos por subclases)
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
        """
        Args:
            message: Mensaje técnico del error (para logs)
            code: Código de error estandarizado
            details: Detalles adicionales del error
            original_exception: Excepción original si es un wrapper
            severity: Severidad del error
            status_code: Código HTTP sugerido
            user_message: Mensaje amigable para el usuario final
        """
        super().__init__(message)
        self.message = message
        self.code = code or self.default_code
        self.details = details or {}
        self.original_exception = original_exception
        self.severity = severity or self.default_severity
        self.status_code = status_code or self.default_status_code
        self.user_message = user_message or self._generate_user_message()

        # Capturar información del contexto
        self.timestamp = datetime.utcnow()
        self.traceback = self._capture_traceback()

    def _generate_user_message(self) -> str:
        """Genera un mensaje amigable para el usuario"""
        # Mapeo de códigos a mensajes genéricos
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
        """Captura el stack trace actual"""
        if sys.exc_info()[0] is not None:
            return ''.join(traceback.format_exception(*sys.exc_info()))
        return traceback.format_stack()[-1] if traceback.format_stack() else ""

    def to_dict(self, include_traceback: bool = False) -> Dict[str, Any]:
        """
        Convierte la excepción a diccionario.

        Args:
            include_traceback: Si incluir el stack trace (solo en debug)

        Returns:
            Dict con información del error
        """
        result = {
            "error": self.__class__.__name__,
            "code": self.code.value,
            "message": self.user_message,  # Mensaje para el usuario
            "timestamp": self.timestamp.isoformat(),
        }

        # Agregar detalles si existen
        if self.details:
            result["details"] = self.details

        # Agregar información técnica en debug
        if include_traceback:
            result["technical_message"] = self.message
            result["traceback"] = self.traceback
            if self.original_exception:
                result["original_error"] = str(self.original_exception)

        return result

    def __str__(self) -> str:
        """Representación en string"""
        return f"[{self.code.name}] {self.message}"

    def __repr__(self) -> str:
        """Representación técnica"""
        return (
            f"{self.__class__.__name__}("
            f"code={self.code.name}, "
            f"message='{self.message}', "
            f"severity={self.severity.value})"
        )


# ============================================================================
# EXCEPCIONES DE VALIDACIÓN
# ============================================================================

class ValidationError(SecOpsException):
    """Error de validación de datos"""
    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 400
    default_severity = ErrorSeverity.LOW

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Any = None,
        expected: Optional[str] = None,
        **kwargs
    ):
        """
        Args:
            message: Mensaje descriptivo del error
            field: Campo que falló la validación
            value: Valor que causó el error
            expected: Valor o formato esperado
            **kwargs: Argumentos adicionales para SecOpsException
        """
        details = {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)
        if expected:
            details["expected"] = expected

        # Mezclar detalles con los que vienen en kwargs
        if "details" in kwargs:
            details.update(kwargs.pop("details"))

        # Construir mensaje de usuario si no viene en kwargs
        if "user_message" not in kwargs:
            if field:
                kwargs["user_message"] = f"El campo '{field}' no es válido: {message}"
            else:
                kwargs["user_message"] = f"Validación fallida: {message}"

        super().__init__(
            message=f"Validación fallida: {message}",
            details=details,
            **kwargs
        )


class PortValidationError(ValidationError):
    """Error en validación de puertos"""
    default_code = ErrorCode.INVALID_PORT_SPEC

    def __init__(self, message: str, port_spec: str):
        super().__init__(
            message=message,
            field="ports",
            value=port_spec,
            expected="Formato: '80', '80,443', '1-1000', '80,443-8080'"
        )


class IPValidationError(ValidationError):
    """Error en validación de IPs"""
    default_code = ErrorCode.INVALID_IP_SPEC

    def __init__(self, message: str, ip_spec: str):
        super().__init__(
            message=message,
            field="ip_address",
            value=ip_spec,
            expected="Formato: '192.168.1.1', '192.168.1.0/24', '192.168.1.1-10'"
        )


class URLValidationError(ValidationError):
    """Error en validación de URL"""
    default_code = ErrorCode.INVALID_URL

    def __init__(self, message: str, url: str):
        super().__init__(
            message=message,
            field="url",
            value=url,
            expected="URL válida: http://example.com o https://example.com"
        )


class MissingParameterError(ValidationError):
    """Parámetro requerido no proporcionado"""
    default_code = ErrorCode.MISSING_PARAMETER

    def __init__(self, parameter: str):
        super().__init__(
            message=f"Parámetro requerido '{parameter}' no proporcionado",
            field=parameter,
            user_message=f"El parámetro '{parameter}' es obligatorio."
        )


# ============================================================================
# EXCEPCIONES DE BASE DE DATOS
# ============================================================================

class DatabaseError(SecOpsException):
    """Error de base de datos"""
    default_code = ErrorCode.DATABASE_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.HIGH


class EntityNotFoundError(DatabaseError):
    """Entidad no encontrada"""
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
    """Entidad ya existe"""
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
    """Error de conexión a BD"""
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
    """Error en transacción"""
    default_code = ErrorCode.TRANSACTION_ERROR
    default_severity = ErrorSeverity.HIGH


# ============================================================================
# EXCEPCIONES DE ESCANEO
# ============================================================================

class ScanError(SecOpsException):
    """Error de escaneo base"""
    default_code = ErrorCode.SCAN_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class ScanNotFoundError(ScanError):
    """Escaneo no encontrado"""
    default_code = ErrorCode.SCAN_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, scan_id: int):
        super().__init__(
            message=f"Escaneo con ID {scan_id} no encontrado",
            details={"scan_id": scan_id},
            user_message=f"El escaneo #{scan_id} no existe."
        )


class ScanAlreadyRunningError(ScanError):
    """Escaneo ya en ejecución"""
    default_code = ErrorCode.SCAN_ALREADY_RUNNING
    default_status_code = 409
    default_severity = ErrorSeverity.LOW

    def __init__(self, target: str, scan_type: str = "escaneo"):
        super().__init__(
            message=f"Ya existe un {scan_type} en ejecución para '{target}'",
            details={"target": target, "scan_type": scan_type},
            user_message=f"Ya hay un {scan_type} activo para este objetivo."
        )


class ScanExecutionError(ScanError):
    """Error durante ejecución"""
    default_code = ErrorCode.SCAN_EXECUTION_ERROR
    default_severity = ErrorSeverity.HIGH

    def __init__(self, scan_type: str, target: str, reason: str):
        super().__init__(
            message=f"Error ejecutando {scan_type} en '{target}': {reason}",
            details={"scan_type": scan_type, "target": target, "reason": reason},
            user_message=f"Error durante el escaneo: {reason}"
        )


class ScanTimeoutError(ScanError):
    """Timeout de escaneo"""
    default_code = ErrorCode.SCAN_TIMEOUT
    default_status_code = 408
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, scan_id: int, timeout: int):
        super().__init__(
            message=f"Escaneo {scan_id} excedió timeout de {timeout}s",
            details={"scan_id": scan_id, "timeout": timeout},
            user_message=f"El escaneo excedió el tiempo límite de {timeout} segundos."
        )


class MaxConcurrentScansError(ScanError):
    """Límite de escaneos concurrentes"""
    default_code = ErrorCode.MAX_CONCURRENT_SCANS
    default_status_code = 429
    default_severity = ErrorSeverity.LOW

    def __init__(self, max_scans: int, current: int):
        super().__init__(
            message=f"Límite de escaneos concurrentes alcanzado ({current}/{max_scans})",
            details={"max_concurrent": max_scans, "current": current},
            user_message=f"Se alcanzó el límite de {max_scans} escaneos simultáneos."
        )


# ============================================================================
# EXCEPCIONES DE REPORTES
# ============================================================================

class ReportError(SecOpsException):
    """Error de reporte base"""
    default_code = ErrorCode.REPORT_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class ReportGenerationError(ReportError):
    """Error generando reporte"""
    default_code = ErrorCode.REPORT_GENERATION_ERROR

    def __init__(self, scan_id: int, reason: str):
        super().__init__(
            message=f"Error generando reporte para escaneo {scan_id}: {reason}",
            details={"scan_id": scan_id, "reason": reason},
            user_message="No se pudo generar el reporte."
        )


class ReportNotFoundError(ReportError):
    """Reporte no encontrado"""
    default_code = ErrorCode.REPORT_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, report_id: str):
        super().__init__(
            message=f"Reporte '{report_id}' no encontrado",
            details={"report_id": report_id},
            user_message="El reporte solicitado no existe."
        )


# ============================================================================
# EXCEPCIONES DE CONFIGURACIÓN
# ============================================================================

class ConfigurationError(SecOpsException):
    """Error de configuración"""
    default_code = ErrorCode.CONFIGURATION_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.CRITICAL


class MissingConfigError(ConfigurationError):
    """Configuración faltante"""
    default_code = ErrorCode.MISSING_CONFIG

    def __init__(self, config_key: str):
        super().__init__(
            message=f"Configuración requerida '{config_key}' no encontrada",
            details={"config_key": config_key},
            user_message="Error de configuración del servidor."
        )


# ============================================================================
# EXCEPCIONES DE AUTENTICACIÓN
# ============================================================================

class AuthenticationError(SecOpsException):
    """Error de autenticación"""
    default_code = ErrorCode.AUTHENTICATION_ERROR
    default_status_code = 401
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, message: str = "Error de autenticación", **kwargs):
        if "user_message" not in kwargs:
            kwargs["user_message"] = "No se pudo verificar su identidad."
        super().__init__(message=message, **kwargs)


class AuthorizationError(SecOpsException):
    """Error de autorización"""
    default_code = ErrorCode.AUTHORIZATION_ERROR
    default_status_code = 403
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, message: str = "Error de autorización", **kwargs):
        if "user_message" not in kwargs:
            kwargs["user_message"] = "No tiene permisos para realizar esta acción."
        super().__init__(message=message, **kwargs)


class InvalidCredentialsError(AuthenticationError):
    """Credenciales inválidas"""
    default_code = ErrorCode.INVALID_CREDENTIALS

    def __init__(self):
        super().__init__(
            message="Credenciales inválidas",
            user_message="Usuario o contraseña incorrectos."
        )


class UserNotFoundError(AuthenticationError):
    """Usuario no encontrado"""
    default_code = ErrorCode.USER_NOT_FOUND

    def __init__(self, user_id: int):
        super().__init__(
            message=f"Usuario '{user_id}' no encontrado",
            details={"id_usuario": user_id},
            user_message="Usuario no encontrado."
        )


class UserBindingError(AuthenticationError):
    """Error al vincular usuario con persona"""
    default_code = ErrorCode.UNBINDABLE_USER

    def __init__(self, username: str, alias: str):
        super().__init__(
            message=f"No se pudo vincular el usuario '{username}' con una persona existente",
            details={"username": username},
            user_message=f"Error al crear el usuario debido a datos incompletos; no se tiene constancia de una persona con alias '{alias}'"
        )


class DuplicatedUserCredentials(AuthenticationError):
    default_code = ErrorCode.DUPLICATED_CREDENTIALS

    def __init__(self, credentials: str):
        super().__init__(
            message=f"Se ha detectado una credencial duplicada para un usuario",
            user_message=f"Se ha detectedo duplicidad de datos para el siguiente valor: {credentials}"
        )


class ExistingUserError(AuthenticationError):
    """Usuario ya existe"""
    default_code = ErrorCode.USER_ALREADY_EXISTS

    def __init__(self, username: str):
        super().__init__(
            message=f"Usuario '{username}' ya existe",
            details={"username": username},
            user_message="El usuario ya existe."
        )


# ============================================================================
# EXCEPCIONES DE PARSING
# ============================================================================

class ParsingError(SecOpsException):
    """Error de parsing"""
    default_code = ErrorCode.PARSING_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class XMLParsingError(ParsingError):
    """Error parseando XML"""
    default_code = ErrorCode.XML_PARSING_ERROR

    def __init__(self, file_path: str, reason: str):
        super().__init__(
            message=f"Error parseando XML '{file_path}': {reason}",
            details={"file_path": file_path, "reason": reason},
            user_message="Error procesando resultados del escaneo."
        )


class JSONParsingError(ParsingError):
    """Error parseando JSON"""
    default_code = ErrorCode.JSON_PARSING_ERROR

    def __init__(self, data: str, reason: str):
        super().__init__(
            message=f"Error parseando JSON: {reason}",
            details={"data": data[:100], "reason": reason},  # Solo primeros 100 chars
            user_message="Error procesando datos JSON."
        )


# ============================================================================
# UTILIDADES PARA MANEJO DE EXCEPCIONES
# ============================================================================

class ExceptionHandler:
    """Manejador centralizado de excepciones"""

    @staticmethod
    def wrap_exception(
        exc: Exception,
        default_exception_class: Type[SecOpsException] = SecOpsException,
        logger=None
    ) -> SecOpsException:
        """
        Envuelve excepciones genéricas en SecOpsException.

        Args:
            exc: Excepción a envolver
            default_exception_class: Clase de excepción por defecto
            logger: Logger para registrar el error

        Returns:
            SecOpsException apropiada
        """
        # Si ya es SecOpsException, retornar directamente
        if isinstance(exc, SecOpsException):
            return exc

        # Registrar error si hay logger
        if logger:
            logger.error(f"Excepción no manejada: {exc}", exc_info=True)

        # Mapear excepciones comunes
        exc_type = type(exc).__name__
        exc_message = str(exc)

        # Mapear excepciones de SQLAlchemy/bases de datos
        if any(keyword in exc_type for keyword in ["SQL", "Database", "Integrity"]):
            return DatabaseError(
                message=f"Error de base de datos: {exc_message}",
                original_exception=exc
            )

        # Mapear timeouts
        if "Timeout" in exc_type or "timeout" in exc_message.lower():
            return ScanTimeoutError(scan_id=0, timeout=0)

        # Mapear errores de conexión
        if "Connection" in exc_type or "connection" in exc_message.lower():
            return DatabaseConnectionError(
                message=f"Error de conexión: {exc_message}"
            )

        # Mapear errores de parsing
        if any(keyword in exc_type for keyword in ["JSON", "XML", "Parse"]):
            return ParsingError(
                message=f"Error de parsing: {exc_message}",
                original_exception=exc
            )

        # Por defecto, usar la clase proporcionada
        return default_exception_class(
            message=f"Error inesperado: {exc_message}",
            details={"exception_type": exc_type},
            original_exception=exc
        )

    @staticmethod
    def handle_and_log(exc: Exception, logger) -> SecOpsException:
        """
        Maneja una excepción y la registra apropiadamente.

        Args:
            exc: Excepción a manejar
            logger: Logger para registrar

        Returns:
            SecOpsException procesada
        """
        secops_exc = ExceptionHandler.wrap_exception(exc, logger=logger)

        # Log según severidad
        if secops_exc.severity == ErrorSeverity.CRITICAL:
            logger.critical(secops_exc.message, exc_info=True)
        elif secops_exc.severity == ErrorSeverity.HIGH:
            logger.error(secops_exc.message, exc_info=True)
        elif secops_exc.severity == ErrorSeverity.MEDIUM:
            logger.warning(secops_exc.message)
        else:
            logger.info(secops_exc.message)

        return secops_exc


# ============================================================================
# DECORADOR PARA MANEJO AUTOMÁTICO DE EXCEPCIONES
# ============================================================================

def handle_exceptions(
    default_exception: Type[SecOpsException] = SecOpsException,
    logger=None,
    re_raise: bool = True
):
    """
    Decorador que maneja excepciones automáticamente.

    Args:
        default_exception: Clase de excepción por defecto
        logger: Logger opcional
        re_raise: Si re-lanzar la excepción después de procesarla

    Ejemplo:
        @handle_exceptions(default_exception=DatabaseError, logger=my_logger)
        def my_function():
            # código que puede lanzar excepciones
            pass
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except SecOpsException:
                # Ya es una excepción manejada, re-lanzar
                raise
            except Exception as e:
                # Convertir a SecOpsException
                secops_exc = ExceptionHandler.wrap_exception(
                    e,
                    default_exception_class=default_exception,
                    logger=logger
                )
                if re_raise:
                    raise secops_exc from e
                return secops_exc
        return wrapper
    return decorator


# ============================================================================
# HELPER PARA CREAR RESPUESTAS DE ERROR CONSISTENTES
# ============================================================================

def create_error_response(
    exception: SecOpsException,
    include_debug_info: bool = False
) -> tuple[Dict[str, Any], int]:
    """
    Crea una respuesta de error consistente para la API.

    Args:
        exception: Excepción a convertir en respuesta
        include_debug_info: Si incluir información de debug

    Returns:
        Tupla de (dict con error, status_code)
    """
    error_dict = exception.to_dict(include_traceback=include_debug_info)
    return error_dict, exception.status_code


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Enums
    'ErrorCode',
    'ErrorSeverity',

    # Excepción base
    'SecOpsException',

    # Excepciones de validación
    'ValidationError',
    'PortValidationError',
    'IPValidationError',
    'URLValidationError',
    'MissingParameterError',

    # Excepciones de base de datos
    'DatabaseError',
    'EntityNotFoundError',
    'EntityAlreadyExistsError',
    'DatabaseConnectionError',
    'TransactionError',

    # Excepciones de escaneo
    'ScanError',
    'ScanNotFoundError',
    'ScanAlreadyRunningError',
    'ScanExecutionError',
    'ScanTimeoutError',
    'MaxConcurrentScansError',

    # Excepciones de reportes
    'ReportError',
    'ReportGenerationError',
    'ReportNotFoundError',

    # Excepciones de configuración
    'ConfigurationError',
    'MissingConfigError',

    # Excepciones de autenticación
    'AuthenticationError',
    'AuthorizationError',
    'InvalidCredentialsError',
    'UserNotFoundError',
    'ExistingUserError',

    # Excepciones de parsing
    'ParsingError',
    'XMLParsingError',
    'JSONParsingError',

    # Utilidades
    'ExceptionHandler',
    'handle_exceptions',
    'create_error_response',
]
