from typing import Any, Dict, Optional, Type

from ._base import SecOpsException, ErrorCode, ErrorSeverity
from .database import DatabaseError, DatabaseConnectionError
from .scan import ScanTimeoutError
from .parsing import ParsingError


class ExceptionHandler:
    @staticmethod
    def wrap_exception(
        exc: Exception,
        default_exception_class: Type[SecOpsException] = SecOpsException,
        logger=None
    ) -> SecOpsException:
        if isinstance(exc, SecOpsException):
            return exc

        if logger:
            logger.error(f"Excepción no manejada: {exc}", exc_info=True)

        exc_type = type(exc).__name__
        exc_message = str(exc)

        if any(keyword in exc_type for keyword in ["SQL", "Database", "Integrity"]):
            return DatabaseError(
                message=f"Error de base de datos: {exc_message}",
                original_exception=exc
            )

        if "Timeout" in exc_type or "timeout" in exc_message.lower():
            return ScanTimeoutError(scan_id=0, timeout=0)

        if "Connection" in exc_type or "connection" in exc_message.lower():
            return DatabaseConnectionError(
                message=f"Error de conexión: {exc_message}"
            )

        if any(keyword in exc_type for keyword in ["JSON", "XML", "Parse"]):
            return ParsingError(
                message=f"Error de parsing: {exc_message}",
                original_exception=exc
            )

        return default_exception_class(
            message=f"Error inesperado: {exc_message}",
            details={"exception_type": exc_type},
            original_exception=exc
        )

    @staticmethod
    def handle_and_log(exc: Exception, logger) -> SecOpsException:
        secops_exc = ExceptionHandler.wrap_exception(exc, logger=logger)

        if secops_exc.severity == ErrorSeverity.CRITICAL:
            logger.critical(secops_exc.message, exc_info=True)
        elif secops_exc.severity == ErrorSeverity.HIGH:
            logger.error(secops_exc.message, exc_info=True)
        elif secops_exc.severity == ErrorSeverity.MEDIUM:
            logger.warning(secops_exc.message)
        else:
            logger.info(secops_exc.message)

        return secops_exc


def handle_exceptions(
    default_exception: Type[SecOpsException] = SecOpsException,
    logger=None,
    re_raise: bool = True
):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except SecOpsException:
                raise
            except Exception as e:
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


def create_error_response(
    exception: SecOpsException,
    include_debug_info: bool = False
) -> tuple[Dict[str, Any], int]:
    error_dict = exception.to_dict(include_traceback=include_debug_info)
    return error_dict, exception.status_code