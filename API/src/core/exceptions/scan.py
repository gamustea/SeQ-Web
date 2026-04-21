from typing import Optional

from .base import SecOpsException, ErrorCode, ErrorSeverity


class ScanError(SecOpsException):
    default_code = ErrorCode.SCAN_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class ScanNotFoundError(ScanError):
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
    default_code = ErrorCode.SCAN_EXECUTION_ERROR
    default_severity = ErrorSeverity.HIGH

    def __init__(self, scan_type: str, target: str, reason: str):
        super().__init__(
            message=f"Error ejecutando {scan_type} en '{target}': {reason}",
            details={"scan_type": scan_type, "target": target, "reason": reason},
            user_message=f"Error durante el escaneo: {reason}"
        )


class ScanTimeoutError(ScanError):
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
    default_code = ErrorCode.MAX_CONCURRENT_SCANS
    default_status_code = 429
    default_severity = ErrorSeverity.LOW

    def __init__(self, max_scans: int, current: int):
        super().__init__(
            message=f"Límite de escaneos concurrentes alcanzado ({current}/{max_scans})",
            details={"max_concurrent": max_scans, "current": current},
            user_message=f"Se alcanzó el límite de {max_scans} escaneos simultáneos."
        )