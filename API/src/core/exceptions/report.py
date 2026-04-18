from .base import SecOpsException, ErrorCode, ErrorSeverity


class ReportError(SecOpsException):
    default_code = ErrorCode.REPORT_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class ReportGenerationError(ReportError):
    default_code = ErrorCode.REPORT_GENERATION_ERROR

    def __init__(self, scan_id: int, reason: str):
        super().__init__(
            message=f"Error generando reporte para escaneo {scan_id}: {reason}",
            details={"scan_id": scan_id, "reason": reason},
            user_message="No se pudo generar el reporte."
        )


class ReportNotFoundError(ReportError):
    default_code = ErrorCode.REPORT_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, report_id: str):
        super().__init__(
            message=f"Reporte '{report_id}' no encontrado",
            details={"report_id": report_id},
            user_message="El reporte solicitado no existe."
        )