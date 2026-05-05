"""
Excepciones específicas del módulo Sentinel (escaneos de seguridad).

Este módulo define las excepciones utilizadas en el flujo de escaneos
de seguridad (Nmap, Nikto, OpenVAS) y generación de reportes.

Excepciones de Escaneo:
    - ScanError: Excepción base para errores de escaneo.
    - ScanNotFoundError: Cuando un escaneo no existe en la base de datos.
    - ScanAlreadyRunningError: Cuando ya hay un escaneo en ejecución.
    - ScanExecutionError: Error durante la ejecución del escaneo.
    - ScanTimeoutError: El escaneo excedió el tiempo límite.
    - MaxConcurrentScansError: Se alcanzó el límite de escaneos concurrentes.

Excepciones de Reportes:
    - ReportError: Excepción base para errores de reportes.
    - ReportGenerationError: Error al generar un reporte.
    - ReportNotFoundError: Cuando un reporte no existe.
    - PDFGenerationError: Error específico al generar PDF.

Excepciones de Validación:
    - PortValidationError: Especificación de puerto inválida.
    - IPValidationError: Especificación de IP inválida.
    - URLValidationError: URL inválida.

Ejemplo de uso:
    >>> raise ScanNotFoundError(scan_id=42)
    >>> raise ScanExecutionError(scan_type="nmap", target="192.168.1.1", reason="Timeout")
    >>> raise PortValidationError(message="Puerto inválido", port_spec="invalid")
"""

from src.modules.shared._exceptions import (
    SecOpsException,
    ErrorCode,
    ErrorSeverity,
    ValidationError,
)


class ScanError(SecOpsException):
    """
    Excepción base para errores relacionados con escaneos de seguridad.

    Esta clase sirve como padre para todas las excepciones de escaneos.
    Por defecto retorna código 500 (Error interno del servidor) con
    severidad MEDIA.

    Atributos:
        default_code: Código de error por defecto (SCAN_ERROR).
        default_status_code: Código HTTP por defecto (500).
        default_severity: Severidad por defecto (MEDIUM).
    """

    default_code = ErrorCode.SCAN_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class ScanNotFoundError(ScanError):
    """
    Excepción lanzada cuando no se encuentra un escaneo en la base de datos.

    Se usa cuando se intenta acceder a un escaneo por su ID pero este
    no existe o ha sido eliminado.

    Atributos:
        default_code: Código de error (SCAN_NOT_FOUND).
        default_status_code: HTTP 404 (No encontrado).
        default_severity: LOW.

    Args:
        scan_id: ID del escaneo que no se encontró.

    Ejemplo:
        >>> raise ScanNotFoundError(scan_id=123)
    """

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
    """
    Excepción lanzada cuando ya existe un escaneo en ejecución para un objetivo.

    Se usa para prevenir múltiples escaneos simultáneos sobre el mismo objetivo.

    Atributos:
        default_code: Código de error (SCAN_ALREADY_RUNNING).
        default_status_code: HTTP 409 (Conflicto).
        default_severity: LOW.

    Args:
        target: Objetivo del escaneo (IP, dominio, etc.).
        scan_type: Tipo de escaneo (nmap, nikto, openvas).

    Ejemplo:
        >>> raise ScanAlreadyRunningError(target="192.168.1.1", scan_type="nmap")
    """

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
    """
    Excepción lanzada cuando ocurre un error durante la ejecución de un escaneo.

    Se usa para errores que ocurren durante el proceso de escaneo, tales como:
    fallos en la conexión, errores del proceso hijo, o problemas de permisos.

    Atributos:
        default_code: Código de error (SCAN_EXECUTION_ERROR).
        default_severity: HIGH.

    Args:
        scan_type: Tipo de escaneo (nmap, nikto, openvas).
        target: Objetivo del escaneo.
        reason: Descripción del error que ocurrió.

    Ejemplo:
    >>> raise ScanExecutionError(
    ...    scan_type="nmap",
    ...    target="192.168.1.1",
    ...    reason="Permission denied"
    )
    """

    default_code = ErrorCode.SCAN_EXECUTION_ERROR
    default_severity = ErrorSeverity.HIGH

    def __init__(self, scan_type: str, target: str, reason: str):
        super().__init__(
            message=f"Error ejecutando {scan_type} en '{target}': {reason}",
            details={"scan_type": scan_type, "target": target, "reason": reason},
            user_message=f"Error durante el escaneo: {reason}"
        )


class ScanTimeoutError(ScanError):
    """
    Excepción lanzada cuando un escaneo excede el tiempo límite establecido.

    Se usa cuando el timeout configurado se agota antes de que el escaneo
    finalice naturalmente.

    Atributos:
        default_code: Código de error (SCAN_TIMEOUT).
        default_status_code: HTTP 408 (Request Timeout).
        default_severity: MEDIUM.

    Args:
        scan_id: ID del escaneo que excedió el timeout.
        timeout: Tiempo límite en segundos configurado.

    Ejemplo:
        >>> raise ScanTimeoutError(scan_id=42, timeout=300)
    """

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
    """
    Excepción lanzada cuando se alcanza el límite de escaneos concurrentes.

    Se usa para limitar el número de escaneos simultáneos que un usuario
    puede tener en ejecución.

    Atributos:
        default_code: Código de error (MAX_CONCURRENT_SCANS).
        default_status_code: HTTP 429 (Too Many Requests).
        default_severity: LOW.

    Args:
        max_scans: Número máximo de escaneos permitidos.
        current: Número actual de escaneos en ejecución.

    Ejemplo:
        >>> raise MaxConcurrentScansError(max_scans=5, current=5)
    """

    default_code = ErrorCode.MAX_CONCURRENT_SCANS
    default_status_code = 429
    default_severity = ErrorSeverity.LOW

    def __init__(self, max_scans: int, current: int):
        super().__init__(
            message=f"Límite de escaneos concurrentes alcanzado ({current}/{max_scans})",
            details={"max_concurrent": max_scans, "current": current},
            user_message=f"Se alcanzó el límite de {max_scans} escaneos simultáneos."
        )


class ReportError(SecOpsException):
    """
    Excepción base para errores relacionados con reportes y documentos.

    Esta clase sirve como padre para todas las excepciones de reportes.
    Por defecto retorna código 500 con severidad MEDIA.

    Atributos:
        default_code: Código de error por defecto (REPORT_ERROR).
        default_status_code: Código HTTP por defecto (500).
        default_severity: Severidad por defecto (MEDIUM).
    """

    default_code = ErrorCode.REPORT_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class ReportGenerationError(ReportError):
    """
    Excepción lanzada cuando ocurre un error al generar un reporte.

    Se usa cuando el procesamiento de resultados del escaneo falla o
    no se pueden generar los datos del reporte.

    Atributos:
        default_code: Código de error (REPORT_GENERATION_ERROR).

    Args:
        scan_id: ID del escaneo para el que se genera el reporte.
        reason: Descripción del error de generación.

    Ejemplo:
    >>> raise ReportGenerationError(scan_id=42, reason="Error al parsear resultados")
    """

    default_code = ErrorCode.REPORT_GENERATION_ERROR

    def __init__(self, scan_id: int, reason: str):
        super().__init__(
            message=f"Error generando reporte para escaneo {scan_id}: {reason}",
            details={"scan_id": scan_id, "reason": reason},
            user_message="No se pudo generar el reporte."
        )


class ReportNotFoundError(ReportError):
    """
    Excepción lanzada cuando no se encuentra un reporte o documento.

    Se usa cuando se intenta acceder a un reporte que no existe o
    no está disponible para el usuario.

    Atributos:
        default_code: Código de error (REPORT_NOT_FOUND).
        default_status_code: HTTP 404 (No encontrado).
        default_severity: LOW.

    Args:
        report_id: Identificador del reporte no encontrado.

    Ejemplo:
        >>> raise ReportNotFoundError(report_id="doc_123")
    """

    default_code = ErrorCode.REPORT_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, report_id: str):
        super().__init__(
            message=f"Reporte '{report_id}' no encontrado",
            details={"report_id": report_id},
            user_message="El reporte solicitado no existe."
        )


class PortValidationError(ValidationError):
    """
    Excepción lanzada cuando la especificación de puertos es inválida.

    Se usa para validar el formato de los puertos especificados en un
    escaneo Nmap. Los formatos válidos son: puerto único (80), lista
    (80,443), rango (1-1000) o combinación (80,443-8080).

    Atributos:
        default_code: Código de error (INVALID_PORT_SPEC).

    Args:
        message: Descripción del error de validación.
        port_spec: Especificación de puertos proporcionada por el usuario.

    Ejemplo:
        >>> raise PortValidationError(message="Puerto inválido", port_spec="abc")
    """

    default_code = ErrorCode.INVALID_PORT_SPEC

    def __init__(self, message: str, port_spec: str):
        super().__init__(
            message=message,
            field="ports",
            value=port_spec,
            expected="Formato: '80', '80,443', '1-1000', '80,443-8080'"
        )


class IPValidationError(ValidationError):
    """
    Excepciónlana cuando la especificación de IP es inválida.

    Se usa para validar el formato de la dirección IP o rango CIDR
    proporcionado para un escaneo. Los formatos válidos son: IP única
    (192.168.1.1), rango CIDR (192.168.1.0/24), o rango (192.168.1.1-10).

    Atributos:
        default_code: Código de error (INVALID_IP_SPEC).

    Args:
        message: Descripción del error de validación.
        ip_spec: Especificación de IP proporcionada por el usuario.

    Ejemplo:
        >>> raise IPValidationError(message="IP inválida", ip_spec="999.999.999.999")
    """

    default_code = ErrorCode.INVALID_IP_SPEC

    def __init__(self, message: str, ip_spec: str):
        super().__init__(
            message=message,
            field="ip_address",
            value=ip_spec,
            expected="Formato: '192.168.1.1', '192.168.1.0/24', '192.168.1.1-10'"
        )


class URLValidationError(ValidationError):
    """
    Excepción lanzada cuando la URL proporcionada es inválida.

    Se usa para validar la URL proporcionada para un escaneo Nikto.
    Debe ser una URL válida con protocolo http o https.

    Atributos:
        default_code: Código de error (INVALID_URL).

    Args:
        message: Descripción del error de validación.
        url: URL proporcionada por el usuario.

    Ejemplo:
        >>> raise URLValidationError(message="URL inválida", url="ftp://invalid")
    """

    default_code = ErrorCode.INVALID_URL

    def __init__(self, message: str, url: str):
        super().__init__(
            message=message,
            field="url",
            value=url,
            expected="URL válida: http://example.com o https://example.com"
        )


class PDFGenerationError(ReportError):
    """
    Excepción lanzada cuando ocurre un error al generar un PDF.

    Se usa específicamente para errores en la generación de documentos
    PDF de reportes de escaneos. Tiene severidad HIGH ya que indica
    un problema significativo en el flujo de generación de informes.

    Atributos:
        default_code: Código de error (REPORT_GENERATION_ERROR).
        default_severity: HIGH.

    Args:
        message: Descripción del error de generación del PDF.
        scan_id: ID opcional del escaneo asociado (puede ser None).

    Ejemplo:
        >>> raise PDFGenerationError(message="Memoria insuficiente", scan_id=42)
    """

    default_code = ErrorCode.REPORT_GENERATION_ERROR
    default_severity = ErrorSeverity.HIGH

    def __init__(self, message: str, scan_id: int | None = None):
        details = {"scan_id": scan_id} if scan_id else {}
        super().__init__(
            message=f"Error generando PDF: {message}",
            details=details,
            user_message="Error al generar el informe PDF."
        )
