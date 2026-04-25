from typing import Any, Optional

from ._base import SecOpsException, ErrorCode, ErrorSeverity


class ValidationError(SecOpsException):
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
        details = {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)
        if expected:
            details["expected"] = expected

        if "details" in kwargs:
            details.update(kwargs.pop("details"))

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
    default_code = ErrorCode.INVALID_PORT_SPEC

    def __init__(self, message: str, port_spec: str):
        super().__init__(
            message=message,
            field="ports",
            value=port_spec,
            expected="Formato: '80', '80,443', '1-1000', '80,443-8080'"
        )


class IPValidationError(ValidationError):
    default_code = ErrorCode.INVALID_IP_SPEC

    def __init__(self, message: str, ip_spec: str):
        super().__init__(
            message=message,
            field="ip_address",
            value=ip_spec,
            expected="Formato: '192.168.1.1', '192.168.1.0/24', '192.168.1.1-10'"
        )


class URLValidationError(ValidationError):
    default_code = ErrorCode.INVALID_URL

    def __init__(self, message: str, url: str):
        super().__init__(
            message=message,
            field="url",
            value=url,
            expected="URL válida: http://example.com o https://example.com"
        )


class MissingParameterError(ValidationError):
    default_code = ErrorCode.MISSING_PARAMETER

    def __init__(self, parameter: str):
        super().__init__(
            message=f"Parámetro requerido '{parameter}' no proporcionado",
            field=parameter,
            user_message=f"El parámetro '{parameter}' es obligatorio."
        )