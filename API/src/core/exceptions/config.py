from .base import SecOpsException, ErrorCode, ErrorSeverity


class ConfigurationError(SecOpsException):
    default_code = ErrorCode.CONFIGURATION_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.CRITICAL


class MissingConfigError(ConfigurationError):
    default_code = ErrorCode.MISSING_CONFIG

    def __init__(self, config_key: str):
        super().__init__(
            message=f"Configuración requerida '{config_key}' no encontrada",
            details={"config_key": config_key},
            user_message="Error de configuración del servidor."
        )