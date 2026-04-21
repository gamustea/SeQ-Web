from .base import SecOpsException, ErrorCode, ErrorSeverity


class ParsingError(SecOpsException):
    default_code = ErrorCode.PARSING_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.MEDIUM


class XMLParsingError(ParsingError):
    default_code = ErrorCode.XML_PARSING_ERROR

    def __init__(self, file_path: str, reason: str):
        super().__init__(
            message=f"Error parseando XML '{file_path}': {reason}",
            details={"file_path": file_path, "reason": reason},
            user_message="Error procesando resultados del escaneo."
        )


class JSONParsingError(ParsingError):
    default_code = ErrorCode.JSON_PARSING_ERROR

    def __init__(self, data: str, reason: str):
        super().__init__(
            message=f"Error parseando JSON: {reason}",
            details={"data": data[:100], "reason": reason},
            user_message="Error procesando datos JSON."
        )