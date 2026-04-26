from ._base import SecOpsException, ErrorCode, ErrorSeverity


class AuthenticationError(SecOpsException):
    default_code = ErrorCode.AUTHENTICATION_ERROR
    default_status_code = 401
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, message: str = "Error de autenticación", **kwargs):
        if "user_message" not in kwargs:
            kwargs["user_message"] = "No se pudo verificar su identidad."
        super().__init__(message=message, **kwargs)


class AuthorizationError(SecOpsException):
    default_code = ErrorCode.AUTHORIZATION_ERROR
    default_status_code = 403
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, message: str = "Error de autorización", **kwargs):
        if "user_message" not in kwargs:
            kwargs["user_message"] = "No tiene permisos para realizar esta acción."
        super().__init__(message=message, **kwargs)


class InvalidCredentialsError(AuthenticationError):
    default_code = ErrorCode.INVALID_CREDENTIALS

    def __init__(self):
        super().__init__(
            message="Credenciales inválidas",
            user_message="Usuario o contraseña incorrectos."
        )


class UserNotFoundError(AuthenticationError):
    default_code = ErrorCode.USER_NOT_FOUND

    def __init__(self, user_id: int):
        super().__init__(
            message=f"Usuario '{user_id}' no encontrado",
            details={"id_usuario": user_id},
            user_message="Usuario no encontrado."
        )


class UserBindingError(AuthenticationError):
    default_code = ErrorCode.UNBINDABLE_USER

    def __init__(self, username: str):
        super().__init__(
            message=f"No se pudo vincular el usuario '{username}' con una persona existente",
            details={"username": username},
            user_message=f"Error al crear el usuario debido a datos incompletos"
        )


class DuplicatedUserCredentials(AuthenticationError):
    default_code = ErrorCode.DUPLICATED_CREDENTIALS

    def __init__(self, credentials: str):
        super().__init__(
            message=f"Se ha detectado una credencial duplicada para un usuario",
            user_message=f"Se ha detectedo duplicidad de datos para el siguiente valor: {credentials}"
        )


class ExistingUserError(AuthenticationError):
    default_code = ErrorCode.USER_ALREADY_EXISTS

    def __init__(self, username: str, email: str):
        super().__init__(
            message="Se ha intentado crear un usuario con un email o nombre de usuario existentes",
            details={"username": username, "email": email},
            user_message=f"""Ya existe un usuario con los siguientes parámetros: {f"email: {email}" if email is not None else "" } {"|" if username is not None and email is not None else ""} {f"username: {username}" if username is not None else "" }"""
        )