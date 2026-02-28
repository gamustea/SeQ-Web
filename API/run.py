"""
API REST para SecOps - Sistema de escaneo de seguridad
Versión 3.1 - Normalizada con mejores prácticas REST
"""


import os
import base64
import time
from functools import wraps
from typing import Optional, Tuple
from flask import send_file, request, jsonify, Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import BadRequest
from src.logic.managers import NmapScanManager, NiktoScanManager, UserManager, OpenVASScanManager
from src.logic.documents import PDFCreator, NmapPrintingStrategy, NiktoPrintingStrategy, OpenVASPrintingStrategy
from src.misc.logging import SecOpsLogger
from src.misc.validation import PortValidator, IPValidator
from src.core.model import Scan, User
from src.core.exceptions import (
    AuthenticationError,
    InvalidCredentialsError,
    ValidationError,
    MissingParameterError,
    EntityNotFoundError,
    ScanNotFoundError,
    ScanExecutionError,
    ReportGenerationError,
    create_error_response,
    ExceptionHandler,
    ExistingUserError,
    UserNotFoundError,
    UserBindingError,
    DatabaseError
)
from src.logic.managers import OAuthTokenManager, ACCESS_TOKEN_EXPIRE_MINUTES

# ============================================================================
# INICIALIZACIÓN DE LA APLICACIÓN
# ============================================================================
app = Flask(__name__)
CORS(app)
logger_instance = SecOpsLogger(name="APIMain")
logger = logger_instance.get_logger()

USER_MANAGER = UserManager()
OAUTH_MANAGER = OAuthTokenManager()

# Rate limiting para prevenir ataques de fuerza bruta
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# ============================================================================
# UTILIDADES DE AUTENTICACIÓN Y USUARIO
# ============================================================================
def get_current_user_id() -> int:
    return request.current_user_id  # type: ignore

def get_current_username() -> str:
    return request.current_username  # type: ignore

def get_user_managers(user_id: int) -> Tuple[NmapScanManager, NiktoScanManager, OpenVASScanManager]:
    """
    Crea managers de escaneo para un usuario específico.

    Args:
        user_id: ID del usuario del ORM para el cual crear los managers

    Returns:
        Tupla (NmapScanManager, NiktoScanManager, OpenVASScanManager) configurados para el usuario
    """
    user = USER_MANAGER.get_user_by_id(user_id)
    nmap_manager = NmapScanManager(user)
    nikto_manager = NiktoScanManager(user)
    openvas_manager = OpenVASScanManager(user)
    USER_MANAGER.close_session()
    return nmap_manager, nikto_manager, openvas_manager

# ============================================================================
# DECORADORES DE AUTENTICACIÓN
# ============================================================================
def require_oauth_token(f):
    """
    Decorador que verifica el access token OAuth 2.0.
    Requiere header: Authorization: Bearer <token>
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                logger.warning("Intento de acceso sin header Authorization")
                return jsonify({
                    "error": "unauthorized",
                    "error_description": "Missing Authorization header"
                }), 401

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                logger.warning("Formato de Authorization header inválido")
                return jsonify({
                    "error": "unauthorized",
                    "error_description": "Invalid Authorization header format. Use: Bearer <token>"
                }), 401

            token = parts[1]
            payload = OAUTH_MANAGER.verify_access_token(token)

            if not payload:
                logger.warning("Token inválido o expirado")
                return jsonify({
                    "error": "invalid_token",
                    "error_description": "The access token is invalid or expired"
                }), 401

            request.current_user_id = int(payload["sub"])  # type: ignore
            request.current_username = payload["username"]  # type: ignore

            logger.info(f"Usuario autenticado vía OAuth: {payload['username']} (ID: {payload['sub']})")
            return f(*args, **kwargs)

        except Exception as e:
            logger.error(f"Error en autenticación OAuth: {str(e)}", exc_info=True)
            return jsonify({
                "error": "server_error",
                "error_description": "Authentication error"
            }), 500

    return decorated_function

# ============================================================================
# FUNCIONES AUXILIARES
# ============================================================================
def build_pdf_creator(scan: Scan) -> PDFCreator:
    """
    Construye el creador de PDF apropiado según el tipo de escaneo.

    Args:
        scan: Objeto Scan (Nmap, Nikto u OpenVAS)

    Returns:
        PDFCreator configurado con la estrategia correcta

    Raises:
        ValidationError: Si el tipo de escaneo no es soportado
    """
    scan_type = scan.scan_type.lower() if hasattr(scan, "scan_type") else "unknown"

    if scan_type == "nmap":
        strategy = NmapPrintingStrategy(scan=scan)
    elif scan_type == "nikto":
        strategy = NiktoPrintingStrategy(scan=scan)
    elif scan_type == "openvas":
        strategy = OpenVASPrintingStrategy(scan=scan)
    else:
        logger.error(f"Tipo de escaneo no soportado: {scan_type}")
        raise ValidationError(
            field="scan_type",
            message=f"Tipo de escaneo '{scan_type}' no soportado",
            expected="'nmap', 'nikto' u 'openvas'"
        )

    return PDFCreator(strategy)

def get_scan_by_id_for_user(
    scan_id: int,
    nmap_manager: NmapScanManager,
    nikto_manager: NiktoScanManager,
    openvas_manager: OpenVASScanManager
) -> Tuple[Optional[Scan], str]:
    """
    Busca un escaneo por ID usando los managers del usuario.

    Args:
        scan_id: ID del escaneo a buscar
        nmap_manager: Manager de Nmap del usuario
        nikto_manager: Manager de Nikto del usuario
        openvas_manager: Manager de OpenVAS del usuario

    Returns:
        Tupla (Scan, tipo) donde tipo es 'nmap', 'nikto' u 'openvas'.
        Retorna (None, '') si no se encuentra
    """
    scan = nmap_manager.get_scan_by_id(scan_id)
    if scan:
        return scan, "nmap"

    scan = nikto_manager.get_scan_by_id(scan_id)
    if scan:
        return scan, "nikto"

    scan = openvas_manager.get_scan_by_id(scan_id)
    if scan:
        return scan, "openvas"

    return None, ""

# ============================================================================
# ENDPOINTS OAUTH 2.0
# ============================================================================
@app.route("/oauth/token", methods=["POST"])
@limiter.limit("10 per minute")
def oauth_token():
    """
    Endpoint para obtener tokens OAuth 2.0.

    Soporta dos grant_types:
    1. password: Obtener tokens con username/password
    2. refresh_token: Renovar access token con refresh token

    Body (JSON) para password grant:
    {
        "grantType": "password",
        "username": "usuario",
        "password": "contraseña"
    }

    Body (JSON) para refresh_token grant:
    {
        "grant_type": "refresh_token",
        "refresh_token": "token_de_refresco"
    }
    """
    try:
        if not request.is_json:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Content-Type must be application/json"
            }), 400

        data = request.get_json()
        if not data:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Request body must be JSON"
            }), 400

        grant_type = data.get("grantType")

        if grant_type == "password":
            username = data.get("username")
            password = data.get("password")

            if not username or not password:
                return jsonify({
                    "error": "invalid_request",
                    "error_description": "username and password are required"
                }), 400

            is_valid, user_id = USER_MANAGER.verify_credentials(username, password)
            if not is_valid:
                logger.warning(f"Intento de login fallido para: {username}")
                return jsonify({
                    "error": "invalid_grant",
                    "error_description": "Invalid username or password"
                }), 401

            access_token = OAUTH_MANAGER.create_access_token(user_id, username)  # type: ignore
            refresh_token = OAUTH_MANAGER.create_refresh_token(user_id)  # type: ignore

            logger.info(f"Tokens OAuth generados para usuario: {username}")
            return jsonify({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "refresh_token": refresh_token
            }), 200

        elif grant_type == "refresh_token":
            refresh_token = data.get("refresh_token")

            if not refresh_token:
                return jsonify({
                    "error": "invalid_request",
                    "error_description": "refresh_token is required"
                }), 400

            user_id = OAUTH_MANAGER.verify_refresh_token(refresh_token)
            if not user_id:
                return jsonify({
                    "error": "invalid_grant",
                    "error_description": "Invalid or expired refresh token"
                }), 401

            user = USER_MANAGER.get_user_by_id(user_id)
            USER_MANAGER.close_session()

            if not user:
                return jsonify({
                    "error": "invalid_grant",
                    "error_description": "User not found"
                }), 401

            access_token = OAUTH_MANAGER.create_access_token(user_id, user.username)  # type: ignore

            logger.info(f"Access token renovado para usuario ID: {user_id}")
            return jsonify({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }), 200

        else:
            return jsonify({
                "error": "unsupported_grant_type",
                "error_description": "Supported grant types: password, refresh_token"
            }), 400

    except BadRequest:
        return jsonify({
            "error": "invalid_request",
            "error_description": "Malformed JSON in request body"
        }), 400
    except Exception as e:
        logger.error(f"Error en /oauth/token: {str(e)}", exc_info=True)
        return jsonify({
            "error": "server_error",
            "error_description": "Internal server error"
        }), 500

@app.route("/oauth/revoke", methods=["POST"])
@require_oauth_token
def oauth_revoke():
    """
    Revoca el token actual del usuario.
    Requiere autenticación OAuth.
    """
    try:
        auth_header = request.headers.get("Authorization")
        token = auth_header.split()[1]  # type: ignore

        OAUTH_MANAGER.revoke_access_token(token)
        logger.info(f"Token revocado para usuario: {get_current_username()}")

        return jsonify({
            "message": "Token revoked successfully"
        }), 200

    except Exception as e:
        logger.error(f"Error en /oauth/revoke: {str(e)}", exc_info=True)
        return jsonify({
            "error": "server_error",
            "error_description": "Failed to revoke token"
        }), 500

@app.route("/oauth/revoke-all", methods=["POST"])
@require_oauth_token
def oauth_revoke_all():
    """
    Revoca TODOS los tokens del usuario actual.
    Útil para "cerrar sesión en todos los dispositivos".
    """
    try:
        user_id = get_current_user_id()
        OAUTH_MANAGER.revoke_all_user_tokens(user_id)

        logger.info(f"Todos los tokens revocados para usuario ID: {user_id}")
        return jsonify({
            "message": "All tokens revoked successfully"
        }), 200

    except Exception as e:
        logger.error(f"Error en /oauth/revoke-all: {str(e)}", exc_info=True)
        return jsonify({
            "error": "server_error"
        }), 500

# ============================================================================
# ENDPOINTS GENERALES
# ============================================================================
@app.route("/say-hello", methods=["GET"])
def hello():
    """
    Endpoint de prueba para verificar que la API está funcionando.
    No requiere autenticación.
    """
    logger.info("Endpoint /say-hello invocado")
    return jsonify({
        "message": "You did it! You reached an endpoint!",
        "status": "ok",
        "version": "3.1-normalized"
    }), 200

@app.route("/sentinel/is-finished", methods=["GET"])
@require_oauth_token
def is_scan_finished():
    """
    Verifica si un escaneo ha finalizado.

    Query Parameters:
        id: ID del escaneo a verificar

    Headers requeridos:
        Authorization: Bearer <token>

    Returns:
        JSON indicando si el escaneo existe y si está finalizado
    """
    try:
        user_id = get_current_user_id()
        nmap_manager, nikto_manager, openvas_manager = get_user_managers(user_id)

        scan_id_str = request.args.get("id")
        if not scan_id_str:
            raise MissingParameterError("id")

        try:
            scan_id = int(scan_id_str)
        except ValueError:
            raise ValidationError(
                field="id",
                message="El ID debe ser un número entero",
                value=scan_id_str
            )

        scan, scan_type = get_scan_by_id_for_user(
            scan_id, nmap_manager, nikto_manager, openvas_manager
        )

        if not scan or scan.user_id != user_id:
            raise ScanNotFoundError(scan_id)

        if scan_type == "nmap":
            manager = nmap_manager
        elif scan_type == "nikto":
            manager = nikto_manager
        else:
            manager = openvas_manager

        scan_finished = manager.is_scan_finished(scan.id)
        message = (
            f"El escaneo con id {scan_id} está terminado"
            if scan_finished
            else f"El escaneo con id {scan_id} no está terminado"
        )

        logger.info(
            f"Usuario {get_current_username()}: escaneo {scan_id} ({scan_type}) - "
            f"{'finalizado' if scan_finished else 'en progreso'}"
        )

        return jsonify({
            "message": message,
            "scanId": scan_id,
            "isFinished": scan_finished,
            "scanType": scan_type
        }), 200

    except (MissingParameterError, ValidationError, ScanNotFoundError) as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error en is-finished: {e}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

@app.route("/sentinel/scan-status", methods=["GET"])
@require_oauth_token
def get_scan_status():
    """
    Obtiene el estado actual de un escaneo.

    Query Parameters:
        id: ID del escaneo a consultar

    Headers requeridos:
        Authorization: Bearer <token>
    """
    try:
        user_id = get_current_user_id()
        nmap_manager, nikto_manager, openvas_manager = get_user_managers(user_id)

        scan_id_str = request.args.get("id")
        if not scan_id_str:
            raise MissingParameterError("id")

        try:
            scan_id = int(scan_id_str)
        except ValueError:
            raise ValidationError(
                field="id",
                message="El ID debe ser un número entero",
                value=scan_id_str
            )

        scan, scan_type = get_scan_by_id_for_user(
            scan_id, nmap_manager, nikto_manager, openvas_manager
        )

        if not scan or scan.user_id != user_id:
            raise ScanNotFoundError(scan_id)

        if scan_type == "nmap":
            manager = nmap_manager
        elif scan_type == "nikto":
            manager = nikto_manager
        else:
            manager = openvas_manager

        status = manager.get_scan_status(scan.id)
        progress = manager.get_scan_progress(scan.id)

        logger.info(
            f"Usuario {get_current_username()}: estado del escaneo {scan_id} ({scan_type}) - {status}"
        )

        response = {
            "message": f"Estado del escaneo con id {scan_id}: {status}",
            "scanId": scan_id,
            "status": status,
            "scanType": scan_type
        }

        if progress is not None:
            response["progress"] = progress

        return jsonify(response), 200

    except (MissingParameterError, ValidationError, ScanNotFoundError) as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error en scan-status: {e}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

@app.route("/sentinel/scans/<int:scan_id>/cancel", methods=["POST"])
@require_oauth_token
def cancel_scan(scan_id: int):
    """
    Cancela un escaneo en ejecución.
    
    Path Parameters:
        scan_id: ID del escaneo a cancelar
    
    Headers requeridos:
        Authorization: Bearer <token>
    
    Returns:
        JSON con el resultado de la cancelación
        
    Response codes:
        200: Escaneo cancelado exitosamente
        400: El escaneo no se puede cancelar (ya finalizó o estado inválido)
        401: No autorizado
        403: El escaneo no pertenece al usuario
        404: Escaneo no encontrado
        500: Error interno
    """
    try:
        user_id = get_current_user_id()
        nmap_manager, nikto_manager, openvas_manager = get_user_managers(user_id)
        
        logger.info(f"Usuario {get_current_username()} intentando cancelar escaneo ID: {scan_id}")
        
        # Buscar el escaneo en los diferentes managers
        scan = None
        manager = None
        scan_type = None
        
        # Intentar con Nmap
        scan = nmap_manager.get_scan_by_id(scan_id)
        if scan:
            manager = nmap_manager
            scan_type = "nmap"
        
        # Intentar con Nikto
        if not scan:
            scan = nikto_manager.get_scan_by_id(scan_id)
            if scan:
                manager = nikto_manager
                scan_type = "nikto"
        
        # Intentar con OpenVAS
        if not scan:
            scan = openvas_manager.get_scan_by_id(scan_id)
            if scan:
                manager = openvas_manager
                scan_type = "openvas"
        
        # Verificar que se encontró el escaneo
        if not scan or not manager:
            logger.warning(f"Escaneo {scan_id} no encontrado")
            raise ScanNotFoundError(scan_id)
        
        # Verificar que pertenece al usuario
        if scan.user_id != user_id:
            logger.warning(
                f"Usuario {get_current_username()} no autorizado para cancelar escaneo {scan_id}"
            )
            return jsonify({
                "error": "forbidden",
                "message": "No tienes permiso para cancelar este escaneo",
                "scanId": scan_id
            }), 403
        
        # Verificar que el escaneo está en un estado cancelable
        if scan.status not in ['pending', 'running']:
            logger.warning(
                f"Escaneo {scan_id} no se puede cancelar (estado: {scan.status})"
            )
            return jsonify({
                "error": "invalid_state",
                "message": f"El escaneo no se puede cancelar en su estado actual: {scan.status}",
                "scanId": scan_id,
                "currentStatus": scan.status,
                "cancellableStates": ["pending", "running"]
            }), 400
        
        # Intentar cancelar
        success = manager.cancel_scan(scan_id)
        
        if success:
            logger.info(
                f"Usuario {get_current_username()}: Escaneo {scan_type} ID {scan_id} cancelado"
            )
            
            # Obtener estado actualizado
            scan = manager.get_scan_by_id(scan_id)
            
            return jsonify({
                "message": "Escaneo cancelado exitosamente",
                "scanId": scan_id,
                "scanType": scan_type,
                "status": scan.status,
                "user": get_current_username()
            }), 200
        else:
            logger.error(f"No se pudo cancelar el escaneo {scan_id}")
            return jsonify({
                "error": "cancellation_failed",
                "message": "No se pudo cancelar el escaneo",
                "scanId": scan_id
            }), 500
    
    except ScanNotFoundError as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    
    except Exception as e:
        logger.error(f"Error cancelando escaneo {scan_id}: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

# ============================================================================
# ENDPOINTS DE USUARIOS
# ============================================================================
@app.route("/users/sign-up", methods=["POST"])
def sign_up_user():
    """
    Registra un nuevo usuario en el sistema.

    Body (JSON):
    {
        "username": "nombre_usuario",
        "password": "contraseña_segura",
        "email": "usuario@ejemplo.com",
        "alias": "alias_usuario"
    }

    Returns:
        JSON con los datos del usuario creado
    """
    try:
        if not request.is_json:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Content-Type must be application/json"
            }), 400

        data = request.get_json()
        if not data:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Request body must be JSON"
            }), 400

        username = data.get("username")
        password = data.get("password")
        email = data.get("email")
        alias = data.get("alias")

        if not username:
            raise MissingParameterError("username")
        if not password:
            raise MissingParameterError("password")
        if not email:
            raise MissingParameterError("email")
        if not alias:
            raise MissingParameterError("alias")

        new_user = USER_MANAGER.sign_in_user(username, password, email, alias)
        logger.info(f"Nuevo usuario registrado: {username} (ID: {new_user.id})")

        return jsonify({
            "message": "Usuario registrado exitosamente",
            "userId": new_user.id,
            "username": new_user.username,
            "email": email
        }), 201

    except DatabaseError as e:
        return jsonify({
            "code": e.status_code,
            "message": "Revisa tus credenciales e inténtalo de nuevo."
        }), e.status_code
    except (MissingParameterError, ExistingUserError, UserBindingError) as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error en sign-up: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

@app.route("/users/sign-up-person", methods=["POST"])
def sign_up_person():
    """
    Registra una nueva persona en el sistema.

    Body (JSON):
    {
        "firstName": "Nombre",
        "lastName": "Apellido",
        "alias": "alias_persona"
    }

    Returns:
        JSON con los datos de la persona creada
    """
    try:
        if not request.is_json:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Content-Type must be application/json"
            }), 400

        data = request.get_json()
        if not data:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Request body must be JSON"
            }), 400

        first_name = data.get("firstName")
        last_name = data.get("lastName")
        alias = data.get("alias")

        if not first_name:
            raise MissingParameterError("firstName")
        if not last_name:
            raise MissingParameterError("lastName")
        if not alias:
            raise MissingParameterError("alias")

        new_person = USER_MANAGER.sign_in_person(first_name, last_name, alias)
        logger.info(f"Nueva persona registrada: {first_name} {last_name} (ID: {new_person.id})")

        return jsonify({
            "message": "Persona registrada exitosamente",
            "personId": new_person.id,
            "firstName": new_person.first_name,
            "lastName": new_person.last_name
        }), 201

    except (MissingParameterError, ExistingUserError) as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error en sign-up-person: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

@app.route("/users/check-credentials", methods=["POST"])
def check_credentials():
    """
    Verifica si las credenciales son válidas.
    LEGACY: Usar /oauth/token en su lugar para producción.

    Body (JSON):
    {
        "username": "nombre_usuario",
        "password": "contraseña"
    }

    Returns:
        JSON indicando si las credenciales son válidas
    """
    try:
        if not request.is_json:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Content-Type must be application/json"
            }), 400

        data = request.get_json()
        if not data:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Request body must be JSON"
            }), 400

        username = data.get("username")
        password = data.get("password")

        if not username:
            raise MissingParameterError("username")
        if not password:
            raise MissingParameterError("password")

        logger.debug(f"Verificando credenciales para usuario: {username}")
        is_valid, user_id = USER_MANAGER.verify_credentials(username, password)

        if not is_valid:
            raise InvalidCredentialsError()

        logger.info(f"Credenciales válidas para usuario: {username} (ID: {user_id})")
        return jsonify({
            "message": "Credenciales válidas",
            "isValid": True,
            "userId": user_id,
            "username": username
        }), 200

    except (MissingParameterError, InvalidCredentialsError) as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error en check-credentials: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

@app.route("/users/change-password", methods=["PUT"])
@require_oauth_token
def change_password():
    """
    Cambia la contraseña del usuario autenticado.

    Headers requeridos:
        Authorization: Bearer <token>

    Body (JSON):
    {
        "newPassword": "nueva_contraseña_segura"
    }

    Returns:
        JSON confirmando el cambio de contraseña
    """
    try:
        if not request.is_json:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Content-Type must be application/json"
            }), 400

        data = request.get_json()
        if not data:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Request body must be JSON"
            }), 400

        user_id = get_current_user_id()
        username = get_current_username()
        new_password = data.get("newPassword")

        if not new_password:
            raise MissingParameterError("newPassword")

        USER_MANAGER.update_user_password(user_id, new_password)  # type: ignore
        OAUTH_MANAGER.revoke_all_user_tokens(user_id)

        logger.info(f"Usuario {username} (ID: {user_id}) cambió su contraseña")
        return jsonify({
            "message": "Contraseña cambiada exitosamente. Por favor, inicia sesión de nuevo.",
            "userId": user_id,
            "username": username
        }), 200

    except (MissingParameterError, InvalidCredentialsError) as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error en change-password: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

# ============================================================================
# ENDPOINTS DE ESCANEO NMAP
# ============================================================================
@app.route("/sentinel/nmap/start", methods=["POST"])
@require_oauth_token
def start_nmap_scan():
    """
    Inicia un escaneo Nmap para el usuario autenticado.

    Headers requeridos:
        Authorization: Bearer <token>

    Body (JSON):
    {
        "target": "192.168.1.1 o 192.168.1.0/24",
        "ports": "80,443 o 1-1000"
    }

    Returns:
        JSON con el ID(s) del escaneo iniciado
    """
    try:
        if not request.is_json:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Content-Type must be application/json"
            }), 400

        data = request.get_json()
        if not data:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Request body must be JSON"
            }), 400

        user_id = get_current_user_id()
        nmap_manager, _, _ = get_user_managers(user_id)

        host = data.get("target")
        ports = data.get("ports")

        if not host:
            raise MissingParameterError("target")
        if not ports:
            raise MissingParameterError("ports")

        if not host.strip():
            raise ValidationError(
                field="target",
                message="El host no puede estar vacío"
            )

        if not ports.strip():
            raise ValidationError(
                field="ports",
                message="Los puertos no pueden estar vacíos"
            )

        valido, hosts, mensaje = IPValidator.validate(host)
        if not valido:
            raise ValidationError(
                field="target",
                message=mensaje,
                value=host
            )

        valido, puertos, mensaje = PortValidator.validate(ports)
        if not valido:
            raise ValidationError(
                field="ports",
                message=mensaje,
                value=ports
            )

        scan_ids = []
        for target_host in hosts:
            try:
                scan_id = nmap_manager.run_scan(target_host, ports)
                scan_ids.append(scan_id)
                logger.info(
                    f"Usuario {get_current_username()}: Escaneo Nmap ID={scan_id}, "
                    f"host={target_host}, ports={ports}"
                )
                time.sleep(0.10)
            except Exception as e:
                logger.error(f"Error iniciando escaneo para {target_host}: {e}")
                raise ScanExecutionError(
                    scan_type="Nmap",
                    target=target_host,
                    reason=str(e)
                )

        return jsonify({
            "message": "Escaneo(s) Nmap iniciado(s) correctamente",
            "scanIds": scan_ids,
            "target": {
                "hosts": hosts,
                "ports": ports
            },
            "totalScans": len(scan_ids),
            "user": get_current_username()
        }), 201

    except (MissingParameterError, ValidationError, ScanExecutionError) as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error al iniciar escaneo Nmap: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

# ============================================================================
# ENDPOINTS DE ESCANEO NIKTO
# ============================================================================
@app.route("/sentinel/nikto/start", methods=["POST"])
@require_oauth_token
def start_nikto_scan():
    """
    Inicia un escaneo Nikto para el usuario autenticado.

    Headers requeridos:
        Authorization: Bearer <token>

    Body (JSON):
    {
        "target": "http://example.com",
        "timeout": 180  // Opcional, por defecto 180 segundos
    }

    Returns:
        JSON con el ID del escaneo iniciado
    """
    try:
        if not request.is_json:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Content-Type must be application/json"
            }), 400

        data = request.get_json()
        if not data:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Request body must be JSON"
            }), 400

        user_id = get_current_user_id()
        _, nikto_manager, _ = get_user_managers(user_id)

        target = data.get("target")
        timeout = data.get("timeout", 180)

        if not target:
            raise MissingParameterError("target")

        if not target.strip():
            raise ValidationError(
                field="target",
                message="El target no puede estar vacío"
            )

        try:
            timeout = int(timeout)
            if timeout <= 0:
                raise ValidationError(
                    field="timeout",
                    message="El timeout debe ser un número positivo",
                    value=timeout
                )
        except ValueError:
            raise ValidationError(
                field="timeout",
                message="El timeout debe ser un número entero válido",
                value=timeout
            )

        try:
            scan_id = nikto_manager.run_scan(target, timeout=timeout)
            logger.info(
                f"Usuario {get_current_username()}: Escaneo Nikto ID={scan_id}, "
                f"target={target}, timeout={timeout}"
            )
        except Exception as e:
            logger.error(f"Error ejecutando escaneo Nikto: {e}")
            raise ScanExecutionError(
                scan_type="Nikto",
                target=target,
                reason=str(e)
            )

        return jsonify({
            "message": "Escaneo Nikto iniciado correctamente",
            "scanId": scan_id,
            "target": target,
            "timeout": timeout,
            "user": get_current_username()
        }), 201

    except (MissingParameterError, ValidationError, ScanExecutionError) as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error al iniciar escaneo Nikto: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

# ============================================================================
# ENDPOINTS DE ESCANEO OPENVAS
# ============================================================================
@app.route("/sentinel/openvas/start", methods=["POST"])
@require_oauth_token
def start_openvas_scan():
    """
    Inicia un escaneo OpenVAS para el usuario autenticado.

    Headers requeridos:
        Authorization: Bearer <token>

    Body (JSON):
    {
        "target": "192.168.1.1",
        "scanConfig": "full_fast"  // Opcional: full_fast, full_deep, full_ultimate
    }

    Returns:
        JSON con el ID del escaneo iniciado
    """
    try:
        if not request.is_json:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Content-Type must be application/json"
            }), 400

        data = request.get_json()
        if not data:
            return jsonify({
                "error": "invalid_request",
                "error_description": "Request body must be JSON"
            }), 400

        user_id = get_current_user_id()
        _, _, openvas_manager = get_user_managers(user_id)

        target = data.get("target")
        scan_config = data.get("scanConfig", "full_fast")

        if not target:
            raise MissingParameterError("target")

        if not target.strip():
            raise ValidationError(
                field="target",
                message="El target no puede estar vacío"
            )

        valid_configs = ["full_fast", "full_deep", "full_ultimate"]
        if scan_config not in valid_configs:
            raise ValidationError(
                field="scanConfig",
                message="Configuración de escaneo inválida",
                value=scan_config,
                expected=f"Una de: {', '.join(valid_configs)}"
            )

        valido, hosts, mensaje = IPValidator.validate(target)
        if not valido:
            raise ValidationError(
                field="target",
                message=mensaje,
                value=target
            )

        if len(hosts) > 1:
            raise ValidationError(
                field="target",
                message="OpenVAS solo puede escanear un host a la vez",
                value=target,
                expected="Una sola IP o hostname"
            )

        target_host = hosts[0]

        try:
            scan_id = openvas_manager.run_scan(target_host, scan_config=scan_config)
            logger.info(
                f"Usuario {get_current_username()}: Escaneo OpenVAS ID={scan_id}, "
                f"target={target_host}, config={scan_config}"
            )
        except Exception as e:
            logger.error(f"Error ejecutando escaneo OpenVAS: {e}", exc_info=True)
            raise ScanExecutionError(
                scan_type="OpenVAS",
                target=target_host,
                reason=str(e)
            )

        return jsonify({
            "message": "Escaneo OpenVAS iniciado correctamente",
            "scanId": scan_id,
            "target": target_host,
            "scanConfig": scan_config,
            "user": get_current_username(),
            "note": "Los escaneos OpenVAS pueden tardar varios minutos. Use /sentinel/scan-status para verificar el progreso."
        }), 201

    except (MissingParameterError, ValidationError, ScanExecutionError) as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error al iniciar escaneo OpenVAS: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

# ============================================================================
# ENDPOINTS DE GENERACIÓN DE PDFs
# ============================================================================
@app.route("/sentinel/generate-pdf", methods=["GET"])
@require_oauth_token
def generate_pdf():
    """
    Genera y descarga un PDF de un escaneo del usuario autenticado.

    Query Parameters:
        id: ID del escaneo

    Headers requeridos:
        Authorization: Bearer <token>

    Returns:
        Archivo PDF para descarga directa
    """
    try:
        user_id = get_current_user_id()
        nmap_manager, nikto_manager, openvas_manager = get_user_managers(user_id)

        scan_id_str = request.args.get("id")
        if not scan_id_str:
            raise MissingParameterError("id")

        try:
            scan_id = int(scan_id_str)
        except ValueError:
            raise ValidationError(
                field="id",
                message="El ID debe ser un número entero válido",
                value=scan_id_str
            )

        logger.info(f"Usuario {get_current_username()} generando PDF para escaneo ID: {scan_id}")

        scan, scan_type = get_scan_by_id_for_user(scan_id, nmap_manager, nikto_manager, openvas_manager)

        if not scan or scan.user_id != user_id:  # type: ignore
            raise ScanNotFoundError(scan_id)

        manager = nmap_manager if scan_type == "nmap" else (nikto_manager if scan_type == "nikto" else openvas_manager)

        if not manager.is_scan_finished(scan.id):  # type: ignore
            raise ValidationError(
                field="scan_id",
                message=f"El escaneo con ID {scan_id} no está finalizado aún",
                value=scan_id
            )

        try:
            pdf_creator = build_pdf_creator(scan)
            pdf_path = pdf_creator.print_pdf()
        except Exception as e:
            logger.error(f"Error generando PDF: {e}")
            raise ReportGenerationError(scan_id, str(e))

        if not pdf_path or not os.path.exists(pdf_path):
            raise ReportGenerationError(
                scan_id,
                "El archivo PDF no se generó correctamente"
            )

        logger.info(f"Usuario {get_current_username()}: PDF generado - {pdf_path}")

        return send_file(
            pdf_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"{scan_type}_scan_{scan_id}.pdf"
        )

    except (MissingParameterError, ValidationError, ScanNotFoundError, ReportGenerationError) as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error interno al generar PDF: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

@app.route("/sentinel/generate-pdf-base64", methods=["GET"])
@require_oauth_token
def generate_pdf_base64():
    """
    Genera un PDF de un escaneo y lo devuelve en formato base64.

    Query Parameters:
        id: ID del escaneo

    Headers requeridos:
        Authorization: Bearer <token>

    Returns:
        JSON con el PDF en base64 y metadata
    """
    try:
        user_id = get_current_user_id()
        nmap_manager, nikto_manager, openvas_manager = get_user_managers(user_id)

        scan_id_str = request.args.get("id")
        if not scan_id_str:
            raise MissingParameterError("id")

        try:
            scan_id = int(scan_id_str)
        except ValueError:
            raise ValidationError(
                field="id",
                message="El ID debe ser un número entero válido",
                value=scan_id_str
            )

        logger.info(f"Usuario {get_current_username()} generando PDF base64 para escaneo ID: {scan_id}")

        scan, scan_type = get_scan_by_id_for_user(scan_id, nmap_manager, nikto_manager, openvas_manager)

        if not scan or scan.user_id != user_id:  # type: ignore
            raise ScanNotFoundError(scan_id)

        try:
            pdf_creator = build_pdf_creator(scan)
            pdf_path = pdf_creator.print_pdf()
        except Exception as e:
            logger.error(f"Error generando PDF base64: {e}")
            raise ReportGenerationError(scan_id, str(e))

        if not pdf_path or not os.path.exists(pdf_path):
            raise ReportGenerationError(
                scan_id,
                "El archivo PDF no se generó correctamente"
            )

        with open(pdf_path, "rb") as pdf_file:
            pdf_base64 = base64.b64encode(pdf_file.read()).decode("utf-8")

        logger.info(f"Usuario {get_current_username()}: PDF base64 generado para escaneo {scan_id}")

        return jsonify({
            "message": "PDF generado exitosamente",
            "scanId": scan_id,
            "scanType": scan_type,
            "filename": f"{scan_type}_scan_{scan_id}.pdf",
            "pdfBase64": pdf_base64,
            "contentType": "application/pdf",
            "user": get_current_username()
        }), 200

    except (MissingParameterError, ValidationError, ScanNotFoundError, ReportGenerationError) as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error interno al generar PDF base64: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

# ============================================================================
# ENDPOINTS DE CONSULTA DE RESULTADOS
# ============================================================================
@app.route("/sentinel/results", methods=["GET"])
@require_oauth_token
def retrieve_all_scans():
    """
    Obtiene todos los escaneos del usuario autenticado.

    Query Parameters opcionales:
        type: Tipo de escaneo ('nmap', 'nikto', 'openvas', o 'all'). Default: 'all'

    Headers requeridos:
        Authorization: Bearer <token>

    Returns:
        JSON con la lista de escaneos del usuario
    """
    try:
        user_id = get_current_user_id()
        nmap_manager, nikto_manager, openvas_manager = get_user_managers(user_id)

        scan_type = request.args.get("type", "all").lower()
        logger.info(f"Usuario {get_current_username()} obteniendo escaneos del tipo: {scan_type}")

        if scan_type not in ["nmap", "nikto", "openvas", "all"]:
            raise ValidationError(
                field="type",
                message="Tipo de escaneo inválido",
                value=scan_type,
                expected="'nmap', 'nikto', 'openvas' o 'all'"
            )

        all_results = []

        # Obtener escaneos Nmap si aplica
        if scan_type in ["nmap", "all"]:
            try:
                nmap_results = nmap_manager.get_scans_for_user()
                formatted_nmap = [
                    {
                        "id": result.id,
                        "scanType": "nmap",
                        "target": result.target,
                        "startedAt": (
                            result.started_at.isoformat()
                            if hasattr(result.started_at, "isoformat")
                            else str(result.started_at)
                        ),
                        "openPorts": [
                            {
                                "port": f"{open_port.port_id}/{open_port.port.protocol}",
                                "reason": open_port.reason
                            }
                            for open_port in result.open_ports_relation
                        ],
                        "totalOpenPorts": len(result.open_ports_relation)
                    }
                    for result in nmap_results
                ]
                all_results.extend(formatted_nmap)
                logger.info(f"Usuario {get_current_username()}: {len(formatted_nmap)} escaneos Nmap")
            except Exception as e:
                logger.error(f"Error obteniendo escaneos Nmap: {str(e)}")

        # Obtener escaneos Nikto si aplica
        if scan_type in ["nikto", "all"]:
            try:
                nikto_results = nikto_manager.get_scans_for_user()
                formatted_nikto = [
                    {
                        "id": result.id,
                        "scanType": "nikto",
                        "target": result.target,
                        "startedAt": (
                            result.started_at.isoformat()
                            if hasattr(result.started_at, "isoformat")
                            else str(result.started_at)
                        ),
                        "incidents": [
                            {
                                "osvdbId": incident.osvdb_id,
                                "method": incident.method,
                                "url": incident.url,
                                "description": incident.description,
                                "severity": getattr(incident, "severity", "UNKNOWN"),
                                "discoveredAt": (
                                    incident.discovered_at.isoformat()
                                    if hasattr(incident.discovered_at, "isoformat")
                                    else str(incident.discovered_at)
                                ),
                            }
                            for incident in result.incidents
                        ],
                        "totalIncidents": len(result.incidents)
                    }
                    for result in nikto_results
                ]
                all_results.extend(formatted_nikto)
                logger.info(f"Usuario {get_current_username()}: {len(formatted_nikto)} escaneos Nikto")
            except Exception as e:
                logger.error(f"Error obteniendo escaneos Nikto: {str(e)}")

        # Obtener escaneos OpenVAS si aplica
        if scan_type in ["openvas", "all"]:
            try:
                openvas_results = openvas_manager.get_scans_for_user()
                formatted_openvas = [
                    {
                        "id": result.id,
                        "scanType": "openvas",
                        "target": result.target,
                        "taskId": result.task_id,
                        "reportId": result.report_id,
                        "startedAt": (
                            result.started_at.isoformat()
                            if hasattr(result.started_at, "isoformat")
                            else str(result.started_at)
                        ),
                        "vulnerabilities": [
                            {
                                "nvtOid": vuln_result.vulnerability.nvt_oid,
                                "name": vuln_result.vulnerability.name,
                                "severityScore": vuln_result.vulnerability.severity_score,
                                "severityClass": vuln_result.vulnerability.severity_class,
                                "cveIds": vuln_result.vulnerability.cve_ids,
                                "hostIp": vuln_result.host.ip_address if vuln_result.host else None
                            }
                            for vuln_result in result.results[:10]
                        ],
                        "totalVulnerabilities": len(result.results),
                        "criticalCount": sum(
                            1 for r in result.results
                            if r.vulnerability.severity_class == "Critical"
                        ),
                        "highCount": sum(
                            1 for r in result.results
                            if r.vulnerability.severity_class == "High"
                        )
                    }
                    for result in openvas_results
                ]
                all_results.extend(formatted_openvas)
                logger.info(f"Usuario {get_current_username()}: {len(formatted_openvas)} escaneos OpenVAS")
            except Exception as e:
                logger.error(f"Error obteniendo escaneos OpenVAS: {str(e)}", exc_info=True)

        logger.info(f"Usuario {get_current_username()}: Total {len(all_results)} escaneos")

        return jsonify({
            "message": "Escaneos obtenidos correctamente",
            "filter": scan_type,
            "count": len(all_results),
            "results": all_results,
            "user": get_current_username()
        }), 200

    except ValidationError as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error al obtener escaneos: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

@app.route("/sentinel/results/<int:scan_id>", methods=["GET"])
@require_oauth_token
def retrieve_scan_by_id(scan_id: int):
    """
    Obtiene un escaneo específico del usuario autenticado.

    Path Parameters:
        scan_id: ID del escaneo

    Headers requeridos:
        Authorization: Bearer <token>

    Returns:
        JSON con los detalles del escaneo
    """
    try:
        user_id = get_current_user_id()
        nmap_manager, nikto_manager, openvas_manager = get_user_managers(user_id)

        logger.info(f"Usuario {get_current_username()} obteniendo escaneo ID: {scan_id}")

        scan, scan_type = get_scan_by_id_for_user(
            scan_id, nmap_manager, nikto_manager, openvas_manager
        )

        if not scan:
            raise ScanNotFoundError(scan_id)

        # Formatear resultado según el tipo de escaneo
        if scan_type == "nmap":
            formatted_result = {
                "id": scan.id,
                "scanType": "nmap",
                "target": scan.target,
                "startedAt": (
                    scan.started_at.isoformat()
                    if hasattr(scan.started_at, "isoformat")
                    else str(scan.started_at)
                ),
                "openPorts": [
                    {
                        "port": f"{port.port_id}/{port.port.protocol}",
                        "reason": port.reason,
                        "product": port.product,
                        "version": port.version
                    }
                    for port in scan.open_ports_relation
                ],
                "totalOpenPorts": len(scan.open_ports_relation)
            }
        elif scan_type == "nikto":
            formatted_result = {
                "id": scan.id,
                "scanType": "nikto",
                "target": scan.target,
                "startedAt": (
                    scan.started_at.isoformat()
                    if hasattr(scan.started_at, "isoformat")
                    else str(scan.started_at)
                ),
                "incidents": [
                    {
                        "osvdbId": incident.osvdb_id,
                        "method": incident.method,
                        "url": incident.url,
                        "description": incident.description,
                        "severity": getattr(incident, "severity", "UNKNOWN"),
                        "discoveredAt": (
                            incident.discovered_at.isoformat()
                            if hasattr(incident.discovered_at, "isoformat")
                            else str(incident.discovered_at)
                        ),
                    }
                    for incident in scan.incidents
                ],
                "totalIncidents": len(scan.incidents)
            }
        else:  # openvas
            formatted_result = {
                "id": scan.id,
                "scanType": "openvas",
                "target": scan.target,
                "taskId": scan.task_id,
                "reportId": scan.report_id,
                "startedAt": (
                    scan.started_at.isoformat()
                    if hasattr(scan.started_at, "isoformat")
                    else str(scan.started_at)
                ),
                "vulnerabilities": [
                    {
                        "nvtOid": vuln_result.vulnerability.nvt_oid,
                        "name": vuln_result.vulnerability.name,
                        "severityScore": vuln_result.vulnerability.severity_score,
                        "severityClass": vuln_result.vulnerability.severity_class,
                        "cvssBaseScore": vuln_result.vulnerability.cvss_base_score,
                        "cvssVector": vuln_result.vulnerability.cvss_vector,
                        "cveIds": vuln_result.vulnerability.cve_ids,
                        "description": vuln_result.vulnerability.description,
                        "solution": vuln_result.vulnerability.solution,
                        "solutionType": vuln_result.vulnerability.solution_type,
                        "affectedSoftware": vuln_result.vulnerability.affected_software,
                        "hostIp": vuln_result.host.ip_address if vuln_result.host else None,
                        "hostName": vuln_result.host.hostname if vuln_result.host else None
                    }
                    for vuln_result in scan.results
                ],
                "totalVulnerabilities": len(scan.results),
                "severityBreakdown": {
                    "critical": sum(1 for r in scan.results if r.vulnerability.severity_class == "Critical"),
                    "high": sum(1 for r in scan.results if r.vulnerability.severity_class == "High"),
                    "medium": sum(1 for r in scan.results if r.vulnerability.severity_class == "Medium"),
                    "low": sum(1 for r in scan.results if r.vulnerability.severity_class == "Low"),
                    "info": sum(1 for r in scan.results if r.vulnerability.severity_class == "Log")
                }
            }

        logger.info(f"Usuario {get_current_username()}: Escaneo {scan_type} ID {scan_id} obtenido")

        return jsonify({
            "message": "Escaneo obtenido correctamente",
            "result": formatted_result,
            "user": get_current_username()
        }), 200

    except ScanNotFoundError as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code
    except Exception as e:
        logger.error(f"Error al obtener escaneo ID {scan_id}: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code

# ============================================================================
# ENDPOINTS DE ELIMINACIÓN DE ESCANEOS
# ============================================================================
@app.route("/sentinel/scans/<int:scan_id>", methods=["DELETE"])
@require_oauth_token
def delete_scan(scan_id: int):
    """
    Elimina un escaneo del sistema dado su ID.

    Path Parameters:
        scan_id: ID del escaneo a eliminar

    Headers requeridos:
        Authorization: Bearer <token>

    Returns:
        JSON con el resultado de la eliminación

    Response codes:
        200: Escaneo eliminado exitosamente
        401: No autorizado
        403: El escaneo no pertenece al usuario
        404: Escaneo no encontrado
        500: Error interno al eliminar
    """
    try:
        user_id = get_current_user_id()
        nmap_manager, nikto_manager, openvas_manager = get_user_managers(user_id)

        logger.info(
            f"Usuario {get_current_username()} intentando eliminar escaneo ID: {scan_id}"
        )

        # Localizar el escaneo en los tres managers
        scan, scan_type = get_scan_by_id_for_user(
            scan_id, nmap_manager, nikto_manager, openvas_manager
        )

        # Si no existe, lanzar error de no encontrado
        if not scan:
            logger.warning(f"Escaneo {scan_id} no encontrado para eliminación")
            raise ScanNotFoundError(scan_id)

        # Verificar propiedad: solo el dueño puede borrar su escaneo
        if scan.user_id != user_id:
            logger.warning(
                f"Usuario {get_current_username()} (ID: {user_id}) intentó eliminar "
                f"el escaneo {scan_id} que pertenece al usuario ID: {scan.user_id}"
            )
            return jsonify({
                "error": "forbidden",
                "message": "No tienes permiso para eliminar este escaneo",
                "scanId": scan_id
            }), 403

        # Seleccionar el manager correcto
        if scan_type == "nmap":
            manager = nmap_manager
        elif scan_type == "nikto":
            manager = nikto_manager
        else:
            manager = openvas_manager

        # Si el escaneo está en curso, cancelarlo antes de borrar
        if scan.status in ["pending", "running"]:
            logger.info(
                f"Escaneo {scan_id} en curso (estado: {scan.status}), "
                f"cancelando antes de eliminar"
            )
            manager.cancel_scan(scan_id)

        # Eliminar el escaneo
        success = manager.delete_scan(scan_id)

        if not success:
            logger.error(f"No se pudo eliminar el escaneo {scan_id}")
            return jsonify({
                "error": "deletion_failed",
                "message": "No se pudo eliminar el escaneo",
                "scanId": scan_id
            }), 500

        logger.info(
            f"Usuario {get_current_username()}: escaneo {scan_type} ID {scan_id} eliminado"
        )
        return jsonify({
            "message": "Escaneo eliminado correctamente",
            "scanId": scan_id,
            "scanType": scan_type,
            "user": get_current_username()
        }), 200

    except ScanNotFoundError as e:
        error_dict, status_code = create_error_response(e, include_debug_info=False)
        return jsonify(error_dict), status_code

    except Exception as e:
        logger.error(f"Error eliminando escaneo {scan_id}: {str(e)}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
        error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(error_dict), status_code


# ============================================================================
# MANEJO DE ERRORES GLOBALES
# ============================================================================
@app.errorhandler(404)
def not_found(error):
    """Manejo de rutas no encontradas."""
    logger.warning(f"Endpoint no encontrado: {request.url}")
    return jsonify({
        "error": "Endpoint no encontrado",
        "message": "La ruta solicitada no existe",
        "path": request.path
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    """Manejo de métodos HTTP no permitidos."""
    logger.warning(f"Método no permitido: {request.method} en {request.url}")
    return jsonify({
        "error": "Método no permitido",
        "message": f"El método {request.method} no está permitido para este endpoint",
        "allowedMethods": list(error.valid_methods) if hasattr(error, 'valid_methods') else []
    }), 405

@app.errorhandler(500)
def internal_error(error):
    """Manejo de errores internos del servidor."""
    logger.error(f"Error interno del servidor: {str(error)}", exc_info=True)
    return jsonify({
        "error": "Error interno del servidor",
        "message": "Ha ocurrido un error inesperado"
    }), 500



# ============================================================================
# EJECUCIÓN
# ============================================================================
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
