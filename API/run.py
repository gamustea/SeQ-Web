"""
API REST para SecOps - Sistema de escaneo de seguridad
Versión con autenticación y managers por usuario.
"""

import os
import base64
import time
from functools import wraps
from typing import Optional, Tuple

from flask import send_file, request, jsonify, Flask
from flask_cors import CORS

from src.persistence import UserDBManager
from src.logic.tasking.managers import NmapScanManager, NiktoScanManager
from src.misc.documents import PDFCreator, NmapPrintingStrategy, NiktoPrintingStrategy
from src.misc.logging import SecOpsLogger
from src.misc.validation import PortValidator, IPValidator
from src.core.model import Scan, User

# Importar excepciones personalizadas
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
    ExceptionHandler
)

# Importar UserManager para autenticación
from src.logic.userutilities import UserManager

# ============================================================================
# INICIALIZACIÓN DE LA APLICACIÓN
# ============================================================================

app = Flask(__name__)
CORS(app)

# Configurar logger
logger_instance = SecOpsLogger(name="APIMain")
logger = logger_instance.get_logger()

# Manager de usuarios para autenticación
USER_MANAGER = UserManager()

# ============================================================================
# UTILIDADES DE AUTENTICACIÓN Y USUARIO
# ============================================================================


def get_current_user_id() -> int:
    return request.current_user_id # type: ignore

def get_current_username() -> str:
    return request.current_username # type: ignore

def get_user_managers(user_id: int) -> Tuple[NmapScanManager, NiktoScanManager]:
    """
    Crea managers de escaneo para un usuario específico.

    Args:
        user: Usuario del ORM para el cual crear los managers

    Returns:
        Tupla (NmapScanManager, NiktoScanManager) configurados para el usuario
    """
    user_db = UserDBManager()
    user = user_db.get_user_by_id(user_id)
    nmap_manager = NmapScanManager(user)
    nikto_manager = NiktoScanManager(user)
    user_db.close_session()
    return nmap_manager, nikto_manager


# ============================================================================
# DECORADOR DE AUTENTICACIÓN
# ============================================================================

def require_authentication(f):
    """
    Decorador que verifica las credenciales del usuario en cada petición.

    Requiere headers:
        - X-Username: Nombre de usuario
        - X-Password: Contraseña del usuario

    El usuario autenticado se almacena en request.current_user y está
    disponible durante toda la petición. Es un objeto User del ORM con
    todos sus atributos (id, username, password, etc.)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Obtener credenciales de los headers
            username = request.headers.get("X-Username")
            password = request.headers.get("X-Password")

            # Validar que existan ambos headers
            if not username:
                logger.warning("Intento de acceso sin header X-Username")
                raise MissingParameterError("X-Username")

            if not password:
                logger.warning(f"Intento de acceso sin header X-Password para usuario: {username}")
                raise MissingParameterError("X-Password")

            # Verificar credenciales usando UserManager
            is_valid, user_id = USER_MANAGER.verify_credentials(username, password)
            request.current_user_id = user_id # type: ignore
            request.current_username = username # type: ignore

            if not is_valid:
                logger.warning(f"Credenciales inválidas para usuario: {username}")
                raise InvalidCredentialsError()
            
            logger.info(f"Usuario autenticado: {username} (ID: {user_id})")

            return f(*args, **kwargs)

        except (MissingParameterError, InvalidCredentialsError) as e:
            error_dict, status_code = create_error_response(e, include_debug_info=False)
            return jsonify(error_dict), status_code
        except Exception as e:
            logger.error(f"Error en autenticación: {str(e)}", exc_info=True)
            sec_exc = ExceptionHandler.wrap_exception(e, logger=logger)
            error_dict, status_code = create_error_response(sec_exc, include_debug_info=False)
            return jsonify(error_dict), status_code

    return decorated_function


# ============================================================================
# FUNCIONES AUXILIARES
# ============================================================================

def build_pdf_creator(scan: Scan) -> PDFCreator:
    """
    Construye el creador de PDF apropiado según el tipo de escaneo.

    Args:
        scan: Objeto Scan (Nmap o Nikto)

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
    else:
        logger.error(f"Tipo de escaneo no soportado: {scan_type}")
        raise ValidationError(
            field="scan_type",
            message=f"Tipo de escaneo '{scan_type}' no soportado",
            expected="'nmap' o 'nikto'"
        )

    return PDFCreator(strategy)


def get_scan_by_id_for_user(
    scan_id: int, 
    nmap_manager: NmapScanManager, 
    nikto_manager: NiktoScanManager
) -> Tuple[Optional[Scan], str]:
    """
    Busca un escaneo por ID usando los managers del usuario.

    Args:
        scan_id: ID del escaneo a buscar
        nmap_manager: Manager de Nmap del usuario
        nikto_manager: Manager de Nikto del usuario

    Returns:
        Tupla (Scan, tipo) donde tipo es 'nmap' o 'nikto'. 
        Retorna (None, '') si no se encuentra
    """
    # Buscar en Nmap
    scan = nmap_manager.get_scan_by_id(scan_id)
    if scan:
        return scan, "nmap"

    # Buscar en Nikto
    scan = nikto_manager.get_scan_by_id(scan_id)
    if scan:
        return scan, "nikto"

    return None, ""


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
        "version": "2.0-multiuser"
    }), 200


@app.route("/is-finished", methods=["GET"])
@require_authentication
def is_scan_finished():
    """
    Verifica si un escaneo ha finalizado.

    Query Parameters:
        id: ID del escaneo a verificar

    Headers requeridos:
        X-Username: Usuario autenticado
        X-Password: Contraseña del usuario

    Returns:
        JSON indicando si el escaneo existe y si está finalizado
    """
    try:
        # Obtener usuario autenticado
        user_id = get_current_user_id()
        nmap_manager, nikto_manager = get_user_managers(user_id)

        # Obtener y validar el ID del escaneo
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

        # Buscar el escaneo usando los managers del usuario
        scan, scan_type = get_scan_by_id_for_user(scan_id, nmap_manager, nikto_manager)

        if not scan or scan.user_id != user_id: #type: ignore
            raise ScanNotFoundError(scan_id)

        # Verificar si está finalizado usando el manager correcto
        manager = nmap_manager if scan_type == "nmap" else nikto_manager
        scan_finished = manager.scan_is_finished(scan)

        message = (
            f"El escaneo con id {scan_id} está terminado"
            if scan_finished
            else f"El escaneo con id {scan_id} no está terminado"
        )

        logger.info(f"Usuario {get_current_username()}: escaneo {scan_id} - {'finalizado' if scan_finished else 'en progreso'}")

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


# ============================================================================
# ENDPOINTS DE ESCANEO NMAP
# ============================================================================

@app.route("/scans/nmap/start", methods=["POST"])
@require_authentication
def start_nmap_scan():
    """
    Inicia un escaneo Nmap para el usuario autenticado.

    Headers requeridos:
        X-Target-Host: Host o IP a escanear (ej: "192.168.1.1", "192.168.1.0/24")
        X-Target-Ports: Puertos a escanear (ej: "80,443", "1-1000")
        X-Username: Usuario autenticado
        X-Password: Contraseña del usuario

    Returns:
        JSON con el ID(s) del escaneo iniciado
    """
    try:
        user_id = get_current_user_id()
        nmap_manager, _ = get_user_managers(user_id)

        # Obtener parámetros de los headers
        host = request.headers.get("X-Target-Host")
        ports = request.headers.get("X-Target-Ports")

        # Validar parámetros requeridos
        if not host:
            raise MissingParameterError("X-Target-Host")

        if not ports:
            raise MissingParameterError("X-Target-Ports")

        # Validar formato del host
        if not host.strip():
            raise ValidationError(
                field="X-Target-Host",
                message="El host no puede estar vacío"
            )

        # Validar formato de puertos
        if not ports.strip():
            raise ValidationError(
                field="X-Target-Ports",
                message="Los puertos no pueden estar vacíos"
            )

        # Validar formato de IP/host
        valido, hosts, mensaje = IPValidator.validate(host)
        if not valido:
            raise ValidationError(
                field="X-Target-Host",
                message=mensaje,
                value=host
            )

        # Validar formato de puertos
        valido, puertos, mensaje = PortValidator.validate(ports)
        if not valido:
            raise ValidationError(
                field="X-Target-Ports",
                message=mensaje,
                value=ports
            )

        # Ejecutar el escaneo para cada host
        scan_ids = []
        for target_host in hosts:
            try:
                # Usar el manager del usuario autenticado
                scan_id = nmap_manager.run_task(target_host, ports)
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

@app.route("/scans/nikto/start", methods=["POST"])
@require_authentication
def start_nikto_scan():
    """
    Inicia un escaneo Nikto para el usuario autenticado.

    Headers requeridos:
        X-Target: URL objetivo del escaneo (ej: "http://example.com")
        X-Username: Usuario autenticado
        X-Password: Contraseña del usuario

    Query Parameters opcionales:
        timeout: Tiempo máximo de ejecución en segundos (default: 180)

    Returns:
        JSON con el ID del escaneo iniciado
    """
    try:
        # Obtener usuario autenticado
        user_id = get_current_user_id()

        # Crear manager específico para este usuario
        _, nikto_manager = get_user_managers(user_id)

        # Obtener parámetros
        target = request.headers.get("X-Target")
        timeout = request.args.get("timeout", 180)

        # Validar target requerido
        if not target:
            raise MissingParameterError("X-Target")

        # Validar que el target no esté vacío
        if not target.strip():
            raise ValidationError(
                field="X-Target",
                message="El target no puede estar vacío"
            )

        # Validar timeout
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

        # Ejecutar el escaneo
        try:
            # Usar el manager del usuario autenticado
            scan_id = nikto_manager.run_task(target, timeout=timeout)
            logger.info(
                f"Usuario {get_current_username}: Escaneo Nikto ID={scan_id}, "
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
# ENDPOINTS DE GENERACIÓN DE PDFs
# ============================================================================

@app.route("/scans/generate-pdf", methods=["GET"])
@require_authentication
def generate_pdf():
    """
    Genera y descarga un PDF de un escaneo del usuario autenticado.

    Query Parameters:
        id: ID del escaneo

    Headers requeridos:
        X-Username: Usuario autenticado
        X-Password: Contraseña del usuario

    Returns:
        Archivo PDF para descarga directa
    """
    try:
        user_id = get_current_user_id()
        nmap_manager, nikto_manager = get_user_managers(user_id)

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

        # Buscar el escaneo usando los managers del usuario
        scan, scan_type = get_scan_by_id_for_user(scan_id, nmap_manager, nikto_manager)

        # Validar que el escaneo exista y pertenezca al usuario
        if not scan or scan.user_id != user_id: #type: ignore
            raise ScanNotFoundError(scan_id)

        # Verificar que el escaneo esté finalizado
        manager = nmap_manager if scan_type == "nmap" else nikto_manager
        if not manager.scan_is_finished(scan):
            raise ValidationError(
                field="scan_id",
                message=f"El escaneo con ID {scan_id} no está finalizado aún",
                value=scan_id
            )

        # Generar el PDF
        try:
            pdf_creator = build_pdf_creator(scan)
            pdf_path = pdf_creator.print_pdf()
        except Exception as e:
            logger.error(f"Error generando PDF: {e}")
            raise ReportGenerationError(scan_id, str(e))

        # Validar que el archivo se creó correctamente
        if not pdf_path or not os.path.exists(pdf_path):
            raise ReportGenerationError(
                scan_id,
                "El archivo PDF no se generó correctamente"
            )

        logger.info(f"Usuario {get_current_username()}: PDF generado - {pdf_path}")

        # Enviar el archivo PDF como respuesta
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


@app.route("/scans/generate-pdf-base64", methods=["GET"])
@require_authentication
def generate_pdf_base64():
    """
    Genera un PDF de un escaneo y lo devuelve en formato base64.

    Query Parameters:
        id: ID del escaneo

    Headers requeridos:
        X-Username: Usuario autenticado
        X-Password: Contraseña del usuario

    Returns:
        JSON con el PDF en base64 y metadata
    """
    try:
        # Obtener usuario autenticado
        user_id = get_current_user_id()
        nmap_manager, nikto_manager = get_user_managers(user_id)

        # Obtener y validar el ID del escaneo
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

        # Buscar el escaneo
        scan, scan_type = get_scan_by_id_for_user(scan_id, nmap_manager, nikto_manager)

        if not scan or scan.user_id != user_id: #type: ignore
            raise ScanNotFoundError(scan_id)

        # Generar el PDF
        try:
            pdf_creator = build_pdf_creator(scan)
            pdf_path = pdf_creator.print_pdf()
        except Exception as e:
            logger.error(f"Error generando PDF base64: {e}")
            raise ReportGenerationError(scan_id, str(e))

        # Validar que el archivo se creó
        if not pdf_path or not os.path.exists(pdf_path):
            raise ReportGenerationError(
                scan_id,
                "El archivo PDF no se generó correctamente"
            )

        # Leer el archivo y convertirlo a base64
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

@app.route("/scans/results", methods=["GET"])
@require_authentication
def retrieve_all_scans():
    """
    Obtiene todos los escaneos del usuario autenticado.

    Query Parameters opcionales:
        type: Tipo de escaneo ('nmap', 'nikto', o 'all'). Default: 'all'

    Headers requeridos:
        X-Username: Usuario autenticado
        X-Password: Contraseña del usuario

    Returns:
        JSON con la lista de escaneos del usuario
    """
    try:
        scan_id = get_current_user_id()
        nmap_manager, nikto_manager = get_user_managers(scan_id)

        scan_type = request.args.get("type", "all").lower()
        logger.info(f"Usuario {get_current_username()} obteniendo escaneos del tipo: {scan_type}")

        # Validar tipo de escaneo
        if scan_type not in ["nmap", "nikto", "all"]:
            raise ValidationError(
                field="type",
                message="Tipo de escaneo inválido",
                value=scan_type,
                expected="'nmap', 'nikto' o 'all'"
            )

        all_results = []

        # Obtener escaneos Nmap si aplica
        if scan_type in ["nmap", "all"]:
            try:
                # Obtener solo los escaneos de ESTE usuario
                nmap_results = nmap_manager.get_scans_for_user()
                formatted_nmap = [
                    {
                        "id": result.id,
                        "scanType": "nmap",
                        "target": result.target,
                        "targetedPorts": [
                            f"{port.id}/{port.protocol}" for port in result.target_ports
                        ],
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
                # Obtener solo los escaneos de ESTE usuario
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


@app.route("/scans/results/<int:scan_id>", methods=["GET"])
@require_authentication
def retrieve_scan_by_id(scan_id: int):
    """
    Obtiene un escaneo específico del usuario autenticado.

    Path Parameters:
        scan_id: ID del escaneo

    Headers requeridos:
        X-Username: Usuario autenticado
        X-Password: Contraseña del usuario

    Returns:
        JSON con los detalles del escaneo
    """
    try:
        # Obtener usuario autenticado
        user_id = get_current_user_id()

        # Crear managers para este usuario
        nmap_manager, nikto_manager = get_user_managers(user_id)

        logger.info(f"Usuario {get_current_username()} obteniendo escaneo ID: {scan_id}")

        # Buscar el escaneo usando los managers del usuario
        scan, scan_type = get_scan_by_id_for_user(scan_id, nmap_manager, nikto_manager)

        if not scan:
            raise ScanNotFoundError(scan_id)

        # Formatear resultado según el tipo de escaneo
        if scan_type == "nmap":
            formatted_result = {
                "id": scan.id,
                "scanType": "nmap",
                "target": scan.target,
                "targetedPorts": [
                    f"{port.id}/{port.protocol}" for port in scan.target_ports
                ],
                "startedAt": (
                    scan.started_at.isoformat()
                    if hasattr(scan.started_at, "isoformat")
                    else str(scan.started_at)
                ),
                "openPorts": [
                    {
                        "port": f"{port.port_id}/{port.port.protocol}",
                        "reason": port.reason
                    }
                    for port in scan.open_ports_relation
                ],
                "totalOpenPorts": len(scan.open_ports_relation)
            }
        else:  # nikto
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
    logger.info("=" * 80)
    logger.info("Iniciando SecOps API v2.0 - Multiusuario")
    logger.info("=" * 80)
    logger.info("Características:")
    logger.info("  - Autenticación por usuario (X-Username, X-Password)")
    logger.info("  - Managers de escaneo por usuario")
    logger.info("  - Manejo robusto de excepciones")
    logger.info("  - Logs detallados por usuario")
    logger.info("=" * 80)

    app.run(debug=True, host="0.0.0.0", port=5000)