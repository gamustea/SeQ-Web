import os
import base64

from src.persistence import UserDBManager
from src.scanning.managers import NmapScanManager, NiktoScanManager
from src.misc.documents import PDFCreator, NmapPrintingStrategy, NiktoPrintingStrategy
from src.misc.logging import SecOpsLogger
from src.model import Scan

from flask import send_file, request, jsonify, Flask

# Inicialización
USER = UserDBManager().get_user_by_id(1)
NMAP_MANAGER = NmapScanManager(USER)
NIKTO_MANAGER = NiktoScanManager(USER)
PDF_CREATOR = None

app = Flask(__name__)

# Configurar logger
logger_instance = SecOpsLogger(name="APIMain")
logger = logger_instance.get_logger()



def build_pdf_creator(scan: Scan) -> PDFCreator:
    # Generar el PDF según el tipo de escaneo
    if scan.scan_type == "nmap":        #type: ignore
        strategy = NmapPrintingStrategy(scan=scan)
    elif scan.scan_type == "nikto":     #type: ignore
        strategy = NiktoPrintingStrategy(scan=scan)
    else:
        logger.error(f"Tipo de escaneo no soportado: {scan.scan_type}")
        return jsonify({"error": f"Tipo de escaneo no soportado: {scan.scan_type}"}), 400

    return PDFCreator(strategy)

# ============================================================================
# ENDPOINTS GENERALES
# ============================================================================

@app.route("/api/say-hello", methods=["GET"])
def hello():
    """Endpoint de prueba para verificar que la API está funcionando."""
    logger.info("Endpoint /api/say-hello invocado")
    return (
        jsonify({"message": "You did it! You reached an endpoint!", "status": "ok"}),
        200,
    )

# ============================================================================
# ENDPOINTS DE ESCANEO
# ============================================================================

@app.route("/api/scans/nmap/start", methods=["POST"])
def start_nmap_scan():
    """
    Inicia un escaneo Nmap.
    Headers requeridos:
    - host: Host o IP a escanear
    - ports: Puertos a escanear (ej: "80,443" o "1-1000")
    Returns:
    JSON con el ID del escaneo iniciado
    """
    try:
        logger.info("Iniciando escaneo Nmap")
        # Obtener parámetros de los headers
        host = request.headers.get("host")
        ports = request.headers.get("ports")

        # Validar parámetros requeridos
        if not host or not ports:
            logger.warning(
                "Faltan parámetros requeridos en la solicitud de escaneo Nmap"
            )
            return (
                jsonify(
                    {
                        "error": "Faltan cabeceras requeridas",
                        "required_headers": ["host", "ports"],
                    }
                ),
                400,
            )

        # Validar formato básico del host
        if not host.strip():
            logger.warning("Host vacío proporcionado")
            return jsonify({"error": "El host no puede estar vacío"}), 400

        # Validar formato básico de puertos
        if not ports.strip():
            logger.warning("Puertos vacíos proporcionados")
            return jsonify({"error": "Los puertos no pueden estar vacíos"}), 400

        # Ejecutar el escaneo
        scan_id = NMAP_MANAGER.run_task(host, ports)
        logger.info(
            f"Escaneo Nmap iniciado correctamente con ID: {scan_id}, host: {host}, ports: {ports}"
        )

        return (
            jsonify(
                {
                    "message": "Escaneo Nmap iniciado correctamente",
                    "scanId": scan_id,
                    "target": {"host": host, "ports": ports},
                }
            ),
            201,
        )

    except Exception as e:
        logger.error(f"Error al iniciar el escaneo Nmap: {str(e)}", exc_info=True)
        return jsonify({"error": "Error al iniciar el escaneo", "details": str(e)}), 500

@app.route("/api/scans/nikto/start", methods=["POST"])
def start_nikto_scan():
    """
    Inicia un escaneo Nikto.
    Headers requeridos:
    - target: URL objetivo del escaneo
    Query Parameters opcionales:
    - timeout: Tiempo máximo de ejecución en segundos (default: 180)
    Returns:
    JSON con el ID del escaneo iniciado
    """
    try:
        logger.info("Iniciando escaneo Nikto")
        # Obtener parámetros
        target = request.headers.get("target")
        timeout = request.args.get("timeout", 180)

        # Validar target requerido
        if not target:
            logger.warning("Falta la cabecera 'target' para iniciar escaneo Nikto")
            return jsonify({"error": "Falta la cabecera requerida 'target'"}), 400

        # Validar que el target no esté vacío
        if not target.strip():
            logger.warning("Target vacío proporcionado")
            return jsonify({"error": "El target no puede estar vacío"}), 400

        # Validar timeout
        try:
            timeout = int(timeout)
            if timeout <= 0:
                logger.warning(f"Timeout inválido proporcionado: {timeout}")
                return jsonify({"error": "El timeout debe ser un número positivo"}), 400
        except ValueError:
            logger.warning(f"Formato de timeout inválido: {timeout}")
            return (
                jsonify({"error": "El timeout debe ser un número entero válido"}),
                400,
            )

        # Ejecutar el escaneo
        scan_id = NIKTO_MANAGER.run_task(target, timeout=timeout)
        logger.info(
            f"Escaneo Nikto iniciado correctamente con ID: {scan_id}, target: {target}, timeout: {timeout}"
        )

        return (
            jsonify(
                {
                    "message": "Escaneo Nikto iniciado correctamente",
                    "scanId": scan_id,
                    "target": target,
                    "timeout": timeout,
                }
            ),
            201,
        )

    except Exception as e:
        logger.error(f"Error al iniciar el escaneo Nikto: {str(e)}", exc_info=True)
        return jsonify({"error": "Error al iniciar el escaneo", "details": str(e)}), 500


# ============================================================================
# GENERAR PDFs
# ============================================================================

@app.route("/api/scans/generate-pdf", methods=["GET"])
def generate_pdf():
    """
    Genera y descarga un PDF de un escaneo (Nmap o Nikto).
    Query Parameters:
    - id: ID del escaneo

    Returns:
    Archivo PDF para descarga directa
    """
    try:
        # Obtener el ID del query parameter
        scan_id = request.args.get("id")
        logger.info(f"Generando PDF para escaneo con ID: {scan_id}")

        # Validar que se proporcione el ID
        if not scan_id:
            logger.warning("Parámetro 'id' no proporcionado para generar PDF")
            return jsonify({"error": "El parámetro 'id' es requerido"}), 400

        # Validar formato del ID
        try:
            scan_id_int = int(scan_id)
        except ValueError:
            logger.warning(f"ID inválido proporcionado: {scan_id}")
            return jsonify({"error": "El ID debe ser un número entero válido"}), 400

        # Intentar obtener el escaneo primero como Nmap
        scan = NMAP_MANAGER.get_scan_by_id(scan_id_int)
        scan_type = "nmap"

        # Si no existe en Nmap, buscar en Nikto
        if not scan:
            scan = NIKTO_MANAGER.get_scan_by_id(scan_id_int)
            scan_type = "nikto"

        # Validar que el escaneo existe
        if not scan:
            logger.warning(f"Escaneo con ID {scan_id} no encontrado en Nmap ni Nikto")
            return (
                jsonify({"error": f"No se encontró el escaneo con ID: {scan_id}"}),
                404,
            )
        
        escaneo_terminado = NIKTO_MANAGER.scan_is_finished(scan)
        if not escaneo_terminado:
            return (
                jsonify({"error": f"El escaneo con el id {scan_id} no está terminado"}),
                404,
            ) 

        # Verificar si el modelo tiene atributo scan_type y usarlo
        if hasattr(scan, "scan_type"):
            scan_type = scan.scan_type.lower()

        logger.info(f"Escaneo identificado como tipo: {scan_type}")



        PDF_CREATOR = build_pdf_creator(scan)
        pdf_path = PDF_CREATOR.print_pdf()

        # Validar que el archivo se creó correctamente
        if not pdf_path or not os.path.exists(pdf_path):
            logger.error(f"Error al generar el archivo PDF para escaneo ID: {scan_id}")
            return jsonify({"error": "Error al generar el archivo PDF"}), 500

        logger.info(
            f"PDF generado correctamente para escaneo {scan_type} ID: {scan_id}"
        )

        # Enviar el archivo PDF como respuesta
        return send_file(
            pdf_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"{scan_type}_scan_{scan_id}.pdf",
        )

    except Exception as e:
        logger.error(f"Error interno al generar PDF: {str(e)}", exc_info=True)
        return jsonify({"error": "Error interno del servidor"}), 500

@app.route("/api/scans/generate-pdf-base64", methods=["GET"])
def generate_pdf_base64():
    """
    Genera un PDF de un escaneo (Nmap o Nikto) y lo devuelve en base64.
    Útil para mostrarlo directamente en el navegador.

    Query Parameters:
    - id: ID del escaneo

    Returns:
    JSON con el PDF en base64 y metadata
    """
    try:
        # Obtener el ID del query parameter
        scan_id = request.args.get("id")
        logger.info(f"Generando PDF en base64 para escaneo con ID: {scan_id}")

        if not scan_id:
            logger.warning("Parámetro 'id' no proporcionado para generar PDF base64")
            return jsonify({"error": "El parámetro 'id' es requerido"}), 400

        # Validar formato del ID
        try:
            scan_id_int = int(scan_id)
        except ValueError:
            logger.warning(f"ID inválido proporcionado: {scan_id}")
            return jsonify({"error": "El ID debe ser un número entero válido"}), 400

        # Intentar obtener el escaneo primero como Nmap
        scan = NMAP_MANAGER.get_scan_by_id(scan_id_int)
        scan_type = "nmap"

        # Si no existe en Nmap, buscar en Nikto
        if not scan:
            scan = NIKTO_MANAGER.get_scan_by_id(scan_id_int)
            scan_type = "nikto"

        # Validar que el escaneo existe
        if not scan:
            logger.warning(
                f"Escaneo con ID {scan_id} no encontrado en Nmap ni Nikto para PDF base64"
            )
            return (
                jsonify({"error": f"No se encontró el escaneo con ID: {scan_id}"}),
                404,
            )

        # Verificar si el modelo tiene atributo scan_type y usarlo
        if hasattr(scan, "scan_type"):
            scan_type = scan.scan_type.lower()

        logger.info(f"Escaneo identificado como tipo: {scan_type}")

        

        if not pdf_path or not os.path.exists(pdf_path):
            logger.error(
                f"Error al generar el archivo PDF base64 para escaneo ID: {scan_id}"
            )
            return jsonify({"error": "Error al generar el archivo PDF"}), 500

        # Leer el archivo y convertirlo a base64
        with open(pdf_path, "rb") as pdf_file:
            pdf_base64 = base64.b64encode(pdf_file.read()).decode("utf-8")

        logger.info(
            f"PDF base64 generado correctamente para escaneo {scan_type} ID: {scan_id}"
        )

        return (
            jsonify(
                {
                    "message": "PDF generado exitosamente",
                    "scanId": scan_id,
                    "scanType": scan_type,
                    "filename": f"{scan_type}_scan_{scan_id}.pdf",
                    "pdfBase64": pdf_base64,
                    "contentType": "application/pdf",
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Error interno al generar PDF base64: {str(e)}", exc_info=True)
        return jsonify({"error": "Error interno del servidor", "details": str(e)}), 500


# ============================================================================
# GENERAR JSONs
# ============================================================================

@app.route("/api/scans/results", methods=["GET"])
def retrieve_all_scans():
    """
    Obtiene todos los escaneos del usuario (Nmap y Nikto).
    
    Query Parameters (opcional):
    - type: Tipo de escaneo ('nmap', 'nikto', o 'all'). Default: 'all'
    
    Returns:
    JSON con la lista de escaneos y sus resultados
    """
    try:
        scan_type = request.args.get("type", "all").lower()
        logger.info(f"Obteniendo escaneos. Tipo: {scan_type}")
        
        # Validar tipo de escaneo
        if scan_type not in ["nmap", "nikto", "all"]:
            logger.warning(f"Tipo de escaneo inválido: {scan_type}")
            return (
                jsonify({
                    "error": "Tipo de escaneo inválido",
                    "message": "Los tipos válidos son: 'nmap', 'nikto' o 'all'"
                }),
                400,
            )
        
        all_results = []
        
        # Obtener escaneos Nmap si aplica
        if scan_type in ["nmap", "all"]:
            try:
                nmap_results = NMAP_MANAGER.get_scans_for_user()
                formatted_nmap = [
                    {
                        "id": result.id,
                        "scanType": "nmap",
                        "target": result.target,
                        "targetedPorts": [
                            f"{port.port}/{port.protocol}" 
                            for port in result.target_ports
                        ],
                        "startedAt": (
                            result.started_at.isoformat()
                            if hasattr(result.started_at, "isoformat")
                            else str(result.started_at)
                        ),
                        "openPorts": [
                            {
                                "port": f"{port.port.port}/{port.port.protocol}",
                                "reason": port.reason,
                            }
                            for port in result.open_ports_relation
                        ],
                        "totalOpenPorts": len(result.open_ports_relation),
                    }
                    for result in nmap_results
                ]
                all_results.extend(formatted_nmap)
                logger.info(f"Se obtuvieron {len(formatted_nmap)} escaneos Nmap")
            except Exception as e:
                logger.error(f"Error al obtener escaneos Nmap: {str(e)}")
        
        # Obtener escaneos Nikto si aplica
        if scan_type in ["nikto", "all"]:
            try:
                nikto_results = NIKTO_MANAGER.get_scans_for_user()
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
                        "totalIncidents": len(result.incidents),
                    }
                    for result in nikto_results
                ]
                all_results.extend(formatted_nikto)
                logger.info(f"Se obtuvieron {len(formatted_nikto)} escaneos Nikto")
            except Exception as e:
                logger.error(f"Error al obtener escaneos Nikto: {str(e)}")
        
        logger.info(f"Total de escaneos obtenidos: {len(all_results)}")
        
        return (
            jsonify(
                {
                    "message": "Escaneos obtenidos correctamente",
                    "filter": scan_type,
                    "count": len(all_results),
                    "results": all_results,
                }
            ),
            200,
        )
    
    except Exception as e:
        logger.error(f"Error al obtener los escaneos: {str(e)}", exc_info=True)
        return jsonify({"error": "Error al obtener los escaneos", "details": str(e)}), 500

@app.route("/api/scans/results/<int:scan_id>", methods=["GET"])
def retrieve_scan_by_id(scan_id):
    """
    Obtiene un escaneo específico por ID (Nmap o Nikto).
    
    Args:
    scan_id: ID del escaneo
    
    Returns:
    JSON con los detalles del escaneo
    """
    try:
        logger.info(f"Obteniendo escaneo con ID: {scan_id}")
        
        # Intentar obtener el escaneo primero como Nmap
        result = NMAP_MANAGER.get_scan_by_id(scan_id)
        scan_type = "nmap"
        
        # Si no existe en Nmap, buscar en Nikto
        if not result:
            result = NIKTO_MANAGER.get_scan_by_id(scan_id)
            scan_type = "nikto"
        
        # Validar que el escaneo existe
        if not result:
            logger.warning(
                f"Escaneo con ID {scan_id} no encontrado en Nmap ni Nikto"
            )
            return (
                jsonify({"error": f"No se encontró el escaneo con ID: {scan_id}"}),
                404,
            )
        
        # Verificar si el modelo tiene atributo scan_type y usarlo
        if hasattr(result, 'scan_type'):
            scan_type = result.scan_type.lower()
        
        logger.info(f"Escaneo identificado como tipo: {scan_type}")
        
        # Formatear resultado según el tipo de escaneo
        if scan_type == "nmap":
            formatted_result = {
                "id": result.id,
                "scanType": "nmap",
                "target": result.target,
                "targetedPorts": [
                    f"{port}/{port.protocol}" 
                    for port in result.target_ports
                ],
                "startedAt": (
                    result.started_at.isoformat()
                    if hasattr(result.started_at, "isoformat")
                    else str(result.started_at)
                ),
                "openPorts": [
                    {
                        "port": f"{port.port}/{port.port.protocol}",
                        "reason": port.reason,
                    }
                    for port in result.open_ports_relation
                ],
                "totalOpenPorts": len(result.open_ports_relation),
            }
        
        elif scan_type == "nikto":
            formatted_result = {
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
                "totalIncidents": len(result.incidents),
            }
        
        else:
            logger.error(f"Tipo de escaneo no soportado: {scan_type}")
            return jsonify({"error": f"Tipo de escaneo no soportado: {scan_type}"}), 400
        
        logger.info(f"Escaneo {scan_type} con ID {scan_id} obtenido correctamente")
        
        return (
            jsonify(
                {
                    "message": "Escaneo obtenido correctamente",
                    "result": formatted_result,
                }
            ),
            200,
        )
    
    except Exception as e:
        logger.error(
            f"Error al obtener el escaneo con ID {scan_id}: {str(e)}",
            exc_info=True,
        )
        return jsonify({"error": "Error al obtener el escaneo", "details": str(e)}), 500


# ============================================================================
# MANEJO DE ERRORES GLOBALES
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Manejo de rutas no encontradas."""
    logger.warning(f"Endpoint no encontrado: {request.url}")
    return (
        jsonify(
            {
                "error": "Endpoint no encontrado",
                "message": "La ruta solicitada no existe",
            }
        ),
        404,
    )

@app.errorhandler(405)
def method_not_allowed(error):
    """Manejo de métodos HTTP no permitidos."""
    logger.warning(f"Método no permitido: {request.method} en {request.url}")
    return (
        jsonify(
            {
                "error": "Método no permitido",
                "message": "El método HTTP utilizado no está permitido para este endpoint",
            }
        ),
        405,
    )

@app.errorhandler(500)
def internal_error(error):
    """Manejo de errores internos del servidor."""
    logger.error(f"Error interno del servidor: {str(error)}", exc_info=True)
    return (
        jsonify(
            {
                "error": "Error interno del servidor",
                "message": "Ha ocurrido un error inesperado",
            }
        ),
        500,
    )


# ============================================================================
# EJECUCIÓN
# ============================================================================

if __name__ == "__main__":
    logger.info("Iniciando aplicación Flask")
    app.run(debug=True)
