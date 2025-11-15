import os
import base64

from src.persistence.dbmanaging import UserDBManager
from src.scanning.scanmanaging import NmapScanManager, NiktoScanManager
from src.documents import PDFCreator

from flask import send_file, request, jsonify, Flask


# Inicialización
USER = UserDBManager().get_user_by_id(1)
NMAP_MANAGER = NmapScanManager(USER)
NIKTO_MANAGER = NiktoScanManager(USER)
PDF_CREATOR = PDFCreator()

app = Flask(__name__)


# ============================================================================
# ENDPOINTS GENERALES
# ============================================================================

@app.route("/api/say-hello", methods=["GET"])
def hello():
    """Endpoint de prueba para verificar que la API está funcionando."""
    return jsonify({
        "message": "You did it! You reached an endpoint!",
        "status": "ok"
    }), 200


# ============================================================================
# ENDPOINTS DE ESCANEO NMAP
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
        # Obtener parámetros de los headers
        host = request.headers.get("host")
        ports = request.headers.get("ports")
        
        # Validar parámetros requeridos
        if not host or not ports:
            return jsonify({
                "error": "Faltan cabeceras requeridas",
                "required_headers": ["host", "ports"]
            }), 400
        
        # Validar formato básico del host
        if not host.strip():
            return jsonify({
                "error": "El host no puede estar vacío"
            }), 400
        
        # Validar formato básico de puertos
        if not ports.strip():
            return jsonify({
                "error": "Los puertos no pueden estar vacíos"
            }), 400
        
        # Ejecutar el escaneo
        scan_id = NMAP_MANAGER.run_task(host, ports)
        
        return jsonify({
            "message": "Escaneo Nmap iniciado correctamente",
            "scanId": scan_id,
            "target": {
                "host": host,
                "ports": ports
            }
        }), 201
        
    except Exception as e:
        return jsonify({
            "error": "Error al iniciar el escaneo",
            "details": str(e)
        }), 500


@app.route("/api/scans/nmap/results", methods=["GET"])
def retrieve_nmap_scans():
    """
    Obtiene todos los escaneos Nmap del usuario.
    
    Returns:
        JSON con la lista de escaneos y sus resultados
    """
    try:
        results = NMAP_MANAGER.get_scans_for_user()
        
        # Formatear resultados de manera consistente
        formatted_results = [
            {
                "id": result.id,
                "target": result.target,
                "targetedPorts": [port.protocol for port in result.target_ports],
                "startedAt": result.started_at.isoformat() if hasattr(result.started_at, 'isoformat') else str(result.started_at),
                "openPorts": [
                    {
                        "port": port.port.protocol,
                        "reason": port.reason  # Corrección del typo "reaseon"
                    }
                    for port in result.open_ports_relation
                ],
                "totalOpenPorts": len(result.open_ports_relation)
            }
            for result in results
        ]
        
        return jsonify({
            "message": "Escaneos obtenidos correctamente",
            "count": len(formatted_results),
            "results": formatted_results
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": "Error al obtener los escaneos",
            "details": str(e)
        }), 500


@app.route("/api/scans/nmap/results/<int:scan_id>", methods=["GET"])
def retrieve_nmap_scan_by_id(scan_id):
    """
    Obtiene un escaneo Nmap específico por ID.
    
    Args:
        scan_id: ID del escaneo
    
    Returns:
        JSON con los detalles del escaneo
    """
    try:
        result = NMAP_MANAGER.get_scan_by_id(scan_id)
        
        if not result:
            return jsonify({
                "error": f"No se encontró el escaneo con ID: {scan_id}"
            }), 404
        
        # Formatear resultado
        formatted_result = {
            "id": result.id,
            "target": result.target,
            "targetedPorts": [port.protocol for port in result.target_ports],
            "startedAt": result.started_at.isoformat() if hasattr(result.started_at, 'isoformat') else str(result.started_at),
            "openPorts": [
                {
                    "port": port.port.protocol,
                    "reason": port.reason
                }
                for port in result.open_ports_relation
            ],
            "totalOpenPorts": len(result.open_ports_relation)
        }
        
        return jsonify({
            "message": "Escaneo obtenido correctamente",
            "result": formatted_result
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": "Error al obtener el escaneo",
            "details": str(e)
        }), 500


@app.route("/api/scans/nmap/generate-pdf", methods=["GET"])
def generate_nmap_pdf():
    """
    Genera y descarga un PDF de un escaneo Nmap.
    
    Query Parameters:
        - id: ID del escaneo
    
    Returns:
        Archivo PDF para descarga directa
    """
    try:
        # Obtener el ID del query parameter
        scan_id = request.args.get("id")
        
        # Validar que se proporcione el ID
        if not scan_id:
            return jsonify({
                "error": "El parámetro 'id' es requerido"
            }), 400
        
        # Validar formato del ID
        try:
            scan_id_int = int(scan_id)
        except ValueError:
            return jsonify({
                "error": "El ID debe ser un número entero válido"
            }), 400
        
        # Obtener el escaneo por ID
        scan = NMAP_MANAGER.get_scan_by_id(scan_id_int)
        
        # Validar que el escaneo existe
        if not scan:
            return jsonify({
                "error": f"No se encontró el escaneo con ID: {scan_id}"
            }), 404
        
        # Generar el PDF
        pdf_path = PDF_CREATOR.print_nmap_pdf(scan=scan)
        
        # Validar que el archivo se creó correctamente
        if not pdf_path or not os.path.exists(pdf_path):
            return jsonify({
                "error": "Error al generar el archivo PDF"
            }), 500
        
        # Enviar el archivo PDF como respuesta
        return send_file(
            pdf_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"nmap_scan_{scan_id}.pdf"
        )
        
    except Exception as e:
        return jsonify({
            "error": "Error interno del servidor",
            "details": str(e)
        }), 500


@app.route("/api/scans/nmap/generate-pdf-base64", methods=["GET"])
def generate_nmap_pdf_base64():
    """
    Genera un PDF de un escaneo Nmap y lo devuelve en base64.
    Útil para mostrarlo directamente en el navegador.
    
    Query Parameters:
        - id: ID del escaneo
    
    Returns:
        JSON con el PDF en base64 y metadata
    """
    try:
        # Obtener el ID del query parameter
        scan_id = request.args.get("id")
        
        if not scan_id:
            return jsonify({
                "error": "El parámetro 'id' es requerido"
            }), 400
        
        # Validar formato del ID
        try:
            scan_id_int = int(scan_id)
        except ValueError:
            return jsonify({
                "error": "El ID debe ser un número entero válido"
            }), 400
        
        # Obtener el escaneo por ID
        scan = NMAP_MANAGER.get_scan_by_id(scan_id_int)
        
        if not scan:
            return jsonify({
                "error": f"No se encontró el escaneo con ID: {scan_id}"
            }), 404
        
        # Generar el PDF
        pdf_path = PDF_CREATOR.print_nmap_pdf(scan=scan)
        
        if not pdf_path or not os.path.exists(pdf_path):
            return jsonify({
                "error": "Error al generar el archivo PDF"
            }), 500
        
        # Leer el archivo y convertirlo a base64
        with open(pdf_path, "rb") as pdf_file:
            pdf_base64 = base64.b64encode(pdf_file.read()).decode("utf-8")
        
        return jsonify({
            "message": "PDF generado exitosamente",
            "scanId": scan_id,
            "filename": f"nmap_scan_{scan_id}.pdf",
            "pdfBase64": pdf_base64,
            "contentType": "application/pdf"
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": "Error interno del servidor",
            "details": str(e)
        }), 500


# ============================================================================
# ENDPOINTS DE ESCANEO NIKTO
# ============================================================================

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
        # Obtener parámetros
        target = request.headers.get("target")
        timeout = request.args.get("timeout", 180)
        
        # Validar target requerido
        if not target:
            return jsonify({
                "error": "Falta la cabecera requerida 'target'"
            }), 400
        
        # Validar que el target no esté vacío
        if not target.strip():
            return jsonify({
                "error": "El target no puede estar vacío"
            }), 400
        
        # Validar timeout
        try:
            timeout = int(timeout)
            if timeout <= 0:
                return jsonify({
                    "error": "El timeout debe ser un número positivo"
                }), 400
        except ValueError:
            return jsonify({
                "error": "El timeout debe ser un número entero válido"
            }), 400
        
        # Ejecutar el escaneo
        scan_id = NIKTO_MANAGER.run_task(target, timeout=timeout)
        
        return jsonify({
            "message": "Escaneo Nikto iniciado correctamente",
            "scanId": scan_id,
            "target": target,
            "timeout": timeout
        }), 201
        
    except Exception as e:
        return jsonify({
            "error": "Error al iniciar el escaneo",
            "details": str(e)
        }), 500


@app.route("/api/scans/nikto/results", methods=["GET"])
def retrieve_nikto_scans():
    """
    Obtiene todos los escaneos Nikto del usuario.
    
    Returns:
        JSON con la lista de escaneos y sus incidencias
    """
    try:
        results = NIKTO_MANAGER.get_scans_for_user()
        
        # Formatear resultados de manera consistente
        formatted_results = [
            {
                "id": result.id,
                "target": result.target,
                "startedAt": result.started_at.isoformat() if hasattr(result.started_at, 'isoformat') else str(result.started_at),
                "incidents": [
                    {
                        "osvdbId": incident.osvdb_id,
                        "method": incident.method,
                        "url": incident.url,
                        "description": incident.description,
                        "discoveredAt": incident.discovered_at.isoformat() if hasattr(incident.discovered_at, 'isoformat') else str(incident.discovered_at)
                    }
                    for incident in result.incidents
                ],
                "totalIncidents": len(result.incidents)
            }
            for result in results
        ]
        
        return jsonify({
            "message": "Escaneos obtenidos correctamente",
            "count": len(formatted_results),
            "results": formatted_results
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": "Error al obtener los escaneos",
            "details": str(e)
        }), 500


@app.route("/api/scans/nikto/results/<int:scan_id>", methods=["GET"])
def retrieve_nikto_scan_by_id(scan_id):
    """
    Obtiene un escaneo Nikto específico por ID.
    
    Args:
        scan_id: ID del escaneo
    
    Returns:
        JSON con los detalles del escaneo
    """
    try:
        result = NIKTO_MANAGER.get_scan_by_id(scan_id)
        
        if not result:
            return jsonify({
                "error": f"No se encontró el escaneo con ID: {scan_id}"
            }), 404
        
        # Formatear resultado
        formatted_result = {
            "id": result.id,
            "target": result.target,
            "startedAt": result.started_at.isoformat() if hasattr(result.started_at, 'isoformat') else str(result.started_at),
            "incidents": [
                {
                    "osvdbId": incident.osvdb_id,
                    "method": incident.method,
                    "url": incident.url,
                    "description": incident.description,
                    "discoveredAt": incident.discovered_at.isoformat() if hasattr(incident.discovered_at, 'isoformat') else str(incident.discovered_at)
                }
                for incident in result.incidents
            ],
            "totalIncidents": len(result.incidents)
        }
        
        return jsonify({
            "message": "Escaneo obtenido correctamente",
            "result": formatted_result
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": "Error al obtener el escaneo",
            "details": str(e)
        }), 500


# ============================================================================
# MANEJO DE ERRORES GLOBALES
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Manejo de rutas no encontradas."""
    return jsonify({
        "error": "Endpoint no encontrado",
        "message": "La ruta solicitada no existe"
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Manejo de métodos HTTP no permitidos."""
    return jsonify({
        "error": "Método no permitido",
        "message": "El método HTTP utilizado no está permitido para este endpoint"
    }), 405


@app.errorhandler(500)
def internal_error(error):
    """Manejo de errores internos del servidor."""
    return jsonify({
        "error": "Error interno del servidor",
        "message": "Ha ocurrido un error inesperado"
    }), 500


# ============================================================================
# EJECUCIÓN
# ============================================================================

if __name__ == "__main__":
    app.run(debug=True)