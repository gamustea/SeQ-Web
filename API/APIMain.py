import os
import base64
import time

from src.persistence import UserDBManager, ScanDBManager
from src.scanning.managers import NmapScanManager, NiktoScanManager
from src.misc.documents import PDFCreator, NmapPrintingStrategy, NiktoPrintingStrategy
from src.misc.logging import SecOpsLogger
from src.model import Scan

from flask import send_file, request, jsonify, Flask
from flask_cors import CORS  # ← AÑADE ESTO

import ipaddress
import itertools

# ... tus otros imports ...

app = Flask(__name__)
CORS(app)  # ← AÑADE ESTO (habilita CORS para todos los endpoints)

# Inicialización
USER = UserDBManager().get_user_by_id(1)
NMAP_MANAGER = NmapScanManager(USER)
NIKTO_MANAGER = NiktoScanManager(USER)
PDF_CREATOR = None

# Configurar logger
logger_instance = SecOpsLogger(name="APIMain")
logger = logger_instance.get_logger()


def validar_puertos_nmap(puertos_str):
    """
    Valida que una cadena de puertos sea válida para Nmap y devuelve la lista expandida.

    Reglas de validación:
    - Puertos en rango 1-65535
    - Puertos y rangos en orden ascendente
    - Rangos válidos (inicio < fin)
    - No solapamiento de rangos
    - Formato: "80", "80,443", "1-1000", "80,443-8080,9000"

    Args:
        puertos_str (str): String con especificación de puertos

    Returns:
        tuple: (bool, list, str) - (es_válido, lista_puertos, mensaje)
    """

    if not puertos_str or not isinstance(puertos_str, str):
        return False, [], "El parámetro debe ser una cadena no vacía"

    puertos_str = puertos_str.strip()

    if not puertos_str:
        return False, [], "La cadena de puertos está vacía"

    segmentos = puertos_str.split(",")
    ultimo_puerto = 0
    lista_puertos = []  # Lista expandida de todos los puertos

    for i, segmento in enumerate(segmentos):
        segmento = segmento.strip()

        if not segmento:
            return False, [], f"Segmento vacío encontrado en la posición {i+1}"

        if "-" in segmento:
            partes = segmento.split("-")

            # Rango desde 1: "-1000"
            if segmento.startswith("-"):
                if len(partes) != 2 or partes[0] != "":
                    return False, [], f"Formato de rango incorrecto: '{segmento}'"

                try:
                    fin = int(partes[1])
                except ValueError:
                    return False, [], f"Puerto de fin no válido en rango: '{segmento}'"

                if fin < 1 or fin > 65535:
                    return False, [], f"Puerto de fin fuera de rango (1-65535): {fin}"

                inicio = 1

            # Rango hasta 65535: "1000-"
            elif segmento.endswith("-"):
                if len(partes) != 2 or partes[1] != "":
                    return False, [], f"Formato de rango incorrecto: '{segmento}'"

                try:
                    inicio = int(partes[0])
                except ValueError:
                    return (
                        False,
                        [],
                        f"Puerto de inicio no válido en rango: '{segmento}'",
                    )

                if inicio < 1 or inicio > 65535:
                    return (
                        False,
                        [],
                        f"Puerto de inicio fuera de rango (1-65535): {inicio}",
                    )

                fin = 65535

            # Rango normal: "80-443"
            else:
                if len(partes) != 2:
                    return (
                        False,
                        [],
                        f"Formato de rango incorrecto (demasiados guiones): '{segmento}'",
                    )

                try:
                    inicio = int(partes[0])
                    fin = int(partes[1])
                except ValueError:
                    return False, [], f"Puertos no numéricos en rango: '{segmento}'"

                if inicio < 1 or inicio > 65535:
                    return (
                        False,
                        [],
                        f"Puerto de inicio fuera de rango (1-65535): {inicio}",
                    )

                if fin < 1 or fin > 65535:
                    return False, [], f"Puerto de fin fuera de rango (1-65535): {fin}"

                if inicio >= fin:
                    return (
                        False,
                        [],
                        f"Rango inválido: el inicio ({inicio}) debe ser menor que el fin ({fin})",
                    )

            if inicio <= ultimo_puerto:
                return (
                    False,
                    [],
                    f"Los puertos no están en orden ascendente: {inicio} aparece después de {ultimo_puerto}",
                )

            # Expandir el rango y añadir a la lista
            lista_puertos.extend(range(inicio, fin + 1))
            ultimo_puerto = fin

        else:
            # Puerto individual
            try:
                puerto = int(segmento)
            except ValueError:
                return False, [], f"Puerto no numérico: '{segmento}'"

            if puerto < 1 or puerto > 65535:
                return False, [], f"Puerto fuera de rango (1-65535): {puerto}"

            if puerto <= ultimo_puerto:
                return (
                    False,
                    [],
                    f"Los puertos no están en orden ascendente: {puerto} aparece después de {ultimo_puerto}",
                )

            # Añadir puerto individual a la lista
            lista_puertos.append(puerto)
            ultimo_puerto = puerto

    return (
        True,
        lista_puertos,
        f"Especificación válida con {len(lista_puertos)} puertos",
    )


def validar_ips_nmap(ips_str):
    """
    Valida que una cadena de IPs sea válida para Nmap y devuelve la lista expandida.

    Formatos soportados:
    - IP individual: "192.168.1.1"
    - CIDR: "192.168.1.0/24"
    - Rangos por octeto: "192.168.1.1-10" o "192.168.1-2.1-10"
    - Lista separada por comas: "192.168.1.1,192.168.1.5"
    - Wildcards: "192.168.1.*" (equivalente a 192.168.1.0-255)

    Args:
        ips_str (str): String con especificación de IPs

    Returns:
        tuple: (bool, list, str) - (es_válido, lista_ips, mensaje)
    """

    if not ips_str or not isinstance(ips_str, str):
        return False, [], "El parámetro debe ser una cadena no vacía"

    ips_str = ips_str.strip()

    if not ips_str:
        return False, [], "La cadena de IPs está vacía"

    # Dividir por comas para procesar múltiples targets
    segmentos = [s.strip() for s in ips_str.split(",")]

    lista_ips = []

    for segmento in segmentos:
        if not segmento:
            return False, [], "Segmento vacío encontrado"

        # Caso 1: Notación CIDR (192.168.1.0/24)
        if "/" in segmento:
            try:
                red = ipaddress.ip_network(segmento, strict=False)
                # Expandir la red a todas las IPs
                lista_ips.extend([str(ip) for ip in red.hosts()])
                # Si es /32 o /31, hosts() puede estar vacío, incluir la IP de red
                if not lista_ips or red.prefixlen >= 31:
                    lista_ips.extend([str(ip) for ip in red])
            except ValueError as e:
                return False, [], f"Notación CIDR inválida '{segmento}': {str(e)}"

        # Caso 2: Rangos por octeto o wildcards (192.168.1.1-10 o 192.168.1.*)
        elif "-" in segmento or "*" in segmento:
            try:
                ips_expandidas = expandir_rango_octetos(segmento)
                if ips_expandidas is None:
                    return False, [], f"Formato de rango inválido: '{segmento}'"
                lista_ips.extend(ips_expandidas)
            except Exception as e:
                return False, [], f"Error al procesar rango '{segmento}': {str(e)}"

        # Caso 3: IP individual (192.168.1.1)
        else:
            try:
                ip = ipaddress.ip_address(segmento)
                lista_ips.append(str(ip))
            except ValueError:
                return False, [], f"Dirección IP inválida: '{segmento}'"

    if not lista_ips:
        return False, [], "No se generaron IPs válidas"

    # Eliminar duplicados manteniendo el orden
    lista_ips_unicas = list(dict.fromkeys(lista_ips))

    return (
        True,
        lista_ips_unicas,
        f"Especificación válida con {len(lista_ips_unicas)} IPs",
    )


def expandir_rango_octetos(rango_str):
    """
    Expande un rango de octetos al estilo Nmap.
    Ejemplos:
    - "192.168.1.1-10" -> ["192.168.1.1", "192.168.1.2", ..., "192.168.1.10"]
    - "192.168.1-2.1-5" -> ["192.168.1.1", "192.168.1.2", ..., "192.168.2.5"]
    - "192.168.1.*" -> ["192.168.1.0", "192.168.1.1", ..., "192.168.1.255"]
    """

    # Reemplazar wildcards por rangos completos
    rango_str = rango_str.replace("*", "0-255")

    # Dividir por puntos
    octetos = rango_str.split(".")

    if len(octetos) != 4:
        return None

    # Procesar cada octeto
    rangos_octetos = []

    for octeto in octetos:
        if "-" in octeto:
            # Es un rango: "1-10"
            partes = octeto.split("-")
            if len(partes) != 2:
                return None

            try:
                inicio = int(partes[0])
                fin = int(partes[1])
            except ValueError:
                return None

            # Validar rango de octeto (0-255)
            if inicio < 0 or inicio > 255 or fin < 0 or fin > 255:
                return None

            if inicio > fin:
                return None

            rangos_octetos.append(range(inicio, fin + 1))
        else:
            # Es un número fijo
            try:
                valor = int(octeto)
            except ValueError:
                return None

            if valor < 0 or valor > 255:
                return None

            rangos_octetos.append([valor])

    # Generar todas las combinaciones
    lista_ips = []
    for combinacion in itertools.product(*rangos_octetos):
        ip_str = ".".join(map(str, combinacion))
        # Validar que sea una IP válida
        try:
            ipaddress.ip_address(ip_str)
            lista_ips.append(ip_str)
        except ValueError:
            continue

    return lista_ips if lista_ips else None


def build_pdf_creator(scan: Scan) -> PDFCreator:
    # Generar el PDF según el tipo de escaneo
    if scan.scan_type == "nmap":  # type: ignore
        strategy = NmapPrintingStrategy(scan=scan)
    elif scan.scan_type == "nikto":  # type: ignore
        strategy = NiktoPrintingStrategy(scan=scan)
    else:
        logger.error(f"Tipo de escaneo no soportado: {scan.scan_type}")
        return jsonify({"error": f"Tipo de escaneo no soportado: {scan.scan_type}"}), 400  # type: ignore

    return PDFCreator(strategy)


# ============================================================================
# ENDPOINTS GENERALES
# ============================================================================


@app.route("/say-hello", methods=["GET"])
def hello():
    """Endpoint de prueba para verificar que la API está funcionando."""
    logger.info("Endpoint /api/say-hello invocado")
    return (
        jsonify({"message": "You did it! You reached an endpoint!", "status": "ok"}),
        200,
    )


@app.route("/is-finished", methods=["GET"])
def is_scan_finished():
    try:
        scan_id = int(request.args.get("id"))  # type: ignore
        if not scan_id:
            return (
                jsonify({"message": f"No existe o no tienes acceso al id {scan_id}"}),
                401,
            )

        # Intentar obtener el scan de Nmap
        scan = NMAP_MANAGER.get_scan_by_id(scan_id)
        manager = NMAP_MANAGER  # Usar el manager correcto
        
        # Si no existe en Nmap, buscar en Nikto
        if not scan:
            scan = NIKTO_MANAGER.get_scan_by_id(scan_id)
            manager = NIKTO_MANAGER  # ← CRUCIAL: Cambiar al manager correcto
            
            if not scan:
                return jsonify({
                    "message": f"El escaneo con id {scan_id} no existe"
                }), 404

        # USAR EL MANAGER CORRECTO
        scan_finished = manager.scan_is_finished(scan)
        
        message = (
            f"El escaneo con id {scan_id} está terminado"
            if scan_finished
            else f"El escaneo con id {scan_id} no está terminado"
        )

        return jsonify({"message": message, "existe": scan_finished})
        
    except Exception as e:
        logger.error(f"Error en is-finished: {e}", exc_info=True)
        return jsonify({"message": "Ha ocurrido un error interno del servidor"}), 500

# ============================================================================
# ENDPOINTS DE ESCANEO
# ============================================================================


@app.route("/scans/nmap/start", methods=["POST"])
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
        host = request.headers.get("X-Target-Host")
        ports = request.headers.get("X-Target-Ports")

        # Validar parámetros requeridos
        if not host or not ports:
            logger.warning(
                "Faltan parámetros requeridos en la solicitud de escaneo Nmap"
            )
            return (
                jsonify(
                    {
                        "error": "Faltan cabeceras requeridas",
                        "required_headers": ["X-Target-Host", "X-Target-Ports"],
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

        valido, hosts, mensaje = validar_ips_nmap(host)

        if not valido:
            return (
                jsonify({"error": "Error ingresando cabeceras", "message": mensaje}),
                400,
            )

        valido, puertos, mensaje = validar_puertos_nmap(ports)

        if not valido:
            return (
                jsonify({"error": "Error ingresando cabeceras", "message": mensaje}),
                400,
            )

        # Ejecutar el escaneo
        ids = []
        for target_host in hosts:
            scan_id = NMAP_MANAGER.run_task(target_host, ports)
            logger.info(
                f"Escaneo Nmap iniciado correctamente con ID: {scan_id}, host: {target_host}, ports: {ports}"
            )
            ids.append(scan_id)
            time.sleep(0.5)

        return (
            jsonify(
                {
                    "message": "Escaneo Nmap iniciado correctamente",
                    "scanId": ids,
                    "target": {"host": host, "ports": ports},
                }
            ),
            201,
        )

    except Exception as e:
        logger.error(f"Error al iniciar el escaneo Nmap: {str(e)}", exc_info=True)
        return jsonify({"error": "Error al iniciar el escaneo", "details": str(e)}), 500


@app.route("/scans/nikto/start", methods=["POST"])
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
        target = request.headers.get("X-Target")
        timeout = request.args.get("timeout", 180)

        # Validar target requerido
        if not target:
            logger.warning("Falta la cabecera 'target' para iniciar escaneo Nikto")
            return jsonify({"error": "Falta la cabecera requerida 'X-target'"}), 400

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


@app.route("/scans/generate-pdf", methods=["GET"])
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


@app.route("/scans/generate-pdf-base64", methods=["GET"])
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

        PDF_CREATOR = build_pdf_creator(scan)
        pdf_path = PDF_CREATOR.print_pdf()

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


@app.route("/scans/results", methods=["GET"])
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
                jsonify(
                    {
                        "error": "Tipo de escaneo inválido",
                        "message": "Los tipos válidos son: 'nmap', 'nikto' o 'all'",
                    }
                ),
                400,
            )

        all_results = []

        # Obtener escaneos Nmap si aplica
        if scan_type in ["nmap", "all"]:
            nmap_results = NMAP_MANAGER.get_scans_for_user()
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
                            "reason": open_port.reason,
                        }
                        for open_port in result.open_ports_relation
                    ],
                    "totalOpenPorts": len(result.open_ports_relation),
                }
                for result in nmap_results
            ]
            all_results.extend(formatted_nmap)
            logger.info(f"Se obtuvieron {len(formatted_nmap)} escaneos Nmap")

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
        return (
            jsonify({"error": "Error al obtener los escaneos", "details": str(e)}),
            500,
        )


@app.route("/scans/results/<int:scan_id>", methods=["GET"])
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
            logger.warning(f"Escaneo con ID {scan_id} no encontrado en Nmap ni Nikto")
            return (
                jsonify({"error": f"No se encontró el escaneo con ID: {scan_id}"}),
                404,
            )

        # Verificar si el modelo tiene atributo scan_type y usarlo
        if hasattr(result, "scan_type"):
            scan_type = result.scan_type.lower()

        logger.info(f"Escaneo identificado como tipo: {scan_type}")

        # Formatear resultado según el tipo de escaneo
        if scan_type == "nmap":
            formatted_result = {
                "id": result.id,
                "scanType": "nmap",
                "target": result.target,
                "targetedPorts": [
                    f"{port}/{port.protocol}" for port in result.target_ports
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
    # Inicialización
    try:
        user_db = UserDBManager()
        USER = user_db.get_user_by_id(1)
        if USER:
            # Obtener el ID inmediatamente para evitar lazy loading posterior
            user_id = USER.id
            logger.info(f"Usuario cargado: ID {user_id}")
        else:
            logger.error("No se pudo cargar el usuario con ID 1")
            USER = None
        user_db.close_session()
    except Exception as e:
        logger.error(f"Error al inicializar usuario: {e}")
        USER = None

    if USER:
        NMAP_MANAGER = NmapScanManager(USER)
        NIKTO_MANAGER = NiktoScanManager(USER)
    else:
        logger.critical("No se pudieron inicializar los managers sin usuario válido")
    logger.info("Iniciando aplicación Flask")
    app.run(debug=True)
