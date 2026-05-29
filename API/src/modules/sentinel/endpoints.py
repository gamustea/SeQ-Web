"""
sentinel_endpoints.py
══════════════════════════════════════════════════════════════════════════════

Blueprint de la API REST para el módulo Sentinel (escaneos de seguridad).

Este módulo proporciona endpoints para lanzar, monitorizar y gestionar escaneos
de seguridad utilizando tres motores de escaneo:

    • Nmap      — Escaneo de puertos y detección de servicios
    • Nikto     — Escaneo de vulnerabilidades web
    • OpenVAS   — Escaneo completo de vulnerabilidades (GMP)f

────────────────────────────────────────────────────────────────────────────────
ENDPOINTS DISPONIBLES
────────────────────────────────────────────────────────────────────────────────

Estado y Control
    GET  /sentinel/is-finished?id=<scan_id>     — ¿Ha finalizado un escaneo?
    GET  /sentinel/scan-status?id=<scan_id>     — Estado y progreso del escaneo
    POST /sentinel/scans/<scan_id>/cancel       — Cancelar escaneo en curso

Lanzamiento
    POST /sentinel/nmap    — Lanzar escaneo Nmap (soporta rangos CIDR/múltiples IPs)
    POST /sentinel/nikto   — Lanzar escaneo Nikto
    POST /sentinel/openvas — Lanzar escaneo OpenVAS (un solo host)

Resultados
    GET /sentinel/results              — Listar todos los escaneos del usuario
    GET /sentinel/results/<scan_id>    — Obtener detalle de un escaneo

PDF y Documentos
    GET /sentinel/generate-pdf?id=<scan_id>         — Solicitar generación async de PDF
    GET /sentinel/document-status                   — Consultar estado de generación
    GET /sentinel/document/<id>/download            — Descargar documento generado
    GET /sentinel/generate-pdf-base64               — (Legacy) Obtener PDF en Base64

Eliminación
    DELETE /sentinel/<scan_id> — Eliminar un escaneo

Escaneos Programados
    POST   /sentinel/scheduled-scans                — Crear un escaneo programado
    GET    /sentinel/scheduled-scans                — Listar escaneos programados del usuario
    DELETE /sentinel/scheduled-scans/<ps_id>        — Revocar un escaneo programado

────────────────────────────────────────────────────────────────────────────────
AUTENTICACIÓN
────────────────────────────────────────────────────────────────────────────────

Todos los endpoints requieren un token OAuth2 válido en el header:
    Authorization: Bearer <access_token>

Los límites de tasa (rate limiting) están configurados por endpoint:
    • is-finished, scan-status, results, document-status: 300/hour, 2000/day
    • nmap, nikto: 20/hour, 100/day
    • openvas: 10/hour, 50/day
    • generate-pdf: 30/hour, 100/day
    • cancel, delete: 60/hour, 200/day

────────────────────────────────────────────────────────────────────────────────
EJEMPLOS DE USO
────────────────────────────────────────────────────────────────────────────────

# Lanzar escaneo Nmap
curl -X POST https://api.example.com/sentinel/nmap \
    -H "Authorization: Bearer <token>" \
    -H "Content-Type: application/json" \
    -d '{"target": "192.168.1.0/24", "ports": "22,80,443", "timeout": 300}'

# Listar escaneos con paginación
curl "https://api.example.com/sentinel/results?type=nmap&page=1&per_page=20" \
    -H "Authorization: Bearer <token>"

# Obtener estado de un escaneo
curl "https://api.example.com/sentinel/scan-status?id=42" \
    -H "Authorization: Bearer <token>"

────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import os
import ipaddress

from flask import Blueprint, jsonify, request, send_file

from src.modules.users import require_oauth_token, require_attributes, AttributeType, get_current_user
from src.modules.shared import (
    handle_exceptions,
    require_json,
    require_arg,
    limiter
)
from src.modules.shared._exceptions import (
    MissingParameterError,
    ValidationError,
    IllegalStateError
)
from src.modules.aegis.exceptions import DocumentError
from src.modules.system import SecOpsLogger

from .managers import (
    ScanManager,
    NmapScanManager,
    NiktoScanManager,
    OpenVASScanManager,
    ProgramedScanManager,
    SentinelReportManager,
)
from .model import ScanType
from .exceptions import (
    ScanExecutionError,
    ScanNotFoundError,
    IPValidationError,
    MaxHostsExceededError,
    PortValidationError,
    PrivateIPRequested,
    ProgramedScanError,
    ProgramedScanNotFoundError,
    InvalidProgramedTaskArgumentError,
)


# =========================================================================
# CONSTANTS
# =========================================================================

sentinel_bp = Blueprint("sentinel", __name__)
_logger     = SecOpsLogger("sentinel").get_logger()

CANCELLABLE_STATES      = frozenset({"pending", "running"})
VALID_SCAN_TYPES        = frozenset({"nmap", "nikto", "openvas", "all"})
VALID_OPENVAS_CONFIGS   = frozenset({"full_fast", "full_deep", "full_ultimate"})
MAX_PDF_SIZE_BYTES      = 50 * 1024 * 1024

# =========================================================================
# SCAN ENDPOINTS
# =========================================================================

@sentinel_bp.get("/scan-status")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def get_scan_status():
    """Estado y progreso de un escaneo."""
    scan_id = int(require_arg("id"))
    user = get_current_user()
    manager = ScanManager.resolve_manager(scan_id)
    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)
    ScanManager.assert_scan_ownership(scan_id, user.id) # type: ignore

    status      = manager.get_scan_status(scan_id)
    progress    = manager.get_scan_progress(scan_id)
    result      = manager.format_scan(scan_id)

    response = {
        "message":  f"Estado del escaneo {scan_id}: {status}",
        "scanId":   scan_id,
        "status":   status,
        "scanType": scan.scan_type,
    }
    if progress is not None:
        response["progress"] = progress
    response["scan"] = result

    return jsonify(response), 200


@sentinel_bp.post("/scans/<int:scan_id>/cancel")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_UPDATE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def cancel_scan(scan_id: int):
    """Cancela un escaneo en curso."""
    user = get_current_user()

    manager = ScanManager.resolve_manager(scan_id)
    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)
    ScanManager.assert_scan_ownership(scan_id, user.id) # type: ignore

    if scan.status not in CANCELLABLE_STATES:
        return jsonify({
            "error": "invalid_state",
            "error_description": f"El escaneo no se puede cancelar en estado: {scan.status}",
            "scanId": scan_id,
            "currentStatus": scan.status,
            "cancellableStates": sorted(CANCELLABLE_STATES),
        }), 400

    if not manager.cancel_scan(scan_id, user.id): # type: ignore
        return jsonify(
            {
                "error": "cancellation_failed",
                "error_description": "No se pudo cancelar",
                "scanId": scan_id
            }
        ), 500

    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)

    _logger.info(f"Escaneo {scan.scan_type} {scan_id} cancelado por {user.username}")
    return jsonify(
        {
            "message": "Escaneo cancelado exitosamente",
            "scanId": scan_id,
            "scanType": scan.scan_type,
            "status": scan.status,
            "user": user.username
        }
    ), 200


@sentinel_bp.post("/nmap")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@limiter.limit("20 per hour; 100 per day")
@require_json(["target", "ports"])
@handle_exceptions(default_exception=ScanExecutionError, logger=_logger)
def start_nmap_scan(data: dict[str, str]):
    """Lanza uno o más escaneos Nmap."""

    host  = data["target"]
    ports = data["ports"]
    user = get_current_user()

    timeout = int(data.get("timeout", 300))
    if timeout <= 0:
        raise ValidationError(
            field="timeout",
            message="El timeout debe ser positivo",
            value=timeout
        )

    nmap_manager = NmapScanManager()
    try:
        hosts = ScanManager.validate_ip(host)
    except IPValidationError as exc:
        raise ValidationError(field="target", message=str(exc), value=host) from exc
    except MaxHostsExceededError as exc:
        return jsonify({
            "error": exc.__class__.__name__,
            "error_description": exc.user_message or str(exc),
            "details": exc.details or {}
        }), 400
    except PrivateIPRequested as exc:
        return jsonify({
            "error": exc.__class__.__name__,
            "error_description": exc.user_message or str(exc),
            "details": exc.details or {}
        }), 403

    try:
        ScanManager.validate_port(ports)
    except PortValidationError as exc:
        raise ValidationError(field="ports", message=str(exc), value=ports) from exc

    scan_ids = []
    for target_host in hosts:
        scan_id = nmap_manager.run_scan(
            target_host=target_host,
            target_ports=ports,
            user_id=user.id,
            timeout=timeout
        )
        scan_ids.append(scan_id)
        _logger.info(
            f"Nmap lanzado: ID={scan_id} host={target_host}\
            ports={ports} user={user.username}"
        )

    return jsonify({
        "message":    "Escaneo(s) Nmap iniciado(s) correctamente",
        "scanIds":    scan_ids,
        "target":     {"hosts": hosts, "ports": ports},
        "totalScans": len(scan_ids),
        "user":       user.username,
    }), 201


@sentinel_bp.post("/nikto")
@limiter.limit("20 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@require_json(["target"])
@handle_exceptions(default_exception=ScanExecutionError, logger=_logger)
def start_nikto_scan(data):
    """Lanza un escaneo Nikto."""
    target = data["target"]
    user = get_current_user()

    timeout = int(data.get("timeout", 900))
    if timeout <= 0:
        raise ValidationError(
            field="timeout",
            message="El timeout debe ser positivo",
            value=timeout
        )

    nikto_manager = NiktoScanManager()
    scan_id = nikto_manager.run_scan(
        target, # type: ignore
        user_id=user.id,
        timeout=timeout
    ) # type: ignore
    _logger.info(
        f"Nikto lanzado: ID={scan_id} target={target}\
        timeout={timeout} user={user.username}"
    )
    return jsonify(
        {
            "message": "Escaneo Nikto iniciado correctamente",
            "scanId": scan_id,
            "target": target,
            "timeout": timeout,
            "user": user.username
        }
    ), 201


@sentinel_bp.post("/openvas")
@limiter.limit("10 per hour; 50 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@require_json(["target"])
@handle_exceptions(default_exception=ScanExecutionError, logger=_logger)
def start_openvas_scan(data):
    """Lanza un escaneo OpenVAS para un único host."""
    target      = data["target"]
    scan_config = data.get("scanConfig", "full_fast")
    user        = get_current_user()
    if user is None:
        raise IllegalStateError("'user' detectado como None")

    if scan_config not in VALID_OPENVAS_CONFIGS:
        raise ValidationError(
            field="scanConfig",
            message="Configuración inválida",
            value=scan_config,
            expected=", ".join(sorted(VALID_OPENVAS_CONFIGS))
        )

    try:
        hosts = ScanManager.validate_ip(target, max_hosts=1)
    except IPValidationError as exc:
        raise ValidationError(field="target", message=str(exc), value=target) from exc
    except MaxHostsExceededError as exc:
        return jsonify({
            "error": exc.__class__.__name__,
            "error_description": exc.user_message or str(exc),
            "details": exc.details or {}
        }), 400
    except PrivateIPRequested as exc:
        return jsonify({
            "error": exc.__class__.__name__,
            "error_description": exc.user_message or str(exc),
            "details": exc.details or {}
        }), 403

    openvas_manager = OpenVASScanManager()
    target_ip = hosts[0]
    ipaddress.ip_address(target_ip)

    scan_id = openvas_manager.run_scan(
        target=target_ip,
        scan_config=scan_config,
        user_id=user.id,
        skip_normalize=True
    )
    _logger.info(f"OpenVAS lanzado: ID={scan_id} target={target_ip} config={scan_config} user={user.username}")

    return jsonify(
        {
            "message": "Escaneo OpenVAS iniciado correctamente",
            "scanId": scan_id,
            "target": target_ip,
            "scanConfig": scan_config,
            "user": user.username,
            "note": "Use /sentinel/scan-status para verificar el progreso."
        }
    ), 201


@sentinel_bp.get("/results")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def retrieve_all_scans():
    """Lista todos los escaneos del usuario."""
    scan_type = request.args.get("type", "all").lower()
    if scan_type not in VALID_SCAN_TYPES:
        raise ValidationError(
            field="type",
            message="Tipo de escaneo inválido",
            value=scan_type,
            expected="nmap, nikto, openvas o all"
        )

    user = get_current_user()
    uid = user.id

    nmap_mgr = NmapScanManager()
    nikto_mgr = NiktoScanManager()
    openvas_mgr = OpenVASScanManager()
    all_results = []

    if scan_type in ("nmap", "all"):
        try:
            for scan in nmap_mgr.get_scans_for_user(uid): # type: ignore
                all_results.append(nmap_mgr.format_scan(scan.id)) # type: ignore
        except (OSError, RuntimeError) as exc:
            _logger.error(f"Error obteniendo Nmap scans: {exc}")

    if scan_type in ("nikto", "all"):
        try:
            for scan in nikto_mgr.get_scans_for_user(uid): # type: ignore
                all_results.append(nikto_mgr.format_scan(scan.id)) # type: ignore
        except (OSError, RuntimeError) as exc:
            _logger.error(f"Error obteniendo Nikto scans: {exc}")

    if scan_type in ("openvas", "all"):
        try:
            for scan in openvas_mgr.get_scans_for_user(uid): # type: ignore
                all_results.append(openvas_mgr.format_scan(scan.id)) # type: ignore
        except (OSError, RuntimeError) as exc:
            _logger.error(f"Error obteniendo OpenVAS scans: {exc}")

    return jsonify({
        "message": "Escaneos obtenidos correctamente",
        "filter": scan_type,
        "count": len(all_results),
        "results": all_results,
        "user": user.username
    }), 200


@sentinel_bp.get("/results/<int:scan_id>")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def retrieve_scan_by_id(scan_id: int):
    """Devuelve el detalle completo de un escaneo específico."""
    user = get_current_user()

    manager = ScanManager.resolve_manager(scan_id)
    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)
    ScanManager.assert_scan_ownership(scan_id, user.id) # type: ignore

    _logger.info(f"Obteniendo detalles para escaneo {scan_id} de tipo {scan.scan_type} por usuario {user.username}")
    result = manager.format_scan(scan_id)
    if scan.scan_type == "nmap": # type: ignore
        result["openPorts"] = [{"port": f"{p.port_id}/{p.port.protocol}", "reason": p.reason, "product": p.product, "version": p.version} for p in scan.open_ports_relation]
    elif scan.scan_type == "openvas": # type: ignore
        result["severityBreakdown"] = {
            "critical": sum(1 for r in scan.results if r.vulnerability.severity_class == "Critical"),
            "high":     sum(1 for r in scan.results if r.vulnerability.severity_class == "High"),
            "medium":   sum(1 for r in scan.results if r.vulnerability.severity_class == "Medium"),
            "low":      sum(1 for r in scan.results if r.vulnerability.severity_class == "Low"),
            "info":     sum(1 for r in scan.results if r.vulnerability.severity_class == "Log"),
        }

    return jsonify(
        {
            "message": "Escaneo obtenido correctamente",
            "result": result,
            "user": user.username
        }
    ), 200


@sentinel_bp.get("/is-finished")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def is_scan_finished():
    """Indica si un escaneo ha finalizado.

    Args (query params):
        id (int): ID del escaneo a verificar.

    Returns:
        200 — JSON con el estado de finalización.
            {
                "message": "El escaneo 42 está terminado",
                "scanId": 42,
                "isFinished": true,
                "scanType": "nmap"
            }
        400 — Error de validación (parámetro 'id' faltante o inválido).
        404 — Escaneo no encontrado.
        401 — Token OAuth2 inválido o ausente.

    Example:
        curl "http://localhost:5000/sentinel/is-finished?id=42" \\
             -H "Authorization: Bearer <token>"
    """
    user = get_current_user()
    scan_id = int(require_arg("id"))
    manager = ScanManager.resolve_manager(scan_id)
    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)
    ScanManager.assert_scan_ownership(scan_id, user.id) # type: ignore

    finished = manager.is_scan_finished(scan.id) # type: ignore

    return jsonify({
        "message":    f"El escaneo {scan_id} {'está' if finished else 'no está'} terminado",
        "scanId":     scan_id,
        "isFinished": finished,
        "scanType":   scan.scan_type,
    }), 200


# =========================================================================
# DOCUMENT ENDPOINTS
# =========================================================================

@sentinel_bp.get("/generate-pdf")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def generate_pdf():
    """Solicita la generación asíncrona de un PDF."""
    scan_id = int(require_arg("id"))
    ai_report_str = request.args.get("aiReport", "false").lower()
    ai_report = ai_report_str == "true"

    user = get_current_user()
    uid = user.id

    manager = ScanManager.resolve_manager(scan_id)
    ScanManager.assert_scan_ownership(scan_id, uid) # type: ignore

    if not manager.is_scan_finished(scan_id):
        raise ValidationError(
            field="scan_id",
            message=f"El escaneo {scan_id} no está finalizado aún",
            value=scan_id
        )

    doc_mgr = SentinelReportManager()
    doc_id = doc_mgr.generate_report(
        scan_id=scan_id,
        ai_report=ai_report,
        strategy_class=manager._strategy_class # type: ignore
    )
    _logger.info(f"Generación de PDF solicitada para escaneo {scan_id} (documento {doc_id}) por usuario {user.username} con AI Report: {ai_report}")

    return jsonify({
        "message": "Generación de PDF iniciada",
        "documentId": doc_id,
        "scanId": scan_id,
        "status": "pending",
        "aiReport": ai_report,
        "downloadUrl": f"/sentinel/document/{doc_id}/download"
    }), 202


@sentinel_bp.delete("/<int:scan_id>")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def delete_scan(scan_id: int):
    """Elimina un escaneo del sistema.

    Si el escaneo está en curso (estado 'pending' o 'running'), se cancela
    automáticamente antes de eliminarlo.

    Args (path):
        scan_id (int): ID del escaneo a eliminar.

    Returns:
        200 — Escaneo eliminado correctamente.
            {
                "message": "Escaneo eliminado correctamente",
                "scanId": 42,
                "scanType": "nmap",
                "user": "admin"
            }
        404 — Escaneo no encontrado.
        500 — Error al intentar eliminar.

    Warning:
        Esta acción es irreversible. Se perderán todos los datos del escaneo.

    Example:
        curl -X DELETE "http://localhost:5000/sentinel/42" \\
             -H "Authorization: Bearer <token>"
    """
    user = get_current_user()

    manager = ScanManager.resolve_manager(scan_id)
    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)
    ScanManager.assert_scan_ownership(scan_id, user.id) # type: ignore

    if scan.status in CANCELLABLE_STATES:
        _logger.info(f"Cancelando escaneo {scan_id} antes de eliminar")
        manager.cancel_scan(scan_id, user.id) # type: ignore

    if not manager.delete_scan(scan_id):
        return jsonify(
            {
                "error": "deletion_failed",
                "error_description": "No se pudo eliminar el escaneo",
                "scanId": scan_id
            }
        ), 500

    _logger.info(f"Escaneo {scan.scan_type} {scan_id} eliminado por {user.username}")
    return jsonify(
        {
            "message": "Escaneo eliminado correctamente",
            "scanId": scan_id,
            "scanType": scan.scan_type,
            "user": user.username
        }
    ), 200


@sentinel_bp.get("/document-status")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def get_document_status():
    """Consulta el estado de generación de un documento."""
    user = get_current_user()

    document_id = request.args.get("document_id", type=int)
    scan_id = request.args.get("scan_id", type=int)

    doc_mgr = SentinelReportManager()

    if not document_id and not scan_id:
        raise MissingParameterError("document_id o scan_id")

    doc = doc_mgr.get_document_by_id(document_id) if document_id else (
        doc_mgr.get_latest_document_by_scan_id(scan_id) if scan_id else None
    )

    if not doc:
        raise ScanNotFoundError(document_id or scan_id)  # type: ignore

    doc_mgr.assert_document_ownership(document_id, user.id) if document_id else None # type: ignore

    download_url = None
    if doc.status == "done" and doc.filename:  # type: ignore
        download_url = f"/sentinel/document/{doc.id}/download"

    return jsonify({
        "documentId": doc.id,
        "scanId": doc.scan_id,
        "status": doc.status,
        "aiReport": doc.enrichment_json is not None,
        "createdAt": doc.created_at.isoformat() if doc.created_at else None,  # type: ignore
        "generatedAt": doc.generated_at.isoformat() if doc.generated_at else None,  # type: ignore
        "downloadUrl": download_url
    }), 200


@sentinel_bp.get("/documents")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=DocumentError, logger=_logger)
def get_all_documents():
    """Obtiene todos los documentos del usuario.

    Query params:
        scan_type (str): Filtrar por tipo de escaneo.\
        Valores válidos: nmap, nikto, openvas, all. Default: all.
    """
    user = get_current_user()
    scan_type_filter = request.args.get("scan_type", "all").lower()

    valid_types = ["nmap", "nikto", "openvas", "all"]
    if scan_type_filter not in valid_types:
        return jsonify(
            {
                "error": f"Tipo de escaneo inválido. Valores válidos: {', '.join(valid_types)}"
            }
        ), 400

    doc_mgr = SentinelReportManager()
    documents = doc_mgr.get_documents_for_user(user.id) # type: ignore

    if scan_type_filter != "all":
        documents = [d for d in documents if d.scan_type == scan_type_filter] # type: ignore

    docs_list = []
    for doc in documents:
        download_url = None
        if doc.status == "done" and doc.filename: # type: ignore
            download_url = f"/sentinel/document/{doc.id}/download"

        docs_list.append({
            "documentId": doc.id,
            "scanId": doc.scan_id,
            "scanType": doc.scan_type,
            "status": doc.status,
            "isAiGenerated": doc.is_ai_generated == 1 if doc.is_ai_generated is not None else False,
            "createdAt": doc.created_at.isoformat() if doc.created_at else None, # type: ignore
            "generatedAt": doc.generated_at.isoformat() if doc.generated_at else None, # type: ignore
            "downloadUrl": download_url
        })

    return jsonify({
        "documents": docs_list,
        "total": len(docs_list),
        "filter": scan_type_filter
    }), 200


@sentinel_bp.get("/scan/<int:scan_id>/documents")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=DocumentError, logger=_logger)
def get_documents_by_scan(scan_id: int):
    """Obtiene todos los documentos de un escaneo concreto.

    Args:
        scan_id(path): ID del escaneo.

    Returns:
        200 — Lista de documentos del escaneo.
        404 — Escaneo no encontrado.
    """
    user = get_current_user()

    doc_mgr = SentinelReportManager()
    scan_mgr = ScanManager.resolve_manager(scan_id)

    scan = scan_mgr.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"error": "not_found", "error_description": "Escaneo no encontrado"}), 404

    documents = doc_mgr.get_documents_by_scan_id(scan_id)

    docs_list = []
    for doc in documents:
        download_url = None
        if doc.status == "done" and doc.filename: # type: ignore
            download_url = f"/sentinel/document/{doc.id}/download"

        docs_list.append({
            "documentId": doc.id,
            "scanId": doc.scan_id,
            "scanType": doc.scan_type,
            "status": doc.status,
            "isAiGenerated": doc.is_ai_generated == 1 if doc.is_ai_generated is not None else False,
            "createdAt": doc.created_at.isoformat() if doc.created_at else None, # type: ignore
            "generatedAt": doc.generated_at.isoformat() if doc.generated_at else None, # type: ignore
            "downloadUrl": download_url
        })

    return jsonify({
        "scanId": scan_id,
        "documents": docs_list,
        "total": len(docs_list)
    }), 200


@sentinel_bp.get("/document/<int:document_id>/download")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@handle_exceptions(default_exception=DocumentError, logger=_logger)
def download_document(document_id: int):
    """Descarga un documento generado previamente.

    Args (path):
        document_id (int): ID del documento a descargar.

    Returns:
        200 — Archivo PDF como attachment.
        400 — El documento aún no está listo (status != 'done').
        404 — Documento no encontrado.

    Example:
        curl "http://localhost:5000/sentinel/document/123/download" \\
                -H "Authorization: Bearer <token>" \\
                -o reporte.pdf
    """
    user = get_current_user()

    uid = user.id
    _logger.info(f"Download request for document {document_id} by user {uid}")

    doc_mgr = SentinelReportManager()
    doc_mgr.assert_document_ownership(document_id, uid) # type: ignore

    doc = doc_mgr.get_document_by_id(document_id)
    if not doc:
        _logger.warning(f"Document {document_id} not found or access denied for user {uid}")
        return jsonify({"error": "not_found", "error_description": "Documento no encontrado o acceso denegado"}), 404

    if doc.status != "done" or not doc.filename or not os.path.exists(doc.filename): # type: ignore
        _logger.warning(f"Document {document_id} not ready: status={doc.status}, filename={doc.filename}")
        return jsonify({"error": "not_ready", "error_description": f"El documento {document_id} aún no está disponible para descarga"}), 400

    _logger.info(f"Serving document {document_id}: {doc.filename}")
    return send_file(
        doc.filename, # type: ignore
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{doc.scan_type}_scan_{doc.scan_id}.pdf"
    ) # type: ignore


@sentinel_bp.route("/document/<int:document_id>", methods=["DELETE"])
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_DELETE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=DocumentError, logger=_logger)
def delete_document(document_id: int):
    """Elimina un documento.

    Args (path):
        document_id (int): ID del documento a eliminar.

    Returns:
        200 — Documento eliminado correctamente.
        404 — Documento no encontrado.
        403 — Sin permisos.
    """
    user = get_current_user()
    uid = user.id

    doc_mgr = SentinelReportManager()
    doc_mgr.assert_document_ownership(document_id, uid) # type: ignore
    doc_mgr.delete_document(document_id)
    _logger.info(f"Documento {document_id} eliminado por usuario {uid}")
    return jsonify({"message": "Documento eliminado correctamente", "documentId": document_id}), 200


# =========================================================================
# SCHEDULED SCAN ENDPOINTS
# =========================================================================

@sentinel_bp.post("/scheduled-scans")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_SCHEDULE_CREATE])
@limiter.limit("30 per hour; 100 per day")
@require_json(["scan_type", "arguments", "schedule_type", "schedule_config"])
@handle_exceptions(default_exception=ProgramedScanError, logger=_logger)
def schedule_scan(data):
    scan_type_str = data["scan_type"].lower()
    valid_types = {t.value for t in ScanType}
    if scan_type_str not in valid_types:
        raise ValidationError(
            field="scan_type",
            message="Tipo de escaneo inv\u00e1lido",
            value=scan_type_str,
            expected=", ".join(sorted(valid_types)),
        )
    user = get_current_user()
    ps = ProgramedScanManager.register(
        user_id=user.id, # type: ignore
        scan_type=ScanType(scan_type_str),
        arguments=data["arguments"],
        schedule_type=data["schedule_type"],
        schedule_config=data["schedule_config"],
    )
    _logger.info(
        f"Escaneo programado {ps.id} creado: tipo={scan_type_str} "
        f"programacion={data['schedule_type']} usuario={user.username}"
    )
    return jsonify({
        "message": "Escaneo programado creado correctamente",
        "programedScanId": ps.id,
        "scanType": scan_type_str,
        "scheduleType": data["schedule_type"],
        "scheduleConfig": data["schedule_config"],
        "nextRunAt": ps.next_run_at.isoformat() if ps.next_run_at else None, # type: ignore
        "user": user.username,
    }), 201

@sentinel_bp.delete("/scheduled-scans/<int:ps_id>")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_SCHEDULE_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=ProgramedScanNotFoundError, logger=_logger)
def revoke_scheduled_scan(ps_id: int):
    user = get_current_user()
    ps = ProgramedScanManager.assert_ownership(ps_id, user.id) # type: ignore
    ProgramedScanManager.revoke(ps_id, user.id) # type: ignore
    _logger.info(f"Escaneo programado {ps_id} revocado por {user.username}")
    return jsonify({
        "message": "Escaneo programado revocado correctamente",
        "programedScanId": ps_id,
        "scanType": ps.scan_type,
        "user": user.username,
    }), 200

@sentinel_bp.get("/scheduled-scans")
@limiter.limit("300 per hour; 2000 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_SCHEDULE_READ])
@handle_exceptions(default_exception=ProgramedScanError, logger=_logger)
def list_scheduled_scans():
    user = get_current_user()
    scans = ProgramedScanManager.get_scans_for_user(user.id) # type: ignore
    results = [
        {
            "id": ps.id,
            "scanType": ps.scan_type,
            "arguments": ps.arguments,
            "scheduleType": ps.schedule_type,
            "scheduleConfig": ps.schedule_config,
            "isActive": ps.is_active,
            "lastRunAt": ps.last_run_at.isoformat() if ps.last_run_at else None, # type: ignore
            "nextRunAt": ps.next_run_at.isoformat() if ps.next_run_at else None, # type: ignore
            "createdAt": ps.created_at.isoformat() if ps.created_at else None, # type: ignore
        }
        for ps in scans
    ]
    return jsonify({
        "message": "Escaneos programados obtenidos correctamente",
        "count": len(results),
        "scheduledScans": results,
        "user": user.username,
    }), 200
