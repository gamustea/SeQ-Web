"""
sentinel_endpoints.py
══════════════════════════════════════════════════════════════════════════════

Blueprint de la API REST para el módulo Sentinel (escaneos de seguridad).

Este módulo proporciona endpoints para lanzar, monitorizar y gestionar escaneos
de seguridad utilizando tres motores de escaneo:

    • Nmap      — Escaneo de puertos y detección de servicios
    • Nikto     — Escaneo de vulnerabilidades web
    • OpenVAS   — Escaneo completo de vulnerabilidades (GMP)

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

import base64
import os
import time
import ipaddress
import threading
from datetime import datetime
from typing import Optional
from contextlib import contextmanager

from flask import Blueprint, jsonify, request, send_file

from src.modules.sentinel import SentinelDocument
from src.modules.users import require_oauth_token, get_user_manager
from src.modules.exceptions import (
    ExceptionHandler,
    MissingParameterError,
    ReportGenerationError,
    ScanExecutionError,
    ScanNotFoundError,
    ValidationError,
    create_error_response,
)
from src.modules.misc import IPValidator, PortValidator, SecOpsLogger
from src.modules.sentinel import NmapPrintingStrategy, NiktoPrintingStrategy, OpenVASPrintingStrategy, PDFCreator
from src.modules.shared import limiter, get_current_user_id, get_current_username

from .managers import NmapScanManager, NiktoScanManager, OpenVASScanManager


sentinel_bp = Blueprint("sentinel", __name__)
_logger     = SecOpsLogger("sentinel").get_logger()

CANCELLABLE_STATES    = frozenset({"pending", "running"})
VALID_SCAN_TYPES      = frozenset({"nmap", "nikto", "openvas", "all"})
VALID_OPENVAS_CONFIGS = frozenset({"full_fast", "full_deep", "full_ultimate"})
MAX_PDF_SIZE_BYTES    = 50 * 1024 * 1024

def resolve_manager(
    scan_type: str,
    nmap_manager:    NmapScanManager,
    nikto_manager:   NiktoScanManager,
    openvas_manager: OpenVASScanManager,
) -> NmapScanManager | NiktoScanManager | OpenVASScanManager:
    """Devuelve el manager correcto a partir del tipo de escaneo (DRY)."""
    _logger.debug(f"Resolviendo manager para tipo de escaneo: {scan_type}")
    if scan_type == "nmap":
        return nmap_manager
    if scan_type == "nikto":
        return nikto_manager
    return openvas_manager

def verify_scan_ownership(
    scan: Scan, 
    user_id: int, 
    scan_id: int
) -> None:
    """
    Verifica que el escaneo pertenece al usuario. Responde 404 en caso
    contrario para evitar enumerar IDs ajenos.
    """
    if scan.user_id != user_id:
        _logger.warning(
            f"Usuario {user_id} intentó acceder al escaneo {scan_id} "
            f"(propietario: {scan.user_id})"
        )
        raise ScanNotFoundError(scan_id)

def get_scan_by_id_for_user(
    scan_id: int,
    nmap_manager:    NmapScanManager,
    nikto_manager:   NiktoScanManager,
    openvas_manager: OpenVASScanManager,
) -> Tuple[Optional[Scan], str]:
    """
    Busca un escaneo entre los tres tipos. Devuelve (scan, tipo) o (None, '').
    El tipo es 'nmap', 'nikto' u 'openvas'.
    """
    scan = nmap_manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)

    uid = get_current_user_id()
    verify_scan_ownership(scan, uid, scan_id)
    return scan, scan.scan_type

def build_pdf_creator(scan: Scan) -> PDFCreator:
    """Construye el PDFCreator con la estrategia correcta según el tipo de escaneo."""
    scan_type = getattr(scan, "scan_type", "").lower()

    if scan_type == "nmap":
        strategy = NmapPrintingStrategy(scan=scan)
    elif scan_type == "nikto":
        strategy = NiktoPrintingStrategy(scan=scan)
    elif scan_type == "openvas":
        strategy = OpenVASPrintingStrategy(scan=scan)
    else:
        raise ValidationError(
            field="scan_type",
            message=f"Tipo de escaneo '{scan_type}' no soportado",
            expected="'nmap', 'nikto' u 'openvas'",
        )

    return PDFCreator(strategy)

@contextmanager
def get_user_managers(user_id: int):
    with get_user_manager() as um:
        user = um.get_user_by_id(user_id)
        nmap    = NmapScanManager(user)
        nikto   = NiktoScanManager(user)
        openvas = OpenVASScanManager(user)
        try:
            yield nmap, nikto, openvas
        finally:
            nmap.close_session()
            nikto.close_session()
            openvas.close_session()

@sentinel_bp.get("/scan-status")
@require_oauth_token
@limiter.limit("300 per hour; 2000 per day")
def get_scan_status():
    """Estado y progreso de un escaneo."""
    try:
        scan_id = _parse_scan_id_from_args()
        uid     = get_current_user_id()
        
        with get_user_managers(uid) as (nmap, nikto, openvas):
            scan, scan_type = get_scan_by_id_for_user(scan_id, nmap, nikto, openvas)
            if not scan:
                raise ScanNotFoundError(scan_id)
            verify_scan_ownership(scan, uid, scan_id)

            manager  = resolve_manager(scan_type, nmap, nikto, openvas)
            status   = manager.get_scan_status(scan.id)
            progress = manager.get_scan_progress(scan.id)

        response = {
            "message":  f"Estado del escaneo {scan_id}: {status}",
            "scanId":   scan_id,
            "status":   status,
            "scanType": scan_type,
        }
        if progress is not None:
            response["progress"] = progress

        return jsonify(response), 200

    except (MissingParameterError, ValidationError, ScanNotFoundError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en scan-status: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code

@sentinel_bp.post("/scans/<int:scan_id>/cancel")
@require_oauth_token
@limiter.limit("60 per hour; 200 per day")
def cancel_scan(scan_id: int):
    """Cancela un escaneo en curso."""
    try:
        uid = get_current_user_id()
        
        with get_user_managers(uid) as (nmap, nikto, openvas):
            scan, scan_type = get_scan_by_id_for_user(scan_id, nmap, nikto, openvas)
            if not scan:
                raise ScanNotFoundError(scan_id)
            verify_scan_ownership(scan, uid, scan_id)

            if scan.status not in CANCELLABLE_STATES:
                return jsonify({
                    "error":            "invalid_state",
                    "message":          f"El escaneo no se puede cancelar en estado: {scan.status}",
                    "scanId":           scan_id,
                    "currentStatus":    scan.status,
                    "cancellableStates": sorted(CANCELLABLE_STATES),
                }), 400

        manager = resolve_manager(scan_type, nmap, nikto, openvas)
        if not manager.cancel_scan(scan_id):
            return jsonify({"error": "cancellation_failed", "message": "No se pudo cancelar", "scanId": scan_id}), 500

        scan = manager.get_scan_by_id(scan_id)
        _logger.info(f"Escaneo {scan_type} {scan_id} cancelado por {get_current_username()}")
        return jsonify({"message": "Escaneo cancelado exitosamente", "scanId": scan_id, "scanType": scan_type, "status": scan.status, "user": get_current_username()}), 200

    except ScanNotFoundError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error cancelando escaneo {scan_id}: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code

@sentinel_bp.post("/nmap")
@require_oauth_token
@limiter.limit("20 per hour; 100 per day")
def start_nmap_scan():
    """Lanza uno o más escaneos Nmap."""
    data = _require_json()
    if isinstance(data, tuple):
        return data

    try:
        host  = _require_str(data, "target")
        ports = _require_str(data, "ports")
    except MissingParameterError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code

    try:
        timeout = int(data.get("timeout", 300))
        if timeout <= 0:
            raise ValidationError(field="timeout", message="El timeout debe ser positivo", value=timeout)
    except (TypeError, ValueError):
        raise ValidationError(field="timeout", message="El timeout debe ser un entero válido", value=data.get("timeout"))

    try:
        uid = get_current_user_id()
        with get_user_managers(uid) as (nmap_manager, _, _):
            valid, hosts, msg = IPValidator.validate(host)
            if not valid:
                raise ValidationError(field="target", message=msg, value=host)

            valid, _, msg = PortValidator.validate(ports)
            if not valid:
                raise ValidationError(field="ports", message=msg, value=ports)

            scan_ids = []
            for target_host in hosts:
                scan_id = nmap_manager.run_scan(target_host=target_host, target_ports=ports, timeout=timeout)
                scan_ids.append(scan_id)
                _logger.info(f"Nmap lanzado: ID={scan_id} host={target_host} ports={ports} user={get_current_username()}")

        return jsonify({
            "message":    "Escaneo(s) Nmap iniciado(s) correctamente",
            "scanIds":    scan_ids,
            "target":     {"hosts": hosts, "ports": ports},
            "totalScans": len(scan_ids),
            "user":       get_current_username(),
        }), 201

    except (MissingParameterError, ValidationError, ScanExecutionError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error lanzando Nmap: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code

@sentinel_bp.post("/nikto")
@require_oauth_token
@limiter.limit("20 per hour; 100 per day")
def start_nikto_scan():
    """Lanza un escaneo Nikto."""
    data = _require_json()
    if isinstance(data, tuple):
        return data

    try:
        target = _require_str(data, "target")
    except MissingParameterError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code

    try:
        timeout = int(data.get("timeout", 900))
        if timeout <= 0:
            raise ValidationError(field="timeout", message="El timeout debe ser positivo", value=timeout)
    except (TypeError, ValueError):
        raise ValidationError(field="timeout", message="El timeout debe ser un entero válido", value=data.get("timeout"))

    try:
        uid = get_current_user_id()
        with get_user_managers(uid) as (_, nikto_manager, _):
            scan_id = nikto_manager.run_scan(target, timeout=timeout)
            _logger.info(f"Nikto lanzado: ID={scan_id} target={target} timeout={timeout} user={get_current_username()}")
        return jsonify({"message": "Escaneo Nikto iniciado correctamente", "scanId": scan_id, "target": target, "timeout": timeout, "user": get_current_username()}), 201

    except (MissingParameterError, ValidationError, ScanExecutionError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error lanzando Nikto: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.post("/openvas")
@require_oauth_token
@limiter.limit("10 per hour; 50 per day")
def start_openvas_scan():
    """Lanza un escaneo OpenVAS para un único host."""
    data = _require_json()
    if isinstance(data, tuple):
        return data

    try:
        target      = _require_str(data, "target")
        scan_config = data.get("scanConfig", "full_fast")
    except MissingParameterError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code

    try:
        if scan_config not in VALID_OPENVAS_CONFIGS:
            raise ValidationError(field="scanConfig", message="Configuración inválida", value=scan_config, expected=", ".join(sorted(VALID_OPENVAS_CONFIGS)))

        valid, hosts, msg = IPValidator.validate(target)
        if not valid:
            raise ValidationError(field="target", message=msg, value=target)
        if len(hosts) > 1:
            raise ValidationError(field="target", message="OpenVAS solo acepta un host a la vez", value=target, expected="Una sola IP")

        uid = get_current_user_id()
        with get_user_managers(uid) as (_, _, openvas_manager):
            target_ip = hosts[0]
            try:
                ipaddress.ip_address(target_ip)
            except ValueError:
                from src.modules.misc import normalize_target
                _, target_ip = normalize_target(target_ip)
            
            scan_id = openvas_manager.run_scan(target_ip, scan_config=scan_config, skip_normalize=True)
        _logger.info(f"OpenVAS lanzado: ID={scan_id} target={target_ip} config={scan_config} user={get_current_username()}")
        return jsonify({"message": "Escaneo OpenVAS iniciado correctamente", "scanId": scan_id, "target": target_ip, "scanConfig": scan_config, "user": get_current_username(), "note": "Use /sentinel/scan-status para verificar el progreso."}), 201

    except (ValidationError, ScanExecutionError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error lanzando OpenVAS: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.get("/results")
@require_oauth_token
@limiter.limit("300 per hour; 2000 per day")
def retrieve_all_scans():
    """Lista todos los escaneos del usuario con soporte de paginación."""
    try:
        scan_type = request.args.get("type", "all").lower()
        if scan_type not in VALID_SCAN_TYPES:
            raise ValidationError(field="type", message="Tipo de escaneo inválido", value=scan_type, expected="nmap, nikto, openvas o all")

        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)
        page = max(1, page)
        per_page = min(max(1, per_page), 100)

        uid = get_current_user_id()
        with get_user_managers(uid) as (nmap_mgr, nikto_mgr, openvas_mgr):
            all_results = []

            if scan_type in ("nmap", "all"):
                try:
                    all_results.extend(_format_nmap_scans(nmap_mgr.get_scans_for_user(), nmap_mgr))
                except Exception as exc:
                    _logger.error(f"Error obteniendo Nmap scans: {exc}")

            if scan_type in ("nikto", "all"):
                try:
                    all_results.extend(_format_nikto_scans(nikto_mgr.get_scans_for_user(), nikto_mgr))
                except Exception as exc:
                    _logger.error(f"Error obteniendo Nikto scans: {exc}")

            if scan_type in ("openvas", "all"):
                try:
                    all_results.extend(_format_openvas_scans(openvas_mgr.get_scans_for_user(), openvas_mgr))
                except Exception as exc:
                    _logger.error(f"Error obteniendo OpenVAS scans: {exc}")

        total_results = len(all_results)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_results = all_results[start:end]

        return jsonify({
            "message": "Escaneos obtenidos correctamente",
            "filter": scan_type,
            "count": len(paginated_results),
            "total": total_results,
            "page": page,
            "perPage": per_page,
            "totalPages": (total_results + per_page - 1) // per_page,
            "results": paginated_results,
            "user": get_current_username()
        }), 200

    except ValidationError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en /results: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.get("/results/<int:scan_id>")
@require_oauth_token
@limiter.limit("300 per hour; 2000 per day")
def retrieve_scan_by_id(scan_id: int):
    """Devuelve el detalle completo de un escaneo específico."""
    try:
        uid = get_current_user_id()
        with get_user_managers(uid) as (nmap, nikto, openvas):
            scan, scan_type = get_scan_by_id_for_user(scan_id, nmap, nikto, openvas)
            if not scan:
                raise ScanNotFoundError(scan_id)
            verify_scan_ownership(scan, uid, scan_id)

            if scan_type == "nmap":
                result = _format_nmap_scans([scan], nmap)[0]
                result["openPorts"] = [{"port": f"{p.port_id}/{p.port.protocol}", "reason": p.reason, "product": p.product, "version": p.version} for p in scan.open_ports_relation]
            elif scan_type == "nikto":
                result = _format_nikto_scans([scan], nikto)[0]
            else:
                result = _format_openvas_scans([scan], openvas)[0]
                result["severityBreakdown"] = {
                    "critical": sum(1 for r in scan.results if r.vulnerability.severity_class == "Critical"),
                    "high":     sum(1 for r in scan.results if r.vulnerability.severity_class == "High"),
                    "medium":   sum(1 for r in scan.results if r.vulnerability.severity_class == "Medium"),
                    "low":      sum(1 for r in scan.results if r.vulnerability.severity_class == "Low"),
                    "info":     sum(1 for r in scan.results if r.vulnerability.severity_class == "Log"),
                }

        return jsonify({"message": "Escaneo obtenido correctamente", "result": result, "user": get_current_username()}), 200

    except ScanNotFoundError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error obteniendo escaneo {scan_id}: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.get("/generate-pdf")
@require_oauth_token
@limiter.limit("30 per hour; 100 per day")
def generate_pdf():
    """Solicita la generación asíncrona de un PDF."""
    try:
        scan_id = _parse_scan_id_from_args()
        ai_report_str = request.args.get("aiReport", "false").lower()
        ai_report = ai_report_str == "true"
        
        uid = get_current_user_id()
        with get_user_managers(uid) as (nmap, nikto, openvas):
            scan, scan_type = get_scan_by_id_for_user(scan_id, nmap, nikto, openvas)

            manager = resolve_manager(scan_type, nmap, nikto, openvas)
            if not manager.is_scan_finished(scan.id):
                raise ValidationError(field="scan_id", message=f"El escaneo {scan_id} no está finalizado aún", value=scan_id)
        
            doc_id = manager.generate_report(scan_id=scan_id, ai_report=ai_report)   
        _logger.info(f"Generación de PDF solicitada para escaneo {scan_id} (documento {doc_id}) por usuario {get_current_username()} con AI Report: {ai_report}")

        return jsonify({
            "message": "Generación de PDF iniciada",
            "documentId": doc_id,
            "scanId": scan_id,
            "status": "pending",
            "aiReport": ai_report,
            "downloadUrl": f"/sentinel/document/{doc_id}/download"
        }), 202

    except (MissingParameterError, ValidationError, ScanNotFoundError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error generando PDF: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.get("/document-status")
@require_oauth_token
@limiter.limit("300 per hour; 2000 per day")
def get_document_status():
    """Consulta el estado de generación de un documento."""
    try:
        uid = get_current_user_id()
        
        document_id = request.args.get("document_id", type=int)
        scan_id = request.args.get("scan_id", type=int)
        
        if not document_id and not scan_id:
            raise MissingParameterError("document_id o scan_id")
        
        with get_user_managers(uid) as (nmap_mgr, _, _):
            from src.modules.sentinel import SentinelDocument
            
            if document_id:
                doc = nmap_mgr.session.query(SentinelDocument).filter(
                    SentinelDocument.id == document_id,
                    SentinelDocument.user_id == uid
                ).first()
            else:
                doc = nmap_mgr.session.query(SentinelDocument).filter(
                    SentinelDocument.scan_id == scan_id,
                    SentinelDocument.user_id == uid
                ).first()
            
            if not doc:
                raise ScanNotFoundError(document_id or scan_id)
            
            download_url = None
            if doc.status == "done" and doc.filename:
                download_url = f"/sentinel/document/{doc.id}/download"
        
        return jsonify({
            "documentId": doc.id,
            "scanId": doc.scan_id,
            "status": doc.status,
            "aiReport": doc.enrichment_json is not None,
            "createdAt": doc.created_at.isoformat() if doc.created_at else None,
            "generatedAt": doc.generated_at.isoformat() if doc.generated_at else None,
            "downloadUrl": download_url
        }), 200
        
    except MissingParameterError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except ScanNotFoundError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error consultando estado de documento: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.get("/documents")
@require_oauth_token
@limiter.limit("300 per hour; 2000 per day")
def get_all_documents():
    """Obtiene todos los documentos del usuario.
    
    Query params:
        scan_type (str): Filtrar por tipo de escaneo. Valores válidos: nmap, nikto, openvas, all. Default: all.
    """
    try:
        uid = get_current_user_id()
        scan_type_filter = request.args.get("scan_type", "all").lower()
        
        valid_types = ["nmap", "nikto", "openvas", "all"]
        if scan_type_filter not in valid_types:
            return jsonify({"error": f"Tipo de escaneo inválido. Valores válidos: {', '.join(valid_types)}"}), 400
        
        with get_user_managers(uid) as (nmap_mgr, _, _):
            documents = nmap_mgr.get_documents_for_user()
            
            if scan_type_filter != "all":
                documents = [d for d in documents if d.scan_type == scan_type_filter]
            
            docs_list = []
            for doc in documents:
                download_url = None
                if doc.status == "done" and doc.filename:
                    download_url = f"/sentinel/document/{doc.id}/download"
                
                docs_list.append({
                    "documentId": doc.id,
                    "scanId": doc.scan_id,
                    "scanType": doc.scan_type,
                    "status": doc.status,
                    "isAiGenerated": doc.is_ai_generated == 1 if doc.is_ai_generated is not None else False,
                    "createdAt": doc.created_at.isoformat() if doc.created_at else None,
                    "generatedAt": doc.generated_at.isoformat() if doc.generated_at else None,
                    "downloadUrl": download_url
                })
        
        return jsonify({
            "documents": docs_list,
            "total": len(docs_list),
            "filter": scan_type_filter
        }), 200
        
    except Exception as exc:
        _logger.error(f"Error obteniendo documentos: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.get("/scan/<int:scan_id>/documents")
@require_oauth_token
@limiter.limit("300 per hour; 2000 per day")
def get_documents_by_scan(scan_id: int):
    """Obtiene todos los documentos de un escaneo concreto.
    
    Args:
        scan_id (path): ID del escaneo.
        
    Returns:
        200 — Lista de documentos del escaneo.
        404 — Escaneo no encontrado.
    """
    try:
        uid = get_current_user_id()
        
        with get_user_managers(uid) as (nmap_mgr, _, _):
            scan = nmap_mgr.get_scan_by_id(scan_id)
            if not scan:
                return jsonify({"error": "Escaneo no encontrado"}), 404
            
            if scan.user_id != uid:
                return jsonify({"error": "No tienes permisos para acceder a este escaneo"}), 403
            
            from src.modules.sentinel import SentinelDocument
            documents = nmap_mgr.session.query(SentinelDocument).filter(
                SentinelDocument.scan_id == scan_id,
                SentinelDocument.user_id == uid
            ).order_by(SentinelDocument.created_at.desc()).all()
            
            docs_list = []
            for doc in documents:
                download_url = None
                if doc.status == "done" and doc.filename:
                    download_url = f"/sentinel/document/{doc.id}/download"
                
                docs_list.append({
                    "documentId": doc.id,
                    "scanId": doc.scan_id,
                    "scanType": doc.scan_type,
                    "status": doc.status,
                    "isAiGenerated": doc.is_ai_generated == 1 if doc.is_ai_generated is not None else False,
                    "createdAt": doc.created_at.isoformat() if doc.created_at else None,
                    "generatedAt": doc.generated_at.isoformat() if doc.generated_at else None,
                    "downloadUrl": download_url
                })
        
        return jsonify({
            "scanId": scan_id,
            "documents": docs_list,
            "total": len(docs_list)
        }), 200
        
    except Exception as exc:
        _logger.error(f"Error obteniendo documentos del escaneo {scan_id}: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.get("/is-finished")
@require_oauth_token
@limiter.limit("300 per hour; 2000 per day")
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
    try:
        scan_id = _parse_scan_id_from_args()
        uid     = get_current_user_id()
        with get_user_managers(uid) as (nmap, nikto, openvas):
            scan, scan_type = get_scan_by_id_for_user(scan_id, nmap, nikto, openvas)
            if not scan:
                raise ScanNotFoundError(scan_id)
            verify_scan_ownership(scan, uid, scan_id)

            manager  = resolve_manager(scan_type, nmap, nikto, openvas)
            finished = manager.is_scan_finished(scan.id)

        return jsonify({
            "message":    f"El escaneo {scan_id} {'está' if finished else 'no está'} terminado",
            "scanId":     scan_id,
            "isFinished": finished,
            "scanType":   scan_type,
        }), 200

    except (MissingParameterError, ValidationError, ScanNotFoundError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.get("/document/<int:document_id>/download")
@require_oauth_token
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
    try:
        uid = get_current_user_id()
        _logger.info(f"Download request for document {document_id} by user {uid}")
        
        with get_user_managers(uid) as (nmap_mgr, _, _):
            doc = nmap_mgr.get_document_by_id(document_id)
            if not doc or doc.user_id != uid:
                _logger.warning(f"Document {document_id} not found or access denied for user {uid}")
                return jsonify({"error": "Documento no encontrado o acceso denegado"}), 404
            
            if doc.status != "done" or not doc.filename or not os.path.exists(doc.filename):
                _logger.warning(f"Document {document_id} not ready: status={doc.status}, filename={doc.filename}")
                return jsonify({"error": f"El documento {document_id} aún no está disponible para descarga"}), 400
            
            _logger.info(f"Serving document {document_id}: {doc.filename}")
            return send_file(doc.filename, mimetype="application/pdf", as_attachment=True, download_name=f"{doc.scan_type}_scan_{doc.scan_id}.pdf")
        
    except Exception as exc:
        _logger.error(f"Error descargando documento {document_id}: {exc}", exc_info=True)
        return jsonify({"error": str(exc)}), 500


@sentinel_bp.get("/document/<int:document_id>/download-test")
def download_document_test(document_id: int):
    """Endpoint de prueba sin auth para verificar la descarga."""
    try:
        with get_user_managers(1) as (nmap_mgr, _, _):
            doc = nmap_mgr.get_document_by_id(document_id)
            if not doc:
                return jsonify({"error": "Documento no encontrado"}), 404
            
            if doc.status != "done" or not doc.filename or not os.path.exists(doc.filename):
                return jsonify({"error": "Documento no disponible", "status": doc.status, "filename": doc.filename}), 400
            
            return send_file(doc.filename, mimetype="application/pdf", as_attachment=True, download_name=f"{doc.scan_type}_scan_{doc.scan_id}.pdf")
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@sentinel_bp.route("/document/<int:document_id>", methods=["DELETE"])
@require_oauth_token
@limiter.limit("30 per hour; 100 per day")
def delete_document(document_id: int):
    """Elimina un documento.
    
    Args (path):
        document_id (int): ID del documento a eliminar.
        
    Returns:
        200 — Documento eliminado correctamente.
        404 — Documento no encontrado.
        403 — Sin permisos.
    """
    try:
        uid = get_current_user_id()
        with get_user_managers(uid) as (nmap_mgr, _, _):
            doc = nmap_mgr.get_document_by_id(document_id)
            if not doc or doc.user_id != uid:
                return jsonify({"error": "Documento no encontrado o acceso denegado"}), 404
            
            scan_id = doc.scan_id
            
            if doc.filename and os.path.exists(doc.filename):
                try:
                    os.remove(doc.filename)
                except Exception as e:
                    _logger.warning(f"No se pudo eliminar el archivo {doc.filename}: {e}")
            
            nmap_mgr.session.delete(doc)
            nmap_mgr._safe_commit()
            
            _logger.info(f"Documento {document_id} eliminado por {get_current_username()}")
            return jsonify({"message": "Documento eliminado", "documentId": document_id, "scanId": scan_id}), 200
        
    except Exception as exc:
        _logger.error(f"Error eliminando documento {document_id}: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.get("/generate-pdf-base64")
@require_oauth_token
@limiter.limit("30 per hour; 100 per day")
def generate_pdf_base64():
    """Devuelve el PDF codificado en Base64 para integraciones cliente.

    Útil cuando se necesita incluir el PDF en una respuesta JSON o передать
    el contenido directamente al frontend.

    Args (query params):
        id (int): ID del escaneo.

    Returns:
        200 — JSON con el PDF en Base64.
            {
                "message": "PDF generado exitosamente",
                "scanId": 42,
                "scanType": "nmap",
                "filename": "nmap_scan_42.pdf",
                "pdfBase64": "JVBERi0xLjQK...",
                "contentType": "application/pdf",
                "user": "admin"
            }
        400 — El escaneo aún no ha terminado.
        413 — El PDF supera el límite de tamaño (10MB). Usa /generate-pdf.
        404 — Escaneo no encontrado.

    Example:
        curl "http://localhost:5000/sentinel/generate-pdf-base64?id=42" \\
             -H "Authorization: Bearer <token>"
    """
    try:
        scan_id = _parse_scan_id_from_args()
        uid     = get_current_user_id()
        with get_user_managers(uid) as (nmap, nikto, openvas):
            scan, scan_type = get_scan_by_id_for_user(scan_id, nmap, nikto, openvas)
            if not scan:
                raise ScanNotFoundError(scan_id)
            verify_scan_ownership(scan, uid, scan_id)

            manager = resolve_manager(scan_type, nmap, nikto, openvas)
            if not manager.is_scan_finished(scan.id):
                raise ValidationError(field="scan_id", message=f"El escaneo {scan_id} no está finalizado aún", value=scan_id)

            try:
                pdf_path = build_pdf_creator(scan).print_pdf()
            except Exception as exc:
                raise ReportGenerationError(scan_id, str(exc))

            if not pdf_path or not os.path.exists(pdf_path):
                raise ReportGenerationError(scan_id, "El archivo PDF no se generó correctamente")

            pdf_size = os.path.getsize(pdf_path)
            if pdf_size > MAX_PDF_SIZE_BYTES:
                return jsonify({"error": "payload_too_large", "message": f"El PDF ({pdf_size // (1024*1024)} MB) supera el límite. Usa /generate-pdf para descarga directa.", "scanId": scan_id}), 413

            with open(pdf_path, "rb") as f:
                pdf_b64 = base64.b64encode(f.read()).decode()

        return jsonify({"message": "PDF generado exitosamente", "scanId": scan_id, "scanType": scan_type, "filename": f"{scan_type}_scan_{scan_id}.pdf", "pdfBase64": pdf_b64, "contentType": "application/pdf", "user": get_current_username()}), 200

    except (MissingParameterError, ValidationError, ScanNotFoundError, ReportGenerationError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error generando PDF base64: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.delete("/<int:scan_id>")
@require_oauth_token
@limiter.limit("60 per hour; 200 per day")
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
    try:
        uid = get_current_user_id()
        with get_user_managers(uid) as (nmap, nikto, openvas):
            scan, scan_type = get_scan_by_id_for_user(scan_id, nmap, nikto, openvas)
            if not scan:
                raise ScanNotFoundError(scan_id)
            verify_scan_ownership(scan, uid, scan_id)

            manager = resolve_manager(scan_type, nmap, nikto, openvas)

            if scan.status in CANCELLABLE_STATES:
                _logger.info(f"Cancelando escaneo {scan_id} antes de eliminar")
                manager.cancel_scan(scan_id)

            if not manager.delete_scan(scan_id):
                return jsonify({"error": "deletion_failed", "message": "No se pudo eliminar el escaneo", "scanId": scan_id}), 500

        _logger.info(f"Escaneo {scan_type} {scan_id} eliminado por {get_current_username()}")
        return jsonify({"message": "Escaneo eliminado correctamente", "scanId": scan_id, "scanType": scan_type, "user": get_current_username()}), 200

    except ScanNotFoundError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error eliminando escaneo {scan_id}: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code






def _require_json() -> dict:
    """Extrae y valida el cuerpo de la petición como JSON.

    Returns:
        dict: Datos JSON parseados.

    Raises:
        400: Si el Content-Type no es application/json o el JSON es inválido.
    """
    if not request.is_json:
        return jsonify({"error": "invalid_request", "error_description": "Content-Type must be application/json"}), 400
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid_request", "error_description": "Request body must be JSON"}), 400
    return data


def _require_str(data: dict, field: str) -> str:
    """Extrae un campo obligatorio del JSON y lo valida como string no vacío.

    Args:
        data: Diccionario con los datos del request.
        field: Nombre del campo a extraer.

    Returns:
        str: El valor del campo, triminado de espacios.

    Raises:
        MissingParameterError: Si el campo falta o está vacío.
    """
    value = data.get(field)
    if not value or not str(value).strip():
        raise MissingParameterError(field)
    return str(value).strip()


def _parse_scan_id_from_args() -> int:
    """Extrae el parámetro 'id' de la query string como entero.

    Returns:
        int: El ID del escaneo.

    Raises:
        MissingParameterError: Si el parámetro 'id' no existe.
        ValidationError: Si el valor no es un entero válido.
    """
    raw = request.args.get("id")
    if not raw:
        raise MissingParameterError("id")
    try:
        return int(raw)
    except ValueError:
        raise ValidationError(field="id", message="El ID debe ser un número entero", value=raw)


def _ts(dt) -> str:
    """Convierte un objeto datetime a string ISO 8601.

    Args:
        dt: Objeto datetime o string.

    Returns:
        str: Representación ISO del datetime.
    """
    return dt.isoformat() if hasattr(dt, "isoformat") else str(dt)


def _format_nmap_scans(scans: list, manager=None) -> list:
    """Formatea una lista de escaneos Nmap para la respuesta JSON.

    Args:
        scans: Lista de objetos NmapScan de la base de datos.
        manager: (opcional) Manager para obtener documentos.

    Returns:
        list: Lista de diccionarios con los datos del escaneo en formato JSON.

    Estructura del resultado:
        {
            "id": int,
            "scanType": "nmap",
            "target": str,
            "status": str,
            "startedAt": str (ISO 8601),
            "openPorts": [
                {"port": "80/tcp", "reason": "syn-ack", "product": "Apache", "version": "2.4"}
            ],
            "totalOpenPorts": int,
            "documentId": int (optional)
        }
    """
    results = []
    for s in scans:
        entry = {
            "id":             s.id,
            "scanType":       "nmap",
            "target":         s.target,
            "status":         getattr(s, "status", "unknown"),
            "startedAt":      _ts(s.started_at),
            "finishedAt":    _ts(s.finished_at),
            "openPorts":      [{"port": f"{p.port_id}/{p.port.protocol}", "reason": p.reason} for p in s.open_ports_relation],
            "totalOpenPorts": len(s.open_ports_relation),
        }

        if manager:
            doc = manager.get_latest_document_by_scan_id(s.id)
            if doc:
                entry["documentId"] = doc.id
                entry["documentStatus"] = doc.status

        results.append(entry)

    return results


def _format_nikto_scans(scans: list, manager=None) -> list:
    """Formatea una lista de escaneos Nikto para la respuesta JSON.

    Args:
        scans: Lista de objetos NiktoScan de la base de datos.
        manager: (opcional) Manager para obtener documentos.

    Returns:
        list: Lista de diccionarios con los datos del escaneo en formato JSON.

    Estructura del resultado:
        {
            "id": int,
            "scanType": "nikto",
            "target": str,
            "status": str,
            "startedAt": str (ISO 8601),
            "incidents": [
                {
                    "osvdbId": int,
                    "method": "GET",
                    "url": "/admin",
                    "description": str,
                    "severity": "MEDIUM",
                    "discoveredAt": str (ISO 8601)
                }
            ],
            "totalIncidents": int,
            "documentId": int (optional)
        }
    """
    results = []
    for s in scans:
        entry = {
            "id":             s.id,
            "scanType":       "nikto",
            "target":         s.target,
            "status":         getattr(s, "status", "unknown"),
            "startedAt":      _ts(s.started_at),
            "finishedAt":    _ts(s.finished_at),
            "incidents":      [
                {
                    "osvdbId":     i.osvdb_id,
                    "method":      i.method,
                    "url":         i.url,
                    "description": i.description,
                    "severity":    getattr(i, "severity", "UNKNOWN"),
                    "discoveredAt": _ts(i.discovered_at),
                }
                for i in s.incidents
            ],
            "totalIncidents": len(s.incidents),
        }

        if manager:
            doc = manager.get_latest_document_by_scan_id(s.id)
            if doc:
                entry["documentId"] = doc.id
                entry["documentStatus"] = doc.status

        results.append(entry)

    return results


def _format_openvas_scans(scans: list, manager=None) -> list:
    """Formatea una lista de escaneos OpenVAS para la respuesta JSON.

    Args:
        scans: Lista de objetos OpenVASScan de la base de datos.
        manager: (opcional) Manager para obtener documentos.

    Returns:
        list: Lista de diccionarios con los datos del escaneo en formato JSON.

    Estructura del resultado:
        {
            "id": int,
            "scanType": "openvas",
            "target": str,
            "taskId": str,
            "reportId": str,
            "status": str,
            "startedAt": str (ISO 8601),
            "vulnerabilities": [...],
            "totalVulnerabilities": int,
            "criticalCount": int,
            "highCount": int,
            "documentId": int (optional)
        }
    """
    results = []
    for s in scans:
        entry = {
            "id":                   s.id,
            "scanType":             "openvas",
            "target":               s.target,
            "taskId":               s.task_id,
            "reportId":             s.report_id,
            "status":               getattr(s, "status", "unknown"),
            "startedAt":            _ts(s.started_at),
            "finishedAt":          _ts(s.finished_at),
            "vulnerabilities":      [
                {
                    "nvtOid":        r.vulnerability.nvt_oid,
                    "name":          r.vulnerability.name,
                    "severityScore": r.vulnerability.severity_score,
                    "severityClass": r.vulnerability.severity_class,
                    "cvssBaseScore": r.vulnerability.cvss_base_score,
                    "cvssVector":    r.vulnerability.cvss_vector,
                    "cveIds":        r.vulnerability.cve_ids,
                    "description":   r.vulnerability.description,
                    "solution":      r.vulnerability.solution,
                    "solutionType":  r.vulnerability.solution_type,
                    "affectedSoftware": r.vulnerability.affected_software,
                    "hostIp":        r.host.ip_address if r.host else None,
                    "hostName":      r.host.hostname   if r.host else None,
                }
                for r in s.results
            ],
            "totalVulnerabilities": len(s.results),
            "criticalCount":        sum(1 for r in s.results if r.vulnerability.severity_class == "Critical"),
            "highCount":            sum(1 for r in s.results if r.vulnerability.severity_class == "High"),
        }

        if manager:
            doc = manager.get_latest_document_by_scan_id(s.id)
            if doc:
                entry["documentId"] = doc.id
                entry["documentStatus"] = doc.status

        results.append(entry)

    return results
