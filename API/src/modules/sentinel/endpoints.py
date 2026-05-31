from __future__ import annotations

import os
import ipaddress

from flask import jsonify, request, send_file
from flask_smorest import Blueprint as SmorestBlueprint

from src.modules.users import require_oauth_token, require_attributes, AttributeType, get_current_user
from src.modules.shared import (
    handle_exceptions,
    limiter,
)
from src.modules.shared._exceptions import (
    MissingParameterError,
    ValidationError,
    IllegalStateError,
)
from src.modules.shared.schemas import ErrorSchema
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
)
from .schemas import (
    ScanIdQuerySchema,
    NmapScanRequestSchema,
    NiktoScanRequestSchema,
    OpenVASScanRequestSchema,
    ResultsQuerySchema,
    GeneratePdfQuerySchema,
    DocumentStatusQuerySchema,
    DocumentsQuerySchema,
    ScheduledScanRequestSchema,
    ScanResponseSchema,
    NmapScanResponseSchema,
    ScanStatusResponseSchema,
    IsFinishedResponseSchema,
    ResultsResponseSchema,
    ScanDetailResponseSchema,
    DocumentStatusResponseSchema,
    DocumentListResponseSchema,
    ScanDocumentsResponseSchema,
    DocumentDeleteResponseSchema,
    PdfGenerateResponseSchema,
    ScheduledScanResponseSchema,
    ScheduledScanListResponseSchema,
    ScheduledScanActionResponseSchema,
)


sentinel_blp = SmorestBlueprint(
    "sentinel", __name__,
    description="Escaneos de seguridad (Nmap, Nikto, OpenVAS) y PDFs"
)
_logger = SecOpsLogger("sentinel").get_logger()

CANCELLABLE_STATES = frozenset({"pending", "running"})
MAX_PDF_SIZE_BYTES = 50 * 1024 * 1024


@sentinel_blp.get("/scan-status")
@sentinel_blp.arguments(ScanIdQuerySchema, location="query")
@sentinel_blp.response(200, ScanStatusResponseSchema, description="Scan status")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def get_scan_status(args):
    """Estado y progreso de un escaneo"""
    scan_id = args["id"]
    user = get_current_user()
    manager = ScanManager.resolve_manager(scan_id)
    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)
    ScanManager.assert_scan_ownership(scan_id, user.id)

    status = manager.get_scan_status(scan_id)
    progress = manager.get_scan_progress(scan_id)
    result = manager.format_scan(scan_id)

    response = {
        "message": f"Estado del escaneo {scan_id}: {status}",
        "scanId": scan_id,
        "status": status,
        "scanType": scan.scan_type,
    }
    if progress is not None:
        response["progress"] = progress
    response["scan"] = result

    return response


@sentinel_blp.post("/scans/<int:scan_id>/cancel")
@sentinel_blp.response(200, ScanResponseSchema, description="Scan cancelled")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Invalid state")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(500, schema=ErrorSchema, description="Cancellation failed")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_UPDATE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def cancel_scan(scan_id: int):
    """Cancelar un escaneo en curso"""
    user = get_current_user()

    manager = ScanManager.resolve_manager(scan_id)
    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)
    ScanManager.assert_scan_ownership(scan_id, user.id)

    if scan.status not in CANCELLABLE_STATES:
        return jsonify({
            "error": "invalid_state",
            "error_description": f"El escaneo no se puede cancelar en estado: {scan.status}",
            "scanId": scan_id,
            "currentStatus": scan.status,
            "cancellableStates": sorted(CANCELLABLE_STATES),
        }), 400

    if not manager.cancel_scan(scan_id, user.id):
        return jsonify({
            "error": "cancellation_failed",
            "error_description": "No se pudo cancelar",
            "scanId": scan_id,
        }), 500

    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)

    _logger.info(f"Escaneo {scan.scan_type} {scan_id} cancelado por {user.username}")
    return jsonify({
        "message": "Escaneo cancelado exitosamente",
        "scanId": scan_id,
        "scanType": scan.scan_type,
        "status": scan.status,
        "user": user.username,
    }), 200


@sentinel_blp.post("/nmap")
@sentinel_blp.arguments(NmapScanRequestSchema)
@sentinel_blp.response(201, NmapScanResponseSchema, description="Nmap scan started")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@limiter.limit("20 per hour; 100 per day")
@handle_exceptions(default_exception=ScanExecutionError, logger=_logger)
def start_nmap_scan(data: dict):
    """Lanzar uno o mas escaneos Nmap (soporta rangos CIDR)"""
    host = data["target"]
    ports = data["ports"]
    timeout = data["timeout"]
    user = get_current_user()

    nmap_manager = NmapScanManager()
    try:
        hosts = ScanManager.validate_ip(host)
    except IPValidationError as exc:
        raise ValidationError(field="target", message=str(exc), value=host) from exc
    except MaxHostsExceededError as exc:
        return jsonify({
            "error": exc.__class__.__name__,
            "error_description": exc.user_message or str(exc),
            "details": exc.details or {},
        }), 400
    except PrivateIPRequested as exc:
        return jsonify({
            "error": exc.__class__.__name__,
            "error_description": exc.user_message or str(exc),
            "details": exc.details or {},
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
            timeout=timeout,
        )
        scan_ids.append(scan_id)
        _logger.info(f"Nmap lanzado: ID={scan_id} host={target_host} ports={ports} user={user.username}")

    return jsonify({
        "message": "Escaneo(s) Nmap iniciado(s) correctamente",
        "scanIds": scan_ids,
        "target": {"hosts": hosts, "ports": ports},
        "totalScans": len(scan_ids),
        "user": user.username,
    }), 201


@sentinel_blp.post("/nikto")
@sentinel_blp.arguments(NiktoScanRequestSchema)
@sentinel_blp.response(201, ScanResponseSchema, description="Nikto scan started")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("20 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@handle_exceptions(default_exception=ScanExecutionError, logger=_logger)
def start_nikto_scan(data):
    """Lanzar un escaneo Nikto"""
    target = data["target"]
    timeout = data["timeout"]
    user = get_current_user()

    nikto_manager = NiktoScanManager()
    scan_id = nikto_manager.run_scan(target, user_id=user.id, timeout=timeout)
    _logger.info(f"Nikto lanzado: ID={scan_id} target={target} timeout={timeout} user={user.username}")
    return jsonify({
        "message": "Escaneo Nikto iniciado correctamente",
        "scanId": scan_id,
        "target": target,
        "timeout": timeout,
        "user": user.username,
    }), 201


@sentinel_blp.post("/openvas")
@sentinel_blp.arguments(OpenVASScanRequestSchema)
@sentinel_blp.response(201, ScanResponseSchema, description="OpenVAS scan started")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("10 per hour; 50 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@handle_exceptions(default_exception=ScanExecutionError, logger=_logger)
def start_openvas_scan(data):
    """Lanzar un escaneo OpenVAS para un unico host"""
    target = data["target"]
    scan_config = data["scanConfig"]
    user = get_current_user()
    if user is None:
        raise IllegalStateError("'user' detectado como None")

    try:
        hosts = ScanManager.validate_ip(target, max_hosts=1)
    except IPValidationError as exc:
        raise ValidationError(field="target", message=str(exc), value=target) from exc
    except MaxHostsExceededError as exc:
        return jsonify({
            "error": exc.__class__.__name__,
            "error_description": exc.user_message or str(exc),
            "details": exc.details or {},
        }), 400
    except PrivateIPRequested as exc:
        return jsonify({
            "error": exc.__class__.__name__,
            "error_description": exc.user_message or str(exc),
            "details": exc.details or {},
        }), 403

    openvas_manager = OpenVASScanManager()
    target_ip = hosts[0]
    ipaddress.ip_address(target_ip)

    scan_id = openvas_manager.run_scan(
        target=target_ip,
        scan_config=scan_config,
        user_id=user.id,
        skip_normalize=True,
    )
    _logger.info(f"OpenVAS lanzado: ID={scan_id} target={target_ip} config={scan_config} user={user.username}")

    return jsonify({
        "message": "Escaneo OpenVAS iniciado correctamente",
        "scanId": scan_id,
        "target": target_ip,
        "scanConfig": scan_config,
        "user": user.username,
        "note": "Use /sentinel/scan-status para verificar el progreso.",
    }), 201


@sentinel_blp.get("/results")
@sentinel_blp.arguments(ResultsQuerySchema, location="query")
@sentinel_blp.response(200, ResultsResponseSchema, description="Scan results")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def retrieve_all_scans(args):
    """Listar todos los escaneos del usuario con paginacion opcional"""
    scan_type = args["type"]
    page = args["page"]
    per_page = args["per_page"]

    user = get_current_user()
    uid = user.id

    TYPE_MGR_MAP = {
        "nmap": NmapScanManager(),
        "nikto": NiktoScanManager(),
        "openvas": OpenVASScanManager(),
    }

    if scan_type != "all":
        mgr = TYPE_MGR_MAP[scan_type]
        results, total_count = mgr.get_scans_paginated(uid, page, per_page)
        total_pages = (total_count + per_page - 1) // per_page

        return jsonify({
            "message": "Escaneos obtenidos correctamente",
            "filter": scan_type,
            "count": total_count,
            "results": results,
            "page": page,
            "perPage": per_page,
            "totalCount": total_count,
            "totalPages": total_pages,
            "user": user.username,
        }), 200

    all_results = []
    for mgr in TYPE_MGR_MAP.values():
        try:
            for scan in mgr.get_scans_for_user(uid):
                all_results.append(mgr.format_scan(scan.id))
        except (OSError, RuntimeError) as exc:
            _logger.error(f"Error obteniendo scans: {exc}")

    return jsonify({
        "message": "Escaneos obtenidos correctamente",
        "filter": scan_type,
        "count": len(all_results),
        "results": all_results,
        "user": user.username,
    }), 200


@sentinel_blp.get("/stats")
@sentinel_blp.response(200, description="Scan statistics")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def get_scan_stats():
    """Contadores de escaneos por tipo"""
    from src.modules.infrastructure.session import get_db_session
    from .repositories import ScanRepository as _ScanRepo
    user = get_current_user()
    session = get_db_session()
    repo = _ScanRepo(session=session)
    stats = repo.get_stats(user.id)
    return stats


@sentinel_blp.get("/results/<int:scan_id>")
@sentinel_blp.response(200, ScanDetailResponseSchema, description="Scan detail")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def retrieve_scan_by_id(scan_id: int):
    """Detalle completo de un escaneo especifico"""
    user = get_current_user()

    manager = ScanManager.resolve_manager(scan_id)
    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)
    ScanManager.assert_scan_ownership(scan_id, user.id)

    _logger.info(f"Obteniendo detalles para escaneo {scan_id} de tipo {scan.scan_type} por usuario {user.username}")
    result = manager.format_scan(scan_id)
    if scan.scan_type == "nmap":
        result["openPorts"] = [{
            "port": f"{p.port_id}/{p.port.protocol}",
            "reason": p.reason,
            "product": p.product,
            "version": p.version,
        } for p in scan.open_ports_relation]
    elif scan.scan_type == "openvas":
        result["severityBreakdown"] = {
            "critical": sum(1 for r in scan.results if r.vulnerability.severity_class == "Critical"),
            "high": sum(1 for r in scan.results if r.vulnerability.severity_class == "High"),
            "medium": sum(1 for r in scan.results if r.vulnerability.severity_class == "Medium"),
            "low": sum(1 for r in scan.results if r.vulnerability.severity_class == "Low"),
            "info": sum(1 for r in scan.results if r.vulnerability.severity_class == "Log"),
        }

    return jsonify({
        "message": "Escaneo obtenido correctamente",
        "result": result,
        "user": user.username,
    }), 200


@sentinel_blp.get("/is-finished")
@sentinel_blp.arguments(ScanIdQuerySchema, location="query")
@sentinel_blp.response(200, IsFinishedResponseSchema, description="Scan finished status")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def is_scan_finished(args):
    """Indicar si un escaneo ha finalizado"""
    user = get_current_user()
    scan_id = args["id"]
    manager = ScanManager.resolve_manager(scan_id)
    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)
    ScanManager.assert_scan_ownership(scan_id, user.id)

    finished = manager.is_scan_finished(scan.id)

    return jsonify({
        "message": f"El escaneo {scan_id} {'esta' if finished else 'no esta'} terminado",
        "scanId": scan_id,
        "isFinished": finished,
        "scanType": scan.scan_type,
    }), 200


@sentinel_blp.delete("/<int:scan_id>")
@sentinel_blp.response(200, ScanResponseSchema, description="Scan deleted")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@sentinel_blp.alt_response(500, schema=ErrorSchema, description="Deletion failed")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def delete_scan(scan_id: int):
    """Eliminar un escaneo del sistema"""
    user = get_current_user()

    manager = ScanManager.resolve_manager(scan_id)
    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)
    ScanManager.assert_scan_ownership(scan_id, user.id)

    if scan.status in CANCELLABLE_STATES:
        _logger.info(f"Cancelando escaneo {scan_id} antes de eliminar")
        manager.cancel_scan(scan_id, user.id)

    if not manager.delete_scan(scan_id):
        return jsonify({
            "error": "deletion_failed",
            "error_description": "No se pudo eliminar el escaneo",
            "scanId": scan_id,
        }), 500

    _logger.info(f"Escaneo {scan.scan_type} {scan_id} eliminado por {user.username}")
    return jsonify({
        "message": "Escaneo eliminado correctamente",
        "scanId": scan_id,
        "scanType": scan.scan_type,
        "user": user.username,
    }), 200


@sentinel_blp.get("/generate-pdf")
@sentinel_blp.arguments(GeneratePdfQuerySchema, location="query")
@sentinel_blp.response(202, PdfGenerateResponseSchema, description="PDF generation started")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Scan not finished")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def generate_pdf(args):
    """Solicitar generacion asincrona de un PDF"""
    scan_id = args["id"]
    ai_report = args["aiReport"].lower() == "true"

    user = get_current_user()
    uid = user.id

    manager = ScanManager.resolve_manager(scan_id)
    ScanManager.assert_scan_ownership(scan_id, uid)

    if not manager.is_scan_finished(scan_id):
        raise ValidationError(
            field="scan_id",
            message=f"El escaneo {scan_id} no esta finalizado aun",
            value=scan_id,
        )

    doc_mgr = SentinelReportManager()
    doc_id = doc_mgr.generate_report(
        scan_id=scan_id,
        ai_report=ai_report,
        strategy_class=manager._strategy_class,
    )
    _logger.info(f"Generacion de PDF solicitada para escaneo {scan_id} (documento {doc_id}) por usuario {user.username} con AI Report: {ai_report}")

    return jsonify({
        "message": "Generacion de PDF iniciada",
        "documentId": doc_id,
        "scanId": scan_id,
        "status": "pending",
        "aiReport": ai_report,
        "downloadUrl": f"/sentinel/document/{doc_id}/download",
    }), 202


@sentinel_blp.get("/document-status")
@sentinel_blp.arguments(DocumentStatusQuerySchema, location="query")
@sentinel_blp.response(200, DocumentStatusResponseSchema, description="Document status")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=_logger)
def get_document_status(args):
    """Consultar estado de generacion de un documento"""
    user = get_current_user()
    document_id = args.get("document_id")
    scan_id = args.get("scan_id")

    doc_mgr = SentinelReportManager()

    doc = doc_mgr.get_document_by_id(document_id) if document_id else (
        doc_mgr.get_latest_document_by_scan_id(scan_id) if scan_id else None
    )

    if not doc:
        raise ScanNotFoundError(document_id or scan_id)

    if document_id:
        doc_mgr.assert_document_ownership(document_id, user.id)

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
        "downloadUrl": download_url,
    }), 200


@sentinel_blp.get("/documents")
@sentinel_blp.arguments(DocumentsQuerySchema, location="query")
@sentinel_blp.response(200, DocumentListResponseSchema, description="All documents")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=DocumentError, logger=_logger)
def get_all_documents(args):
    """Obtener todos los documentos del usuario"""
    user = get_current_user()
    scan_type_filter = args["scan_type"]

    doc_mgr = SentinelReportManager()
    documents = doc_mgr.get_documents_for_user(user.id)

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
            "downloadUrl": download_url,
        })

    return jsonify({
        "documents": docs_list,
        "total": len(docs_list),
        "filter": scan_type_filter,
    }), 200


@sentinel_blp.get("/scan/<int:scan_id>/documents")
@sentinel_blp.response(200, ScanDocumentsResponseSchema, description="Scan documents")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=DocumentError, logger=_logger)
def get_documents_by_scan(scan_id: int):
    """Obtener todos los documentos de un escaneo concreto"""
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
            "downloadUrl": download_url,
        })

    return jsonify({
        "scanId": scan_id,
        "documents": docs_list,
        "total": len(docs_list),
    }), 200


@sentinel_blp.get("/document/<int:document_id>/download")
@sentinel_blp.response(200, description="PDF file download")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Document not ready")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@handle_exceptions(default_exception=DocumentError, logger=_logger)
def download_document(document_id: int):
    """Descargar un documento PDF generado"""
    user = get_current_user()
    uid = user.id
    _logger.info(f"Download request for document {document_id} by user {uid}")

    doc_mgr = SentinelReportManager()
    doc_mgr.assert_document_ownership(document_id, uid)

    doc = doc_mgr.get_document_by_id(document_id)
    if not doc:
        _logger.warning(f"Document {document_id} not found or access denied for user {uid}")
        return jsonify({"error": "not_found", "error_description": "Documento no encontrado o acceso denegado"}), 404

    if doc.status != "done" or not doc.filename or not os.path.exists(doc.filename):
        _logger.warning(f"Document {document_id} not ready: status={doc.status}, filename={doc.filename}")
        return jsonify({"error": "not_ready", "error_description": f"El documento {document_id} aun no esta disponible para descarga"}), 400

    _logger.info(f"Serving document {document_id}: {doc.filename}")
    return send_file(
        doc.filename,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{doc.scan_type}_scan_{doc.scan_id}.pdf",
    )


@sentinel_blp.delete("/document/<int:document_id>")
@sentinel_blp.response(200, DocumentDeleteResponseSchema, description="Document deleted")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_DELETE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=DocumentError, logger=_logger)
def delete_document(document_id: int):
    """Eliminar un documento"""
    user = get_current_user()
    uid = user.id

    doc_mgr = SentinelReportManager()
    doc_mgr.assert_document_ownership(document_id, uid)
    doc_mgr.delete_document(document_id)
    _logger.info(f"Documento {document_id} eliminado por usuario {uid}")
    return {"message": "Documento eliminado correctamente", "documentId": document_id}


@sentinel_blp.post("/scheduled-scans")
@sentinel_blp.arguments(ScheduledScanRequestSchema)
@sentinel_blp.response(201, ScheduledScanResponseSchema, description="Scheduled scan created")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_SCHEDULE_CREATE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=ProgramedScanError, logger=_logger)
def schedule_scan(data):
    """Crear un escaneo programado"""
    scan_type_str = data["scan_type"].lower()
    valid_types = {t.value for t in ScanType}
    if scan_type_str not in valid_types:
        raise ValidationError(
            field="scan_type",
            message="Tipo de escaneo invalido",
            value=scan_type_str,
            expected=", ".join(sorted(valid_types)),
        )
    user = get_current_user()
    ps = ProgramedScanManager.register(
        user_id=user.id,
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
        "nextRunAt": ps.next_run_at.isoformat() if ps.next_run_at else None,
        "user": user.username,
    }), 201


@sentinel_blp.delete("/scheduled-scans/<int:ps_id>")
@sentinel_blp.response(200, ScheduledScanActionResponseSchema, description="Scheduled scan revoked")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_SCHEDULE_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=ProgramedScanNotFoundError, logger=_logger)
def revoke_scheduled_scan(ps_id: int):
    """Revocar un escaneo programado (desactivar)"""
    user = get_current_user()
    ps = ProgramedScanManager.assert_ownership(ps_id, user.id)
    ProgramedScanManager.revoke(ps_id, user.id)
    _logger.info(f"Escaneo programado {ps_id} revocado por {user.username}")
    return jsonify({
        "message": "Escaneo programado revocado correctamente",
        "programedScanId": ps_id,
        "scanType": ps.scan_type,
        "user": user.username,
    }), 200


@sentinel_blp.delete("/scheduled-scans/<int:ps_id>/permanent")
@sentinel_blp.response(200, ScheduledScanActionResponseSchema, description="Scheduled scan permanently deleted")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_SCHEDULE_DELETE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=ProgramedScanNotFoundError, logger=_logger)
def delete_scheduled_scan(ps_id: int):
    """Eliminar permanentemente un escaneo programado de la BD"""
    user = get_current_user()
    ps = ProgramedScanManager.assert_ownership(ps_id, user.id)
    ProgramedScanManager.delete(ps_id, user.id)
    _logger.info(f"Escaneo programado {ps_id} eliminado permanentemente por {user.username}")
    return jsonify({
        "message": "Escaneo programado eliminado permanentemente",
        "programedScanId": ps_id,
        "scanType": ps.scan_type,
        "user": user.username,
    }), 200


@sentinel_blp.get("/scheduled-scans")
@sentinel_blp.response(200, ScheduledScanListResponseSchema, description="List of scheduled scans")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("300 per hour; 2000 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_SCHEDULE_READ])
@handle_exceptions(default_exception=ProgramedScanError, logger=_logger)
def list_scheduled_scans():
    """Listar todos los escaneos programados del usuario"""
    user = get_current_user()
    scans = ProgramedScanManager.get_scans_for_user(user.id)
    results = [
        {
            "id": ps.id,
            "scanType": ps.scan_type,
            "arguments": ps.arguments,
            "scheduleType": ps.schedule_type,
            "scheduleConfig": ps.schedule_config,
            "isActive": ps.is_active,
            "lastRunAt": ps.last_run_at.isoformat() if ps.last_run_at else None,
            "nextRunAt": ps.next_run_at.isoformat() if ps.next_run_at else None,
            "createdAt": ps.created_at.isoformat() if ps.created_at else None,
        }
        for ps in scans
    ]
    return jsonify({
        "message": "Escaneos programados obtenidos correctamente",
        "count": len(results),
        "scheduledScans": results,
        "user": user.username,
    }), 200
