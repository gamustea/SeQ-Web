"""
endpoints/sentinel.py
─────────────────────
Blueprint de escaneos (Sentinel). Registrado en /sentinel.

Estado y control
  GET  /sentinel/is-finished              — ¿ha finalizado un escaneo?
  GET  /sentinel/scan-status              — estado/progreso de un escaneo
  POST /sentinel/scans/<scan_id>/cancel   — cancelar un escaneo en curso

Lanzamiento
  POST /sentinel/nmap                     — lanzar escaneo Nmap
  POST /sentinel/nikto                    — lanzar escaneo Nikto
  POST /sentinel/openvas                  — lanzar escaneo OpenVAS

Resultados
  GET  /sentinel/results                  — todos los escaneos del usuario
  GET  /sentinel/results/<scan_id>        — un escaneo concreto

PDF
  GET  /sentinel/generate-pdf             — descargar PDF
  GET  /sentinel/generate-pdf-base64      — obtener PDF en base64

Eliminación
  DELETE /sentinel/<scan_id>              — eliminar escaneo
"""

from __future__ import annotations

import base64
import os
import time
from datetime import datetime
from typing import Optional

from flask import Blueprint, jsonify, request, send_file

from src.core.exceptions import (
    ExceptionHandler,
    MissingParameterError,
    ReportGenerationError,
    ScanExecutionError,
    ScanNotFoundError,
    ValidationError,
    create_error_response,
)
from src.misc.logging import SecOpsLogger
from src.misc.validation import IPValidator, PortValidator

from ._shared import (
    CANCELLABLE_STATES,
    MAX_PDF_SIZE_BYTES,
    VALID_OPENVAS_CONFIGS,
    VALID_SCAN_TYPES,
    build_pdf_creator,
    get_current_user_id,
    get_current_username,
    get_scan_by_id_for_user,
    get_user_managers,
    require_oauth_token,
    resolve_manager,
    verify_scan_ownership,
)

sentinel_bp = Blueprint("sentinel", __name__)
_logger     = SecOpsLogger("sentinel").get_logger()


# ═══════════════════════════════════════════════════════════════════════════════
# ESTADO Y CONTROL
# ═══════════════════════════════════════════════════════════════════════════════

@sentinel_bp.get("/is-finished")
@require_oauth_token
def is_scan_finished():
    """Indica si un escaneo ya finalizó."""
    try:
        scan_id = _parse_scan_id_from_args()
        uid     = get_current_user_id()
        nmap, nikto, openvas = get_user_managers(uid)

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
    except Exception as exc:
        _logger.error(f"Error en is-finished: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.get("/scan-status")
@require_oauth_token
def get_scan_status():
    """Estado y progreso de un escaneo."""
    try:
        scan_id = _parse_scan_id_from_args()
        uid     = get_current_user_id()
        nmap, nikto, openvas = get_user_managers(uid)

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
def cancel_scan(scan_id: int):
    """Cancela un escaneo en curso (estados 'pending' o 'running')."""
    try:
        uid = get_current_user_id()
        nmap, nikto, openvas = get_user_managers(uid)

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


# ═══════════════════════════════════════════════════════════════════════════════
# LANZAMIENTO DE ESCANEOS
# ═══════════════════════════════════════════════════════════════════════════════

@sentinel_bp.post("/nmap")
@require_oauth_token
def start_nmap_scan():
    """Lanza uno o más escaneos Nmap (soporta rangos CIDR y rangos de IPs)."""
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
        uid = get_current_user_id()
        nmap_manager, _, _ = get_user_managers(uid)

        valid, hosts, msg = IPValidator.validate(host)
        if not valid:
            raise ValidationError(field="target", message=msg, value=host)

        valid, _, msg = PortValidator.validate(ports)
        if not valid:
            raise ValidationError(field="ports", message=msg, value=ports)

        scan_ids = []
        for target_host in hosts:
            scan_id = nmap_manager.run_scan(target_host, ports)
            scan_ids.append(scan_id)
            _logger.info(f"Nmap lanzado: ID={scan_id} host={target_host} ports={ports} user={get_current_username()}")
            time.sleep(0.10)

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
        timeout = int(data.get("timeout", 180))
        if timeout <= 0:
            raise ValidationError(field="timeout", message="El timeout debe ser positivo", value=timeout)
    except (TypeError, ValueError):
        raise ValidationError(field="timeout", message="El timeout debe ser un entero válido", value=data.get("timeout"))

    try:
        uid = get_current_user_id()
        _, nikto_manager, _ = get_user_managers(uid)
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
        _, _, openvas_manager = get_user_managers(uid)
        scan_id = openvas_manager.run_scan(hosts[0], scan_config=scan_config)
        _logger.info(f"OpenVAS lanzado: ID={scan_id} target={hosts[0]} config={scan_config} user={get_current_username()}")
        return jsonify({"message": "Escaneo OpenVAS iniciado correctamente", "scanId": scan_id, "target": hosts[0], "scanConfig": scan_config, "user": get_current_username(), "note": "Use /sentinel/scan-status para verificar el progreso."}), 201

    except (ValidationError, ScanExecutionError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error lanzando OpenVAS: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


# ═══════════════════════════════════════════════════════════════════════════════
# RESULTADOS
# ═══════════════════════════════════════════════════════════════════════════════

@sentinel_bp.get("/results")
@require_oauth_token
def retrieve_all_scans():
    """Lista todos los escaneos del usuario. Filtrable por ?type=nmap|nikto|openvas|all."""
    try:
        scan_type = request.args.get("type", "all").lower()
        if scan_type not in VALID_SCAN_TYPES:
            raise ValidationError(field="type", message="Tipo de escaneo inválido", value=scan_type, expected="nmap, nikto, openvas o all")

        uid = get_current_user_id()
        nmap_mgr, nikto_mgr, openvas_mgr = get_user_managers(uid)
        all_results = []

        if scan_type in ("nmap", "all"):
            try:
                all_results.extend(_format_nmap_scans(nmap_mgr.get_scans_for_user()))
            except Exception as exc:
                _logger.error(f"Error obteniendo Nmap scans: {exc}")

        if scan_type in ("nikto", "all"):
            try:
                all_results.extend(_format_nikto_scans(nikto_mgr.get_scans_for_user()))
            except Exception as exc:
                _logger.error(f"Error obteniendo Nikto scans: {exc}")

        if scan_type in ("openvas", "all"):
            try:
                all_results.extend(_format_openvas_scans(openvas_mgr.get_scans_for_user()))
            except Exception as exc:
                _logger.error(f"Error obteniendo OpenVAS scans: {exc}")

        return jsonify({"message": "Escaneos obtenidos correctamente", "filter": scan_type, "count": len(all_results), "results": all_results, "user": get_current_username()}), 200

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
def retrieve_scan_by_id(scan_id: int):
    """Devuelve el detalle completo de un escaneo concreto."""
    try:
        uid = get_current_user_id()
        nmap, nikto, openvas = get_user_managers(uid)

        scan, scan_type = get_scan_by_id_for_user(scan_id, nmap, nikto, openvas)
        if not scan:
            raise ScanNotFoundError(scan_id)
        verify_scan_ownership(scan, uid, scan_id)

        if scan_type == "nmap":
            result = _format_nmap_scans([scan])[0]
            result["openPorts"] = [{"port": f"{p.port_id}/{p.port.protocol}", "reason": p.reason, "product": p.product, "version": p.version} for p in scan.open_ports_relation]
        elif scan_type == "nikto":
            result = _format_nikto_scans([scan])[0]
        else:
            result = _format_openvas_scans([scan])[0]
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


# ═══════════════════════════════════════════════════════════════════════════════
# PDF
# ═══════════════════════════════════════════════════════════════════════════════

@sentinel_bp.get("/generate-pdf")
@require_oauth_token
def generate_pdf():
    """Genera y descarga el PDF de un escaneo finalizado."""
    try:
        scan_id = _parse_scan_id_from_args()
        uid     = get_current_user_id()
        nmap, nikto, openvas = get_user_managers(uid)

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

        _logger.info(f"PDF generado para escaneo {scan_id} — user={get_current_username()}")
        return send_file(pdf_path, mimetype="application/pdf", as_attachment=True, download_name=f"{scan_type}_scan_{scan_id}.pdf")

    except (MissingParameterError, ValidationError, ScanNotFoundError, ReportGenerationError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error generando PDF: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@sentinel_bp.get("/generate-pdf-base64")
@require_oauth_token
def generate_pdf_base64():
    """Devuelve el PDF de un escaneo como string base64."""
    try:
        scan_id = _parse_scan_id_from_args()
        uid     = get_current_user_id()
        nmap, nikto, openvas = get_user_managers(uid)

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


# ═══════════════════════════════════════════════════════════════════════════════
# ELIMINACIÓN
# ═══════════════════════════════════════════════════════════════════════════════

@sentinel_bp.delete("/<int:scan_id>")
@require_oauth_token
def delete_scan(scan_id: int):
    """Elimina un escaneo. Si está en curso, lo cancela primero."""
    try:
        uid = get_current_user_id()
        nmap, nikto, openvas = get_user_managers(uid)

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


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS PRIVADOS
# ═══════════════════════════════════════════════════════════════════════════════

def _require_json():
    if not request.is_json:
        return jsonify({"error": "invalid_request", "error_description": "Content-Type must be application/json"}), 400
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid_request", "error_description": "Request body must be JSON"}), 400
    return data


def _require_str(data: dict, field: str) -> str:
    value = data.get(field)
    if not value or not str(value).strip():
        raise MissingParameterError(field)
    return str(value).strip()


def _parse_scan_id_from_args() -> int:
    raw = request.args.get("id")
    if not raw:
        raise MissingParameterError("id")
    try:
        return int(raw)
    except ValueError:
        raise ValidationError(field="id", message="El ID debe ser un número entero", value=raw)


def _ts(dt) -> str:
    return dt.isoformat() if hasattr(dt, "isoformat") else str(dt)


def _format_nmap_scans(scans) -> list:
    return [
        {
            "id":             s.id,
            "scanType":       "nmap",
            "target":         s.target,
            "status":         getattr(s, "status", "unknown"),
            "startedAt":      _ts(s.started_at),
            "openPorts":      [{"port": f"{p.port_id}/{p.port.protocol}", "reason": p.reason} for p in s.open_ports_relation],
            "totalOpenPorts": len(s.open_ports_relation),
        }
        for s in scans
    ]


def _format_nikto_scans(scans) -> list:
    return [
        {
            "id":             s.id,
            "scanType":       "nikto",
            "target":         s.target,
            "status":         getattr(s, "status", "unknown"),
            "startedAt":      _ts(s.started_at),
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
        for s in scans
    ]


def _format_openvas_scans(scans) -> list:
    return [
        {
            "id":                   s.id,
            "scanType":             "openvas",
            "target":               s.target,
            "taskId":               s.task_id,
            "reportId":             s.report_id,
            "status":               getattr(s, "status", "unknown"),
            "startedAt":            _ts(s.started_at),
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
        for s in scans
    ]
