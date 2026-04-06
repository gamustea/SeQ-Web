# src/endpoints/aegis.py
"""
endpoints/aegis.py
──────────────────
Blueprint consolidado de generación y exportación de píldoras Aegis.
Registrado en /aegis.

Rutas principales:
    POST   /aegis/generate             — iniciar generación asíncrona
    GET    /aegis/status               — consultar estado
    GET    /aegis/document             — obtener contenido estructurado
    GET    /aegis/download             — descargar fichero original
    DELETE /aegis/document             — eliminar documento
    GET    /aegis/documents            — listar documentos
    GET    /aegis/topics               — listar temas

Rutas de exportación:
    GET    /aegis/export/formats       — listar formatos disponibles
    POST   /aegis/export/<id>          — exportar a formato específico
    GET    /aegis/export/<id>/download — descargar exportación
    GET    /aegis/export/md/<id>       — quick export a Markdown
"""

from flask import Blueprint, jsonify, request, send_file, Response

from src.core.exceptions import (
    ExceptionHandler,
    MissingParameterError,
    UserNotFoundError,
    ValidationError,
    create_error_response,
)
from src.logic.documents.aegis_exporters import (
    ExportData,
    ExportFormat,
    MarkdownExporter,
    MarkdownTemplate,
    JsonExporter,
    get_exporter_for_format,
)
from src.misc.logging import SecOpsLogger

from ._shared import (
    get_aegis_manager,
    get_current_user_id,
    get_current_username,
    limiter,
    require_oauth_token,
)


aegis_bp = Blueprint("aegis", __name__)
_logger  = SecOpsLogger("aegis").get_logger()


# ============================================================================
# HELPERS INTERNOS
# ============================================================================

def _parse_doc_id(source: str = "args") -> int:
    """Extrae y valida el parámetro 'id' desde query string o JSON body."""
    raw = (
        request.args.get("id")
        if source == "args"
        else (request.get_json(silent=True) or {}).get("id")
    )
    if not raw:
        raise MissingParameterError("id")
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ValidationError(field="id", message="El ID debe ser un número entero", value=raw)


def _doc_not_found(doc_id: int):
    return jsonify({"error": "not_found", "message": f"Documento {doc_id} no encontrado"}), 404


def _doc_not_ready(doc_id: int, status: str):
    return jsonify({
        "error":   "not_ready",
        "message": f"El documento {doc_id} aún no está disponible (estado: {status})",
        "status":  status,
    }), 409


def _get_document_checked(manager, doc_id: int, user_id: int) -> dict:
    """
    Recupera un documento validando propiedad y estado.
    Lanza ValueError si no existe o no pertenece al usuario.
    Lanza PermissionError si el estado no es 'done'.
    """
    doc = manager.get_document(doc_id)
    if not doc or doc.get("userId") != user_id:
        _logger.warning(f"Documento {doc_id} no encontrado o acceso denegado para user {get_current_username()} (userId={user_id})")
        raise ValueError(f"Documento {doc_id} no encontrado")
    if doc["status"] != "done":
        raise PermissionError(f"Documento no listo. Estado: {doc['status']}")
    return doc


# ============================================================================
# ENDPOINTS PRINCIPALES
# ============================================================================

@aegis_bp.post("/generate")
@require_oauth_token
@limiter.limit("10 per hour; 30 per day")
def aegis_generate():
    """
    Inicia la generación asíncrona de una píldora Aegis.
    Devuelve 202 Accepted con el documentId para polling de estado.
    """
    if not request.is_json:
        return jsonify({"error": "invalid_request", "error_description": "Content-Type must be application/json"}), 400

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid_request", "error_description": "Request body must be a JSON object"}), 400

    topic_id_raw = data.get("topicId")
    if topic_id_raw is None:
        err, code = create_error_response(MissingParameterError("topicId"), include_debug_info=False)
        return jsonify(err), code

    try:
        topic_id = int(topic_id_raw)
    except (TypeError, ValueError):
        err, code = create_error_response(
            ValidationError(field="topicId", message="El topicId debe ser un número entero", value=topic_id_raw),
            include_debug_info=False,
        )
        return jsonify(err), code

    tweaks = data.get("tweaks") or {}
    if not isinstance(tweaks, dict):
        err, code = create_error_response(
            ValidationError(field="tweaks", message="tweaks debe ser un objeto JSON", value=str(type(tweaks))),
            include_debug_info=False,
        )
        return jsonify(err), code

    try:
        uid         = get_current_user_id()
        mgr         = get_aegis_manager(uid)
        document_id = mgr.generate(topic_id=topic_id, tweaks=tweaks)
        mgr.close_session()

        _logger.info(f"Aegis generate lanzado — topicId={topic_id} documentId={document_id} user={get_current_username()}")
        return jsonify({"message": "Generación Aegis iniciada", "documentId": document_id, "status": "pending"}), 202

    except (MissingParameterError, ValidationError, UserNotFoundError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en /aegis/generate: {exc}", exc_info=True)
        err, code = create_error_response(ExceptionHandler.wrap_exception(exc, logger=_logger), include_debug_info=False)
        return jsonify(err), code


@aegis_bp.get("/status")
@require_oauth_token
@limiter.limit("120 per hour; 500 per day")
def aegis_status():
    """Devuelve el estado de generación de un documento."""
    try:
        doc_id   = _parse_doc_id()
        uid      = get_current_user_id()
        mgr      = get_aegis_manager(uid)
        doc_info = mgr.get_document(doc_id)
        mgr.close_session()

        if not doc_info or doc_info.get("userId") != uid:
            return _doc_not_found(doc_id)

        return jsonify({
            "id":          doc_info["id"],
            "title":       doc_info["title"],
            "status":      doc_info["status"],
            "format":      doc_info.get("format", "json"),
            "generatedAt": doc_info["generatedAt"],
            "topicId":     doc_info["topicId"],
        }), 200

    except (MissingParameterError, ValidationError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en /aegis/status: {exc}", exc_info=True)
        err, code = create_error_response(ExceptionHandler.wrap_exception(exc, logger=_logger), include_debug_info=False)
        return jsonify(err), code


@aegis_bp.get("/document")
@require_oauth_token
@limiter.limit("60 per hour; 300 per day")
def aegis_get_document():
    """Devuelve el contenido estructurado de un documento 'done'."""
    try:
        doc_id   = _parse_doc_id()
        uid      = get_current_user_id()
        mgr      = get_aegis_manager(uid)
        doc_info = mgr.get_document(doc_id)
        mgr.close_session()

        if not doc_info or doc_info.get("userId") != uid:
            return _doc_not_found(doc_id)
        if doc_info["status"] != "done":
            return _doc_not_ready(doc_id, doc_info["status"])

        return jsonify(doc_info), 200

    except (MissingParameterError, ValidationError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en /aegis/document: {exc}", exc_info=True)
        err, code = create_error_response(ExceptionHandler.wrap_exception(exc, logger=_logger), include_debug_info=False)
        return jsonify(err), code


@aegis_bp.get("/download")
@require_oauth_token
@limiter.limit("30 per hour; 100 per day")
def aegis_download():
    """
    Descarga el fichero original generado (.json).
    Para exportaciones formateadas usar /aegis/export/.
    """
    try:
        doc_id   = _parse_doc_id()
        uid      = get_current_user_id()
        mgr      = get_aegis_manager(uid)
        doc_info = mgr.get_document(doc_id)

        if not doc_info or doc_info.get("userId") != uid:
            mgr.close_session()
            return _doc_not_found(doc_id)
        if doc_info["status"] != "done":
            mgr.close_session()
            return _doc_not_ready(doc_id, doc_info["status"])

        try:
            path = mgr.get_document_path(doc_id)
        except ValueError:
            mgr.close_session()
            return _doc_not_found(doc_id)
        except FileNotFoundError:
            mgr.close_session()
            return jsonify({"error": "not_found", "message": "El fichero del documento no está disponible en disco"}), 404

        mgr.close_session()

        doc_format = doc_info.get("format", "json")
        mimetype   = "application/json" if doc_format == "json" else "text/markdown; charset=utf-8"

        _logger.info(f"Descargando Aegis doc {doc_id} ({doc_format}) — user={get_current_username()}")
        return send_file(path, as_attachment=True, download_name=path.name, mimetype=mimetype)

    except (MissingParameterError, ValidationError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en /aegis/download: {exc}", exc_info=True)
        err, code = create_error_response(ExceptionHandler.wrap_exception(exc, logger=_logger), include_debug_info=False)
        return jsonify(err), code


@aegis_bp.delete("/document")
@require_oauth_token
@limiter.limit("30 per hour; 100 per day")
def aegis_delete_document():
    """Elimina un documento Aegis (BD + fichero en disco)."""
    try:
        doc_id   = _parse_doc_id()
        uid      = get_current_user_id()
        mgr      = get_aegis_manager(uid)
        doc_info = mgr.get_document(doc_id)

        if not doc_info or doc_info.get("userId") != uid:
            mgr.close_session()
            return _doc_not_found(doc_id)

        mgr.delete_document(doc_id)

        _logger.info(f"Aegis doc {doc_id} eliminado — user={get_current_username()}")
        return jsonify({"message": "Documento eliminado correctamente", "documentId": doc_id}), 200

    except (MissingParameterError, ValidationError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except ValueError as exc:
        return jsonify({"error": "not_found", "message": str(exc)}), 404
    except Exception as exc:
        _logger.error(f"Error en DELETE /aegis/document: {exc}", exc_info=True)
        err, code = create_error_response(ExceptionHandler.wrap_exception(exc, logger=_logger), include_debug_info=False)
        return jsonify(err), code


@aegis_bp.get("/documents")
@require_oauth_token
@limiter.limit("60 per hour; 300 per day")
def aegis_list_documents():
    """Lista todos los documentos Aegis del usuario autenticado."""
    try:
        uid  = get_current_user_id()
        mgr  = get_aegis_manager(uid)
        docs = mgr.list_documents()
        mgr.close_session()

        return jsonify({"count": len(docs), "documents": docs}), 200

    except Exception as exc:
        _logger.error(f"Error en /aegis/documents: {exc}", exc_info=True)
        err, code = create_error_response(ExceptionHandler.wrap_exception(exc, logger=_logger), include_debug_info=False)
        return jsonify(err), code


@aegis_bp.get("/topics")
@require_oauth_token
@limiter.limit("120 per hour; 600 per day")
def aegis_get_topics():
    """Devuelve la lista de temas disponibles."""
    try:
        uid     = get_current_user_id()
        mgr     = get_aegis_manager(uid)
        topics  = mgr.get_topics()
        mgr.close_session()

        return jsonify(topics), 200

    except Exception as exc:
        _logger.error(f"Error en /aegis/topics: {exc}", exc_info=True)
        err, code = create_error_response(ExceptionHandler.wrap_exception(exc, logger=_logger), include_debug_info=False)
        return jsonify(err), code


# ============================================================================
# ENDPOINTS DE EXPORTACIÓN
# ============================================================================


@aegis_bp.get("/export/formats")
@require_oauth_token
def list_export_formats():
    """Lista todos los formatos de exportación disponibles."""
    return jsonify({
        "default": "md",
        "formats": [
            {
                "id":          "md",
                "name":        "Markdown",
                "description": "Documento estructurado legible por humanos, ideal para revisión",
                "mimetype":    "text/markdown; charset=utf-8",
                "extension":   ".md",
                "features":    ["streaming", "human_readable", "version_control_friendly", "editable"],
            },
            {
                "id":          "json",
                "name":        "JSON",
                "description": "Formato nativo estructurado para integraciones",
                "mimetype":    "application/json",
                "extension":   ".json",
                "features":    ["machine_readable", "structured", "api_friendly"],
            },
            {
                "id":          "pdf",
                "name":        "PDF",
                "description": "Documento final para distribución formal (próximamente)",
                "mimetype":    "application/pdf",
                "extension":   ".pdf",
                "coming_soon": True,
            },
            {
                "id":          "html",
                "name":        "HTML",
                "description": "Página web para intranet (próximamente)",
                "mimetype":    "text/html",
                "extension":   ".html",
                "coming_soon": True,
            },
        ],
    }), 200


@aegis_bp.post("/export/<int:doc_id>")
@require_oauth_token
@limiter.limit("20 per hour; 100 per day")
def export_document(doc_id: int):
    """
    Exporta un documento Aegis al formato solicitado.

    Body JSON:
        format  (str):  "md" o "json" (por defecto "md")
        options (dict): includeToc (bool), includeMetadata (bool)
    """
    try:
        if not request.is_json:
            return jsonify({"error": "invalid_request", "message": "Content-Type debe ser application/json"}), 400

        body       = request.get_json(silent=True) or {}
        format_str = body.get("format", "md")
        options    = body.get("options", {})

        try:
            export_format = ExportFormat(format_str.lower())
        except ValueError:
            return jsonify({"error": "unsupported_format", "message": f"Formato '{format_str}' no soportado", "supported": ["md", "json"]}), 400

        uid = get_current_user_id()
        mgr = get_aegis_manager(uid)

        try:
            doc_info = _get_document_checked(mgr, doc_id, uid)
        except ValueError:
            mgr.close_session()
            return jsonify({"error": "not_found", "message": f"Documento {doc_id} no encontrado"}), 404
        except PermissionError as exc:
            mgr.close_session()
            return jsonify({"error": "not_ready", "message": str(exc)}), 409

        export_data = ExportData.from_document_dict(doc_info, doc_id)

        if export_format == ExportFormat.MARKDOWN:
            exporter = MarkdownExporter(template=MarkdownTemplate(
                include_toc            = options.get("includeToc",   False),
                include_metadata_block = options.get("includeMetadata", True),
            ))
        else:
            exporter = JsonExporter()

        result = exporter.export(export_data)
        mgr.close_session()

        _logger.info(f"Exportación {export_format.value} generada para doc {doc_id} — user={get_current_username()}, size={result.size_bytes}b")
        return jsonify({
            "success":     True,
            "export":      result.to_response_dict(),
            "document":    {"id": doc_id, "title": doc_info.get("title"), "topicId": doc_info.get("topicId"), "status": doc_info.get("status")},
            "downloadUrl": f"/aegis/export/{doc_id}/download?format={export_format.value}",
        }), 200

    except Exception as exc:
        _logger.error(f"Error en exportación: {exc}", exc_info=True)
        err, code = create_error_response(ExceptionHandler.wrap_exception(exc, logger=_logger), include_debug_info=False)
        return jsonify(err), code


@aegis_bp.get("/export/<int:doc_id>/download")
@require_oauth_token
@limiter.limit("30 per hour; 150 per day")
def download_export(doc_id: int):
    """
    Descarga directa de una exportación.

    Query params:
        format (str):  "md" o "json" (por defecto "md")
        inline (bool): mostrar en navegador en lugar de descargar
    """
    try:
        format_str    = request.args.get("format", "md")
        inline        = request.args.get("inline", "false").lower() == "true"

        try:
            export_format = ExportFormat(format_str.lower())
        except ValueError:
            return jsonify({"error": "unsupported_format", "message": f"Formato '{format_str}' no soportado"}), 400

        uid = get_current_user_id()
        mgr = get_aegis_manager(uid)

        try:
            doc_info = _get_document_checked(mgr, doc_id, uid)
        except ValueError:
            mgr.close_session()
            return jsonify({"error": "not_found", "message": f"Documento {doc_id} no encontrado"}), 404
        except PermissionError as exc:
            mgr.close_session()
            return jsonify({"error": "not_ready", "message": str(exc)}), 409

        export_data = ExportData.from_document_dict(doc_info, doc_id)
        exporter    = MarkdownExporter() if export_format == ExportFormat.MARKDOWN else JsonExporter()
        result      = exporter.export(export_data)
        mgr.close_session()

        disposition = "inline" if inline else "attachment"
        _logger.info(f"Descarga {export_format.value} doc {doc_id} — user={get_current_username()}, inline={inline}")

        return Response(
            result.content,
            mimetype = result.mimetype,
            headers  = {
                "Content-Disposition": f'{disposition}; filename="{result.filename}"',
                "Content-Length":      str(result.size_bytes),
                "X-Export-Format":     export_format.value,
                "X-Document-Id":       str(doc_id),
            },
        )

    except Exception as exc:
        _logger.error(f"Error en download export: {exc}", exc_info=True)
        err, code = create_error_response(ExceptionHandler.wrap_exception(exc, logger=_logger), include_debug_info=False)
        return jsonify(err), code


@aegis_bp.get("/export/md/<int:doc_id>")
@require_oauth_token
@limiter.limit("30 per hour; 150 per day")
def quick_export_markdown(doc_id: int):
    """
    Exportación rápida a Markdown. Equivale a /export/<id>/download?format=md.

    Query params:
        inline   (bool): mostrar en navegador en lugar de descargar
        noAlerts (bool): excluir la sección de alertas
    """
    try:
        inline         = request.args.get("inline",   "false").lower() == "true"
        include_alerts = request.args.get("noAlerts", "false").lower() != "true"

        uid = get_current_user_id()
        mgr = get_aegis_manager(uid)

        try:
            doc_info = _get_document_checked(mgr, doc_id, uid)
        except ValueError:
            mgr.close_session()
            return jsonify({"error": "not_found", "message": f"Documento {doc_id} no encontrado"}), 404
        except PermissionError as exc:
            mgr.close_session()
            return jsonify({"error": "not_ready", "message": str(exc), "status": "pending"}), 409

        export_data = ExportData.from_document_dict(doc_info, doc_id)
        if not include_alerts:
            # Sobreescribir alertas con lista vacía sin mutar el dict original
            from dataclasses import replace
            export_data = replace(export_data, alerts=[])

        exporter = MarkdownExporter(template=MarkdownTemplate(
            include_metadata_block = False,
            alert_section_title    = "## Alertas Recientes" if include_alerts else "",
        ))
        result = exporter.export(export_data)
        mgr.close_session()

        disposition = "inline" if inline else "attachment"
        _logger.info(f"Quick MD export doc {doc_id} — user={get_current_username()}, inline={inline}, alerts={include_alerts}")

        return Response(
            result.content,
            mimetype = "text/markdown; charset=utf-8",
            headers  = {
                "Content-Disposition": f'{disposition}; filename="{result.filename}"',
                "Content-Length":      str(result.size_bytes),
            },
        )

    except Exception as exc:
        _logger.error(f"Error en quick MD export: {exc}", exc_info=True)
        err, code = create_error_response(ExceptionHandler.wrap_exception(exc, logger=_logger), include_debug_info=False)
        return jsonify(err), code