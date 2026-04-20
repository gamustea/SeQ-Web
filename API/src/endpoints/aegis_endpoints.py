# src/endpoints/aegis.py
"""
aegis_endpoints.py
══════════════════════════════════════════════════════════════════════════════

Blueprint consolidado de generación y exportación de píldoras Aegis.
Registrado en /aegis.

Este módulo proporciona endpoints para crear, gestionar y exportar documentos
(Aegis Pills) generados por IA a partir de temas predefinidos.

────────────────────────────────────────────────────────────────────────────────
ENDPOINTS DISPONIBLES
────────────────────────────────────────────────────────────────────────────────

Generación
    POST /aegis/generate     — Iniciar generación asíncrona de una píldora
    GET  /aegis/status       — Consultar estado de generación

Gestión de Documentos
    GET  /aegis/document     — Obtener contenido estructurado (JSON)
    GET  /aegis/download    — Descargar archivo original (.json/.md)
    DELETE /aegis/document  — Eliminar documento
    GET  /aegis/documents   — Listar todos los documentos del usuario
    GET  /aegis/topics      — Listar temas disponibles

Exportación
    GET  /aegis/export/formats          — Listar formatos disponibles
    POST /aegis/export/<id>             — Exportar a formato específico
    GET  /aegis/export/<id>/download    — Descargar exportación
    GET  /aegis/export/md/<id>           — Exportación rápida a Markdown

────────────────────────────────────────────────────────────────────────────────
AUTENTICACIÓN
────────────────────────────────────────────────────────────────────────────────

Todos los endpoints requieren un token OAuth2 válido en el header:
    Authorization: Bearer <access_token>

Límites de tasa:
    • /generate: 10/hour, 30/day
    • /status: 120/hour, 500/day
    • /document: 60/hour, 300/day
    • /download: 30/hour, 100/day
    • /delete: 30/hour, 100/day
    • /documents: 60/hour, 300/day
    • /topics: 120/hour, 600/day

────────────────────────────────────────────────────────────────────────────────
EJEMPLOS DE USO
────────────────────────────────────────────────────────────────────────────────

# Iniciar generación de una píldora
curl -X POST https://api.example.com/aegis/generate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"topicId": 1, "tweaks": {}}'

# Consultar estado
curl "https://api.example.com/aegis/status?id=42" \
  -H "Authorization: Bearer <token>"

# Listar documentos
curl "https://api.example.com/aegis/documents" \
  -H "Authorization: Bearer <token>"

# Exportar a Markdown
curl -X POST "https://api.example.com/aegis/export/42" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"format": "md", "options": {"includeToc": true}}'

# Descargar exportación
curl "https://api.example.com/aegis/export/42/download?format=md" \
  -H "Authorization: Bearer <token>" -o export.md

────────────────────────────────────────────────────────────────────────────────
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
    HTMLExporter,
    get_exporter_for_format,
)
from src.misc import SecOpsLogger

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
    """Inicia la generación asíncrona de una píldora Aegis.

    Args (JSON body):
        topicId (int): ID del tema predefinido para generar la píldora.
        tweaks  (dict, optional): Personalización de la generación.

    Returns:
        202 — Generación iniciada.
            {
                "message": "Generación Aegis iniciada",
                "documentId": 42,
                "status": "pending"
            }
        400 — Error de validación (topicId faltante o inválido).
        429 — Límite de tasa alcanzado.

    Example:
        curl -X POST https://api.example.com/aegis/generate \\
             -H "Authorization: Bearer <token>" \\
             -H "Content-Type: application/json" \\
             -d '{"topicId": 1, "tweaks": {}}'

    Note:
        Este endpoint devuelve inmediatamente con un documentId.
        Usa /aegis/status?id=<documentId> para consultar el progreso.
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
        with get_aegis_manager(uid) as mgr:
            document_id = mgr.generate(topic_id=topic_id, tweaks=tweaks)

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
    """Devuelve el estado de generación de un documento.

    Args (query params):
        id (int): ID del documento a consultar.

    Returns:
        200 — Estado del documento.
            {
                "id": 42,
                "title": "Mi Documento",
                "status": "done",
                "format": "json",
                "generatedAt": "2026-04-11T10:00:00",
                "topicId": 1
            }
        400 — ID faltante o inválido.
        404 — Documento no encontrado.

    Example:
        curl "https://api.example.com/aegis/status?id=42" \\
             -H "Authorization: Bearer <token>"
    """
    try:
        doc_id   = _parse_doc_id()
        uid      = get_current_user_id()
        with get_aegis_manager(uid) as mgr:
            doc_info = mgr.get_document(doc_id)

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
    """Devuelve el contenido estructurado de un documento 'done'.

    Args (query params):
        id (int): ID del documento a obtener.

    Returns:
        200 — Contenido del documento (JSON estructurado).
        400 — ID faltante o inválido.
        404 — Documento no encontrado.
        409 — El documento aún no está listo (estado != 'done').

    Example:
        curl "https://api.example.com/aegis/document?id=42" \\
                -H "Authorization: Bearer <token>"
    """
    try:
        doc_id   = _parse_doc_id()
        uid      = get_current_user_id()
        with get_aegis_manager(uid) as mgr:
            doc_info = mgr.get_document(doc_id)

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
    """Descarga el archivo original generado (.json o .md).

    Args (query params):
        id (int): ID del documento a descargar.

    Returns:
        200 — Archivo como attachment.
        400 — ID faltante o inválido.
        404 — Documento no encontrado.
        409 — El documento aún no está listo.

    Note:
        Para exportaciones formateadas usar /aegis/export/.

    Example:
        curl "https://api.example.com/aegis/download?id=42" \\
                -H "Authorization: Bearer <token>" -o document.json
    Descarga el fichero original generado (.json).
    Para exportaciones formateadas usar /aegis/export/.
    """
    try:
        doc_id   = _parse_doc_id()
        uid      = get_current_user_id()
        with get_aegis_manager(uid) as mgr:
            doc_info = mgr.get_document(doc_id)

            if not doc_info or doc_info.get("userId") != uid:
                return _doc_not_found(doc_id)
            if doc_info["status"] != "done":
                return _doc_not_ready(doc_id, doc_info["status"])

            try:
                path = mgr.get_document_path(doc_id)
            except ValueError:
                return _doc_not_found(doc_id)
            except FileNotFoundError:
                return jsonify({"error": "not_found", "message": "El fiche" + "o del documento no est" + chr(0xe1) + " disponible en disco"}), 404

            doc_format = doc_info.get("format", "json")
            mimetype   = "application/json" if doc_format == "json" else "text/markdown; charset=utf-8"

            _logger.info(f"Descargando Aegis doc {doc_id} ({doc_format}) " + chr(0xe2) + " user={get_current_username()}")
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
    """
    Elimina un documento Aegis (BD + archivo en disco).

    Args (query params):
        id (int): ID del documento a eliminar.

    Returns:
        200 — Documento eliminado correctamente.
            {"message": "Documento eliminado correctamente", "documentId": 42}
        400 — ID faltante o inválido.
        404 — Documento no encontrado.

    Warning:
        Esta acción es irreversible.

    Example:
        curl -X DELETE "https://api.example.com/aegis/document?id=42" \\
             -H "Authorization: Bearer <token>"
    """
    try:
        doc_id   = _parse_doc_id()
        uid      = get_current_user_id()
        with get_aegis_manager(uid) as mgr:
            doc_info = mgr.get_document(doc_id)

            if not doc_info or doc_info.get("userId") != uid:
                return _doc_not_found(doc_id)

            mgr.delete_document(doc_id)

            _logger.info(f"Aegis doc {doc_id} eliminado para usuario {get_current_username()}")
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
    """Lista todos los documentos Aegis del usuario autenticado.

    Returns:
        200 — Lista de documentos.
            {
                "count": 5,
                "documents": [
                    {"id": 1, "title": "Doc 1", "status": "done", ...},
                    {"id": 2, "title": "Doc 2", "status": "pending", ...}
                ]
            }

    Example:
        curl "https://api.example.com/aegis/documents" \\
             -H "Authorization: Bearer <token>"
    """
    try:
        uid  = get_current_user_id()
        with get_aegis_manager(uid) as mgr:
            docs = mgr.list_documents()

        return jsonify({"count": len(docs), "documents": docs}), 200

    except Exception as exc:
        _logger.error(f"Error en /aegis/documents: {exc}", exc_info=True)
        err, code = create_error_response(ExceptionHandler.wrap_exception(exc, logger=_logger), include_debug_info=False)
        return jsonify(err), code


@aegis_bp.get("/topics")
@require_oauth_token
@limiter.limit("120 per hour; 600 per day")
def aegis_get_topics():
    """Devuelve la lista de temas disponibles para generar píldoras.

    Returns:
        200 — Lista de temas disponibles.
            {
                "topics": [
                    {"id": 1, "name": "Ciberseguridad", "description": "..."},
                    {"id": 2, "name": "RGPD", "description": "..."}
                ]
            }

    Example:
        curl "https://api.example.com/aegis/topics" \\
             -H "Authorization: Bearer <token>"
    """
    try:
        uid     = get_current_user_id()
        with get_aegis_manager(uid) as mgr:
            topics  = mgr.get_topics()

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
    """Lista todos los formatos de exportación disponibles.

    Returns:
        200 — Formatos disponibles.
            {
                "default": "md",
                "formats": [
                    {"id": "md", "name": "Markdown", "description": "..."},
                    {"id": "json", "name": "JSON", "description": "..."},
                    {"id": "pdf", "name": "PDF", "description": "...", "coming_soon": true},
                    {"id": "html", "name": "HTML", "description": "...", "coming_soon": true}
                ]
            }

    Example:
        curl "https://api.example.com/aegis/export/formats" \\
             -H "Authorization: Bearer <token>"
    """
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
    """Exporta un documento Aegis al formato solicitado.

    Args (path):
        doc_id (int): ID del documento a exportar.

    Args (JSON body):
        format  (str): "md" o "json" (por defecto "md")
        options (dict): includeToc (bool), includeMetadata (bool)

    Returns:
        200 — Exportación completada.
            {
                "success": true,
                "export": {...},
                "document": {...},
                "downloadUrl": "/aegis/export/42/download?format=md"
            }
        400 — Formato no soportado o body inválido.
        404 — Documento no encontrado.
        409 — El documento aún no está listo.

    Example:
        curl -X POST "https://api.example.com/aegis/export/42" \\
             -H "Authorization: Bearer <token>" \\
             -H "Content-Type: application/json" \\
             -d '{"format": "md", "options": {"includeToc": true}}'
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
            return jsonify({"error": "unsupported_format", "message": f"Formato '{format_str}' no soportado", "supported": ["md", "json", "html"]}), 400

        uid = get_current_user_id()

        with get_aegis_manager(uid) as mgr:
            try:
                doc_info = _get_document_checked(mgr, doc_id, uid)
            except ValueError:
                return jsonify({"error": "not_found", "message": f"Documento {doc_id} no encontrado"}), 404
            except PermissionError as exc:
                return jsonify({"error": "not_ready", "message": str(exc)}), 409

            export_data = ExportData.from_document_dict(doc_info, doc_id)

            if export_format == ExportFormat.MARKDOWN:
                exporter = MarkdownExporter(template=MarkdownTemplate(
                    include_toc            = options.get("includeToc",   False),
                    include_metadata_block = options.get("includeMetadata", True),
                ))
            elif export_format == ExportFormat.JSON:
                exporter = JsonExporter()
            else:
                exporter = get_exporter_for_format(export_format)

            result = exporter.export(export_data)

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
    """Descarga una exportación previamente generada.

    Args (path):
        doc_id (int): ID del documento exportado.

    Args (query params):
        format (str): "md" o "json" (por defecto "md")
        inline (bool): mostrar en navegador en lugar de descargar

    Returns:
        200 — Archivo exportado como attachment o inline.
        400 — Formato no soportado.
        404 — Documento no encontrado.
        409 — El documento aún no está listo.

    Example:
        # Descargar como archivo
        curl "https://api.example.com/aegis/export/42/download?format=md" \\
             -H "Authorization: Bearer <token>" -o export.md

        # Ver en navegador
        curl "https://api.example.com/aegis/export/42/download?format=md&inline=true" \\
             -H "Authorization: Bearer <token>"
    """
    try:
        format_str    = request.args.get("format", "md")
        inline        = request.args.get("inline", "false").lower() == "true"

        try:
            export_format = ExportFormat(format_str.lower())
        except ValueError:
            return jsonify({"error": "unsupported_format", "message": f"Formato '{format_str}' no soportado"}), 400

        uid = get_current_user_id()

        with get_aegis_manager(uid) as mgr:
            try:
                doc_info = _get_document_checked(mgr, doc_id, uid)
            except ValueError:
                return jsonify({"error": "not_found", "message": f"Documento {doc_id} no encontrado"}), 404
            except PermissionError as exc:
                return jsonify({"error": "not_ready", "message": str(exc)}), 409

            export_data = ExportData.from_document_dict(doc_info, doc_id)
            exporter    = get_exporter_for_format(export_format)
            result      = exporter.export(export_data)

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
    """Exportación rápida a Markdown.

    Equivale a /export/<id>/download?format=md pero con opciones adicionales
    para controlar el contenido.

    Args (path):
        doc_id (int): ID del documento a exportar.

    Args (query params):
        inline   (bool): mostrar en navegador (true) o descargar (false)
        noAlerts (bool): excluir la sección de alertas (true) o incluirla (false)

    Returns:
        200 — Documento Markdown.
        404 — Documento no encontrado.
        409 — El documento aún no está listo.

    Example:
        # Ver en navegador
        curl "https://api.example.com/aegis/export/md/42?inline=true" \\
             -H "Authorization: Bearer <token>"

        # Descargar sin alertas
        curl "https://api.example.com/aegis/export/md/42?noAlerts=true" \\
             -H "Authorization: Bearer <token>" -o export.md
    """
    try:
        inline         = request.args.get("inline",   "false").lower() == "true"
        include_alerts = request.args.get("noAlerts", "false").lower() != "true"

        uid = get_current_user_id()

        with get_aegis_manager(uid) as mgr:
            try:
                doc_info = _get_document_checked(mgr, doc_id, uid)
            except ValueError:
                return jsonify({"error": "not_found", "message": f"Documento {doc_id} no encontrado"}), 404
            except PermissionError as exc:
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