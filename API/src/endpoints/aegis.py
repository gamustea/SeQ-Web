"""
endpoints/aegis.py
──────────────────
Blueprint de generación de píldoras de concienciación (Aegis).
Registrado en /aegis.
 
Rutas:
  POST  /aegis/generate          — iniciar generación asíncrona
  GET   /aegis/status            — consultar estado de un documento
  GET   /aegis/document          — obtener contenido estructurado (JSON)
  GET   /aegis/download          — descargar el fichero generado (.json o .md legacy)
  DELETE /aegis/document         — eliminar un documento
  GET   /aegis/documents         — listar todos los documentos del usuario
 
Notas de retrocompatibilidad:
  - El endpoint /aegis/download_as_md se mantiene como alias de /aegis/download
    para no romper clientes existentes.
"""
 
from flask import Blueprint, jsonify, request, send_file
from src.core.exceptions import (
    ExceptionHandler,
    MissingParameterError,
    UserNotFoundError,
    ValidationError,
    create_error_response,
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
 
 
def _parse_doc_id(source: str = "args") -> int:
    """Extrae y valida el parámetro 'id' desde query string o JSON body."""
    raw = request.args.get("id") if source == "args" else (
        (request.get_json(silent=True) or {}).get("id")
    )
    if not raw:
        raise MissingParameterError("id")
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ValidationError(
            field="id",
            message="El ID debe ser un número entero",
            value=raw,
        )
 
def _doc_not_found(doc_id: int):
    return jsonify({
        "error":   "not_found",
        "message": f"Documento {doc_id} no encontrado",
    }), 404
 
def _doc_not_ready(doc_id: int, status: str):
    return jsonify({
        "error":   "not_ready",
        "message": f"El documento {doc_id} aún no está disponible (estado: {status})",
        "status":  status,
    }), 409
 
 
@aegis_bp.post("/generate")
@require_oauth_token
@limiter.limit("10 per hour; 30 per day")
def aegis_generate():
    """
    Inicia la generación asíncrona de una píldora Aegis.
    Devuelve 202 Accepted con el documentId para polling de estado.

    Body JSON:
        topicId  (int, requerido)  — ID del tema en la tabla Topic
        tweaks   (dict, opcional)  — personalizaciones:
            company, sector, audienceLevel, associatedBrands,
            mentionContact, language, tone, topicFocus
    """
    if not request.is_json:
        return jsonify({
            "error":             "invalid_request",
            "error_description": "Content-Type must be application/json",
        }), 400

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({
            "error":             "invalid_request",
            "error_description": "Request body must be a JSON object",
        }), 400

    topic_id_raw = data.get("topicId")
    if topic_id_raw is None:
        err, code = create_error_response(
            MissingParameterError("topicId"), include_debug_info=False
        )
        return jsonify(err), code

    try:
        topic_id = int(topic_id_raw)
    except (TypeError, ValueError):
        err, code = create_error_response(
            ValidationError(
                field="topicId",
                message="El topicId debe ser un número entero",
                value=topic_id_raw,
            ),
            include_debug_info=False,
        )
        return jsonify(err), code

    tweaks = data.get("tweaks") or {}
    if not isinstance(tweaks, dict):
        err, code = create_error_response(
            ValidationError(
                field="tweaks",
                message="tweaks debe ser un objeto JSON",
                value=str(type(tweaks)),
            ),
            include_debug_info=False,
        )
        return jsonify(err), code

    try:
        uid         = get_current_user_id()
        mgr         = get_aegis_manager(uid)
        document_id = mgr.generate(
            topic_id=topic_id, 
            tweaks=tweaks
        )
        mgr.close_session()

        _logger.info(
            f"Aegis generate lanzado — topicId={topic_id} "
            f"documentId={document_id} user={get_current_username()}"
            f"tweaks={tweaks}"
        )
        return jsonify({
            "message":    "Generación Aegis iniciada",
            "documentId": document_id,
            "status":     "pending",
            "tweaks": tweaks
        }), 202

    except (MissingParameterError, ValidationError, UserNotFoundError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en /aegis/generate: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code

@aegis_bp.get("/status")
@require_oauth_token
@limiter.limit("120 per hour; 500 per day")
def aegis_status():
    """
    Devuelve el estado de generación de un documento.
 
    Query params:
        id (int, requerido) — documentId devuelto por /generate
 
    Respuesta:
        {id, title, status, format, generatedAt, topicId}
    """
    try:
        doc_id = _parse_doc_id()
        uid    = get_current_user_id()
        mgr    = get_aegis_manager(uid)
 
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
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code

@aegis_bp.get("/document")
@require_oauth_token
@limiter.limit("60 per hour; 300 per day")
def aegis_get_document():
    """
    Devuelve el contenido estructurado de un documento 'done'.
 
    Query params:
        id (int, requerido) — documentId
 
    Respuesta (cuando status == 'done'):
        {
          id, title, status, format, generatedAt, topicId,
          pill: { subtitle, intro, tips:[{position,headline,body,links}], closing, contactEmail },
          alerts: [{position, source, sourceLabel, title, published, severity,
                    affectedBrands, description, url}]
        }
 
    Devuelve 409 si el documento no está en estado 'done'.
    """
    try:
        doc_id = _parse_doc_id()
        uid    = get_current_user_id()
        mgr    = get_aegis_manager(uid)
 
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
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code

@aegis_bp.get("/download")
@require_oauth_token
@limiter.limit("30 per hour; 100 per day")
def aegis_download():
    """
    Descarga el fichero generado (.json para documentos nuevos, .md para legacy).
 
    Query params:
        id (int, requerido) — documentId
 
    Devuelve el fichero con el Content-Type adecuado:
        application/json   para format='json'
        text/markdown      para format='md'  (retrocompatibilidad)
    """
    try:
        doc_id = _parse_doc_id()
        uid    = get_current_user_id()
        mgr    = get_aegis_manager(uid)
 
        # Obtener info para conocer el format antes de leer el path
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
            return jsonify({
                "error":   "not_found",
                "message": "El fichero del documento no está disponible en disco",
            }), 404
 
        mgr.close_session()
 
        doc_format = doc_info.get("format", "json")
        mimetype   = (
            "application/json"
            if doc_format == "json"
            else "text/markdown; charset=utf-8"
        )
 
        _logger.info(
            f"Descargando Aegis doc {doc_id} ({doc_format}) "
            f"— user={get_current_username()}"
        )
        return send_file(
            path,
            as_attachment=True,
            download_name=path.name,
            mimetype=mimetype,
        )
 
    except (MissingParameterError, ValidationError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en /aegis/download: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code

@aegis_bp.delete("/document")
@require_oauth_token
@limiter.limit("30 per hour; 100 per day")
def aegis_delete_document():
    """
    Elimina un documento Aegis (BD + fichero en disco).
 
    Query params:
        id (int, requerido) — documentId
    """
    try:
        doc_id = _parse_doc_id()
        uid    = get_current_user_id()
        mgr    = get_aegis_manager(uid)
 
        doc_info = mgr.get_document(doc_id)
        if not doc_info or doc_info.get("userId") != uid:
            mgr.close_session()
            return _doc_not_found(doc_id)
 
        mgr.delete_document(doc_id)
        # delete_document() llama a session.commit() internamente
 
        _logger.info(
            f"Aegis doc {doc_id} eliminado — user={get_current_username()}"
        )
        return jsonify({
            "message":    "Documento eliminado correctamente",
            "documentId": doc_id,
        }), 200
 
    except (MissingParameterError, ValidationError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except ValueError as exc:
        return jsonify({"error": "not_found", "message": str(exc)}), 404
    except Exception as exc:
        _logger.error(f"Error en DELETE /aegis/document: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code

@aegis_bp.get("/documents")
@require_oauth_token
@limiter.limit("60 per hour; 300 per day")
def aegis_list_documents():
    """
    Lista todos los documentos Aegis del usuario autenticado.

    Respuesta:
        { count, documents: [{id, title, filename, format, status, generatedAt, topicId}] }
    """
    try:
        uid  = get_current_user_id()
        mgr  = get_aegis_manager(uid)
        docs = mgr.list_documents()
        mgr.close_session()

        return jsonify({
            "count":     len(docs),
            "documents": docs,
        }), 200

    except Exception as exc:
        _logger.error(f"Error en /aegis/documents: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code

@aegis_bp.get("/topics")
@require_oauth_token
@limiter.limit("120 per hour; 600 per day")
def aegis_get_topics():
    """
    Devuelve la lista de temas disponibles para generar píldoras Aegis.
    Endpoint no registrado en el blueprint, pero puede ser utilizado internamente
    por el frontend para mostrar opciones al usuario.

    Respuesta:
        [{id, name, description}]
    """
    try:
        uid = get_current_user_id()
        manager = get_aegis_manager(uid)
        topics = manager.get_topics()
        manager.close_session()

        return jsonify(topics), 200

    except Exception as exc:
        _logger.error(f"Error en /aegis/topics: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code