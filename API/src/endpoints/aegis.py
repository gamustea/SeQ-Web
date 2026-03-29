"""
endpoints/aegis.py
──────────────────
Blueprint de generación de newsletters de ciberseguridad (Aegis).
Registrado en /aegis.

Rutas:
  POST  /aegis/generate          — iniciar generación asíncrona de una píldora
  GET   /aegis/status            — consultar estado de una píldora
  GET   /aegis/download_as_md    — descargar la píldora en Markdown
"""

from flask import Blueprint, jsonify, request, send_file
from werkzeug.exceptions import BadRequest

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
    require_oauth_token,
)

aegis_bp = Blueprint("aegis", __name__)
_logger  = SecOpsLogger("aegis").get_logger()


# ── POST /aegis/generate ──────────────────────────────────────────────────────

@aegis_bp.post("/generate")
@require_oauth_token
def aegis_generate():
    """
    Inicia la generación asíncrona de una píldora Aegis.
    Devuelve 202 Accepted con el documentId para consultar el estado.
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
        err, code = create_error_response(ValidationError(field="topicId", message="El topicId debe ser un número entero", value=topic_id_raw), include_debug_info=False)
        return jsonify(err), code

    tweaks = data.get("tweaks") or {}
    if not isinstance(tweaks, dict):
        err, code = create_error_response(ValidationError(field="tweaks", message="tweaks debe ser un objeto JSON", value=str(type(tweaks))), include_debug_info=False)
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
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


# ── GET /aegis/status ─────────────────────────────────────────────────────────

@aegis_bp.get("/status")
@require_oauth_token
def aegis_status():
    """Devuelve el estado de generación de una píldora por su documentId."""
    doc_id_str = request.args.get("id")
    if not doc_id_str:
        err, code = create_error_response(MissingParameterError("id"), include_debug_info=False)
        return jsonify(err), code

    try:
        doc_id = int(doc_id_str)
    except ValueError:
        err, code = create_error_response(ValidationError(field="id", message="El ID debe ser un número entero", value=doc_id_str), include_debug_info=False)
        return jsonify(err), code

    try:
        uid      = get_current_user_id()
        mgr      = get_aegis_manager(uid)
        doc_info = mgr.get_document(doc_id)
        mgr.close_session()

        if not doc_info or doc_info.get("userId") != uid:
            return jsonify({"error": "not_found", "message": f"Documento {doc_id} no encontrado"}), 404

        return jsonify({
            "id":          doc_info["id"],
            "title":       doc_info["title"],
            "status":      doc_info["status"],
            "generatedAt": doc_info["generatedAt"],
            "topicId":     doc_info["topicId"],
        }), 200

    except (MissingParameterError, ValidationError, UserNotFoundError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en /aegis/status: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


# ── GET /aegis/download_as_md ─────────────────────────────────────────────────

@aegis_bp.get("/download_as_md")
@require_oauth_token
def aegis_download_as_md():
    """Descarga una píldora generada como fichero Markdown."""
    doc_id_str = request.args.get("id")
    if not doc_id_str:
        err, code = create_error_response(MissingParameterError("id"), include_debug_info=False)
        return jsonify(err), code

    try:
        doc_id = int(doc_id_str)
    except ValueError:
        err, code = create_error_response(ValidationError(field="id", message="El ID debe ser un número entero", value=doc_id_str), include_debug_info=False)
        return jsonify(err), code

    try:
        uid = get_current_user_id()
        mgr = get_aegis_manager(uid)

        try:
            path = mgr.get_document_path(doc_id)
        except ValueError:
            mgr.close_session()
            return jsonify({"error": "not_found", "message": f"Documento {doc_id} no encontrado"}), 404
        except FileNotFoundError:
            mgr.close_session()
            return jsonify({"error": "not_found", "message": "El fichero del documento no está disponible"}), 404

        mgr.close_session()
        _logger.info(f"Descargando Aegis doc {doc_id} — user={get_current_username()}")
        return send_file(path, as_attachment=True, download_name=path.name, mimetype="text/markdown; charset=utf-8")

    except (MissingParameterError, ValidationError, UserNotFoundError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en /aegis/download_as_md: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code
