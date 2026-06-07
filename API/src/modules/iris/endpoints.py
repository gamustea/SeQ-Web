"""
Iris REST API endpoints for email header analysis.

Provides:
- POST /iris/analyze         — submit headers for analysis
- GET  /iris/status?id=...   — check analysis status/progress
- GET  /iris/results         — list all analyses for the current user
- GET  /iris/results/{id}    — full analysis report
- POST /iris/analyze/{id}/cancel — cancel a running analysis
- DELETE /iris/results/{id}  — delete an analysis
"""

from __future__ import annotations

from flask_smorest import Blueprint as SmorestBlueprint

from src.modules.users import (
    require_oauth_token,
    require_attributes,
    AttributeType,
    get_current_user,
)
from src.modules.shared import handle_exceptions, limiter
from src.modules.shared.schemas import ErrorSchema

from .managers import IrisManager
from .exceptions import (
    IrisAnalysisNotFoundError,
    IrisAnalysisNotReadyError,
    IrisExecutionError,
    IrisInvalidStateError,
)
from .schemas import (
    AnalysisIdQuerySchema,
    AnalyzeRequestSchema,
    AnalyzeResponseSchema,
    AnalysisStatusResponseSchema,
    AnalysisDetailResponseSchema,
    AnalysisListResponseSchema,
    AnalysisDeleteResponseSchema,
    AnalysisCancelResponseSchema,
    ResultsQuerySchema,
)
from src.modules.system import SecOpsLogger


iris_blp = SmorestBlueprint(
    "iris", __name__,
    description="Analisis de cabeceras de correo electronico (anti-phishing)"
)

_logger = SecOpsLogger("IrisAPI").get_logger()

CANCELLABLE_STATES = frozenset({"pending", "running"})


@iris_blp.post("/analyze")
@iris_blp.arguments(AnalyzeRequestSchema)
@iris_blp.response(201, AnalyzeResponseSchema, description="Analysis started")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_CREATE])
@limiter.limit("20 per hour; 100 per day")
@handle_exceptions(default_exception=IrisExecutionError, logger=_logger)
def analyze_headers(data: dict):
    """Enviar cabeceras de correo para un analisis anti-phishing"""
    raw_headers = data["headers"]
    user = get_current_user()

    manager = IrisManager()
    analysis_id = manager.analyze(raw_headers, user.id)

    _logger.info(f"Iris analysis {analysis_id} started by user {user.username}")
    return {
        "message": "Analisis de cabeceras iniciado correctamente",
        "analysisId": analysis_id,
        "status": "pending",
    }


@iris_blp.get("/status")
@iris_blp.arguments(AnalysisIdQuerySchema, location="query")
@iris_blp.response(200, AnalysisStatusResponseSchema, description="Analysis status")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=_logger)
def get_analysis_status(args: dict):
    """Estado y progreso de un analisis"""
    analysis_id = args["id"]
    user = get_current_user()

    manager = IrisManager()
    IrisManager.assert_analysis_ownership(analysis_id, user.id)

    status = manager.get_analysis_status(analysis_id)
    progress = manager.get_analysis_progress(analysis_id)
    analysis = manager.get_analysis(analysis_id)

    response = {
        "analysisId": analysis_id,
        "status": status,
        "totalScore": analysis.total_score if analysis else None,
        "verdict": analysis.verdict if analysis else None,
    }
    if progress is not None:
        response["progress"] = progress

    return response


@iris_blp.get("/results")
@iris_blp.arguments(ResultsQuerySchema, location="query")
@iris_blp.response(200, AnalysisListResponseSchema, description="List of analyses")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=_logger)
def list_analyses(args):
    """Listar todos los analisis del usuario con paginacion"""
    page = args["page"]
    per_page = args["per_page"]
    user = get_current_user()

    manager = IrisManager()
    results, total = manager.get_analyses_for_user(user.id, page, per_page)
    total_pages = (total + per_page - 1) // per_page

    return {
        "analyses": results,
        "total": total,
        "page": page,
        "perPage": per_page,
    }


@iris_blp.get("/results/<int:analysis_id>")
@iris_blp.response(200, AnalysisDetailResponseSchema, description="Full analysis report")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@iris_blp.alt_response(409, schema=ErrorSchema, description="Analysis not ready")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=_logger)
def get_analysis_result(analysis_id: int):
    """Informe completo de un analisis"""
    user = get_current_user()

    manager = IrisManager()
    IrisManager.assert_analysis_ownership(analysis_id, user.id)

    result = manager.get_analysis_results(analysis_id)
    return result


@iris_blp.post("/analyze/<int:analysis_id>/cancel")
@iris_blp.response(200, AnalysisCancelResponseSchema, description="Analysis cancelled")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Invalid state")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=_logger)
def cancel_analysis(analysis_id: int):
    """Cancelar un analisis en curso"""
    user = get_current_user()

    manager = IrisManager()
    IrisManager.assert_analysis_ownership(analysis_id, user.id)

    if not manager.cancel_analysis(analysis_id, user.id):
        raise IrisExecutionError("No se pudo cancelar el analisis")

    analysis = manager.get_analysis(analysis_id)
    _logger.info(f"Analysis {analysis_id} cancelled by user {user.username}")
    return {
        "message": "Analisis cancelado exitosamente",
        "analysisId": analysis_id,
        "status": analysis.status if analysis else "cancelled",
    }


@iris_blp.delete("/results/<int:analysis_id>")
@iris_blp.response(200, AnalysisDeleteResponseSchema, description="Analysis deleted")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=_logger)
def delete_analysis(analysis_id: int):
    """Eliminar un analisis del sistema"""
    user = get_current_user()

    manager = IrisManager()
    IrisManager.assert_analysis_ownership(analysis_id, user.id)

    if not manager.delete_analysis(analysis_id):
        raise IrisExecutionError("No se pudo eliminar el analisis")

    _logger.info(f"Analysis {analysis_id} deleted by user {user.username}")
    return {
        "message": "Analisis eliminado correctamente",
        "analysisId": analysis_id,
    }
