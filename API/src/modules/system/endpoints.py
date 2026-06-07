import uuid

import psutil

from flask_smorest import Blueprint as SmorestBlueprint
from flask import request
from marshmallow import ValidationError as MarshmallowValidationError

from src.modules.users.services.permissions import Role
from src.modules.shared._endpoints import limiter
from src.modules.shared._exceptions import (
    handle_exceptions,
    IllegalStateError,
    ValidationError,
)
from src.modules.shared.schemas import ErrorSchema
from src.modules.system.logging import SecOpsLogger
from src.modules.users import require_oauth_token, require_role
from src.modules.system.sequeue import SeQueue, SeQueueTask, SeQueueTaskStatus
from .schemas import (
    HelloResponseSchema,
    SystemStatusSchema,
    SeQueueTaskSchema,
    SeQueueStatusSchema,
    SeQueueConfigSchema,
    SeQueuePaginationQuerySchema,
)

import src.modules.system.config_reading as CR


system_blp = SmorestBlueprint(
    "system", __name__,
    description="Estado, configuración y health check del sistema"
)
_logger = SecOpsLogger("system").get_logger()


@system_blp.get("/say-hello")
@system_blp.response(200, HelloResponseSchema, description="Health check")
@limiter.limit("60 per minute")
def hello():
    """Health check del servicio"""
    _logger.info("GET /say-hello")
    return {
        "message": "You did it! You reached an endpoint!",
        "status":  "ok",
        "version": "3.2",
    }


@system_blp.get("/status")
@system_blp.response(200, SystemStatusSchema, description="System metrics")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def status():
    """Métricas en tiempo real del servidor (CPU, memoria, disco)"""
    _logger.info("GET /status")

    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    return {
        "cpu": {"percent": cpu_percent},
        "memory": {
            "total": memory.total,
            "available": memory.available,
            "percent": memory.percent,
            "used": memory.used,
            "free": memory.free,
        },
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent,
        },
        "status": "ok",
    }


@system_blp.get("")
@system_blp.response(200, description="Full SecOps configuration")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
@handle_exceptions(default_exception=IllegalStateError, logger=_logger)
def get_config():
    """Obtiene toda la configuración de SecOpsConfig.json"""
    config = CR.get_full_config()
    return config


@system_blp.put("")
@system_blp.response(200, description="Updated configuration")
@system_blp.alt_response(400, schema=ErrorSchema, description="Invalid body")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("10 per hour; 20 per day")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
@handle_exceptions(default_exception=IllegalStateError, logger=_logger)
def update_config():
    """Actualiza la configuración de SecOpsConfig.json"""
    if not request.is_json:
        raise ValidationError("Content-Type must be application/json")

    new_config = request.get_json(silent=True)
    if not new_config:
        raise ValidationError("Request body must be JSON")

    config = CR.save_full_config(new_config)
    _logger.info("Configuracion actualizada correctamente")
    return config


# =============================================================================
# SEQUEUE ENDPOINTS
# =============================================================================


@system_blp.get("/sequeue/status")
@system_blp.response(200, SeQueueStatusSchema, description="SeQueue status")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("60 per minute")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def sequeue_status():
    """Devuelve el estado global de la cola de tareas en segundo plano."""
    sequeue = SeQueue.get_instance()
    return sequeue.get_status()


@system_blp.get("/sequeue/tasks")
@system_blp.arguments(SeQueuePaginationQuerySchema, location="query")
@system_blp.response(200, SeQueueTaskSchema(many=True), description="SeQueue tasks")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("60 per minute")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def sequeue_tasks(query_args):
    """Lista las tareas de la cola con paginacion y filtros opcionales."""
    sequeue = SeQueue.get_instance()
    category = query_args.get("category")
    status = query_args.get("status")
    page = query_args.get("page", 1)
    per_page = query_args.get("per_page", 20)

    # Gather tasks based on status filter
    if status == "pending":
        tasks = sequeue.get_pending(category=category)
    elif status == "running":
        tasks = sequeue.get_running(category=category)
    elif status is not None:
        history = sequeue.get_history(category=category)
        tasks = [t for t in history if str(t.status) == status]
    else:
        tasks = (
            sequeue.get_pending(category=category)
            + sequeue.get_running(category=category)
            + sequeue.get_history(category=category)
        )

    start = (page - 1) * per_page
    return [t.to_dict() for t in tasks[start:start + per_page]]


@system_blp.get("/sequeue/tasks/<uuid:task_id>")
@system_blp.response(200, SeQueueTaskSchema, description="Task detail")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@system_blp.alt_response(404, schema=ErrorSchema, description="Task not found")
@limiter.limit("60 per minute")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def sequeue_task_detail(task_id):
    """Obtiene el detalle de una tarea especifica por su ID."""
    sequeue = SeQueue.get_instance()
    task = sequeue.get_task(task_id)
    if task is None:
        return {"error": "not_found", "error_description": "Task not found"}, 404
    return task.to_dict()


@system_blp.post("/sequeue/tasks/<uuid:task_id>/cancel")
@system_blp.response(200, SeQueueTaskSchema, description="Task cancelled")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@system_blp.alt_response(404, schema=ErrorSchema, description="Task not found")
@limiter.limit("30 per minute")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def sequeue_cancel_task(task_id):
    """Cancela una tarea, estando en espera o en ejecucion."""
    sequeue = SeQueue.get_instance()
    cancelled = sequeue.cancel(task_id)
    if not cancelled:
        return {"error": "not_found", "error_description": "Task not found or already finished"}, 404
    task = sequeue.get_task(task_id)
    return (task or SeQueueTask(id=task_id)).to_dict()


@system_blp.put("/sequeue/config")
@system_blp.arguments(SeQueueConfigSchema, location="json")
@system_blp.response(200, SeQueueStatusSchema, description="Updated SeQueue config")
@system_blp.alt_response(400, schema=ErrorSchema, description="Invalid body")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("10 per hour; 20 per day")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def sequeue_update_config(json_data):
    """Modifica el numero maximo de workers de la cola en runtime."""
    max_workers = json_data.get("max_workers")
    if not isinstance(max_workers, int) or max_workers < 1:
        raise ValidationError("max_workers must be a positive integer")

    sequeue = SeQueue.get_instance()
    sequeue.resize(max_workers)
    return sequeue.get_status()
