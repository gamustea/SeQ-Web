"""
acheron_endpoints.py
══════════════════════════════════════════════════════════════════════════════

Blueprint de gestión de bóvedas (Acheron). Gestiona dos prefijos de URL:
  /acheron  — operaciones sobre Vaults
  /vaults   — operaciones sobre Storables individuales

Este módulo proporciona endpoints para gestionar el vault del usuario,
incluyendo la creación, actualización, eliminación de storables (accounts
y credit cards) y operaciones de bulk.

────────────────────────────────────────────────────────────────────────────────
ENDPOINTS DISPONIBLES
────────────────────────────────────────────────────────────────────────────────

Vault
    GET    /acheron/vault           — Obtener vault del usuario
    POST   /acheron/vault           — Crear/actualizar vault completo (upsert)
    PATCH  /acheron/storables      — Actualizar bulk de Storables

Storables
    POST   /vaults/storables        — Añadir un Storable al vault
    DELETE /vaults/storables        — Eliminar un Storable del vault

────────────────────────────────────────────────────────────────────────────────
AUTENTICACIÓN
────────────────────────────────────────────────────────────────────────────────

Todos los endpoints requieren un token OAuth2 válido en el header:
    Authorization: Bearer <access_token>

Límites de tasa:
    • /acheron/vault (GET): 120/hour, 500/day
    • /acheron/vault (POST): 60/hour, 300/day
    • /acheron/storables: 60/hour, 300/day
    • /vaults/storables (POST): 60/hour, 300/day
    • /vaults/storables (DELETE): 60/hour, 200/day

────────────────────────────────────────────────────────────────────────────────
EJEMPLOS DE USO
────────────────────────────────────────────────────────────────────────────────

# Obtener vault
curl "https://api.example.com/acheron/vault" \\
     -H "Authorization: Bearer <token>"

# Crear vault
curl -X POST "https://api.example.com/acheron/vault" \\
     -H "Authorization: Bearer <token>" \\
     -H "Content-Type: application/json" \\
     -d '{...vault_json...}'

# Añadir account
curl -X POST "https://api.example.com/vaults/storables" \\
     -H "Authorization: Bearer <token>" \\
     -H "Content-Type: application/json" \\
     -d '{"kind": "account", "title": "Gmail", "username": "user", "password": "pass"}'

# Eliminar storable
curl -X DELETE "https://api.example.com/vaults/storables" \\
     -H "Authorization: Bearer <token>" \\
     -H "Content-Type: application/json" \\
     -d '{"internalId": "abc123"}'

────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

from datetime import datetime
from flask import Blueprint, jsonify, request
from contextlib import contextmanager

from src.modules.shared._exceptions import (
    handle_exceptions,
    ValidationError,
)
from src.modules.acheron.exceptions import VaultError, VaultNotFoundError, StorableConflictError
from src.modules.users.exceptions import UserNotFoundError
from src.modules.system.logging import SecOpsLogger
from src.modules.users import require_oauth_token, get_current_user
from src.modules.shared._endpoints import _get_limiter, require_json
from .managers import VaultManager

limiter = _get_limiter()

acheron_bp = Blueprint("acheron", __name__)
_logger    = SecOpsLogger("acheron").get_logger()


@contextmanager
def get_vault_manager():
    """
    TODO: REVISAR PARA SUSTITUIR POR UNA IMPLEMENTACIÓN MENOS VERBOSA
    Crea una instancia de VaultManager
    """
    yield VaultManager(get_current_user())

# ═══════════════════════════════════════════════════════════════════════════════
# VAULT
# ═══════════════════════════════════════════════════════════════════════════════

@acheron_bp.get("/acheron/vault")
@require_oauth_token
@limiter.limit("120 per hour; 500 per day")
@handle_exceptions(default_exception=VaultNotFoundError, logger=_logger)
def get_vault():
    """Devuelve el vault del usuario en formato JSON.

    Args (query params):
        recovery (bool, optional): Si true, devuelve el vault de recuperación.
            Por defecto false.

    Returns:
        200 — Vault del usuario en formato JSON.
        404 — Vault no encontrado.
        403 — Acceso denegado (recovery vault bloqueado).

    Example:
        curl "https://api.example.com/acheron/vault" \\
                -H "Authorization: Bearer <token>"

        # Obtener recovery vault
        curl "https://api.example.com/acheron/vault?recovery=true" \\
                -H "Authorization: Bearer <token>"
    """
    is_recovery = _parse_is_recovery()
    with get_vault_manager() as mgr:
        vault = mgr.get_vault_for_user(is_recovery=is_recovery)

        if not vault:
            return jsonify(
                {
                    "error": "not_found",
                    "error_description": "Vault not found for current user",
                    "isRecovery": is_recovery
                }
            ), 404

        payload = mgr.export_vault_to_json(vault.id)
    _logger.info(f"Vault {vault.id} devuelto — user={get_current_user().username}")
    return jsonify(payload), 200


@acheron_bp.post("/acheron/vault")
@require_oauth_token
@limiter.limit("60 per hour; 300 per day")
@require_json
@handle_exceptions(default_exception=VaultError, logger=_logger)
def upsert_vault(data):
    """Crea o reemplaza completamente el vault del usuario.
  
    Args (query params):
        recovery (bool, optional): Si true, opera sobre el vault de recuperación.

    Args (JSON body):
        Estructura completa del vault (storables, metadata, etc.).

    Returns:
        201 — Vault creado exitosamente.
            {"message": "Vault created", "vaultId": 1, "isRecovery": false}
        200 — Vault actualizado exitosamente.
            {"message": "Vault updated", "vaultId": 1, "isRecovery": false}
        400 — Error de validación en el JSON del vault.
        403 — Acceso denegado.

    Example:
        curl -X POST "https://api.example.com/acheron/vault" \\
             -H "Authorization: Bearer <token>" \\
             -H "Content-Type: application/json" \\
             -d '{...vault_json...}'
    """
    uid         = get_current_user().id
    is_recovery = _parse_is_recovery()
    with get_vault_manager() as mgr:
        vault, created = mgr.upsert_vault_from_json(data, is_recovery=is_recovery)

        _logger.info(f"Vault {'creado' if created else 'actualizado'} (ID={vault.id}) — user={get_current_user().username}")
    return jsonify({"message": "Vault created" if created else "Vault updated", "vaultId": vault.id, "isRecovery": is_recovery}), 201 if created else 200


@acheron_bp.patch("/acheron/storables")
@require_oauth_token
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=VaultError, logger=_logger)
def patch_vault_storables():
    """Actualiza en bulk uno o varios Storables del usuario.

    Args (JSON body):
        Array de operaciones de actualización.
        Cada operación debe contener: op, path, value.

    Returns:
        200 — Actualización completada.
            {"message": "Bulk storable update completed", "results": [...]}
        400 — Formato de operaciones inválido.

    Example:
        curl -X PATCH "https://api.example.com/acheron/storables" \\
             -H "Authorization: Bearer <token>" \\
             -H "Content-Type: application/json" \\
             -d '[
                 {"op": "update", "path": "/1/password", "value": "newpass"},
                 {"op": "delete", "path": "/2"}
               ]'
    """
    if not request.is_json:
        return jsonify({"error": "invalid_request", "error_description": "Content-Type must be application/json"}), 400

    data = request.get_json(silent=True)
    if not isinstance(data, list):
        raise ValidationError(field="body", message="Body must be a JSON array of operations", value=data)

    uid     = get_current_user().id
    with get_vault_manager() as mgr:
        results = mgr.bulk_update_storables(operations=data)
        _logger.info(f"Bulk update: {len(data)} operaciones — user={get_current_user().username}")
    return jsonify({"message": "Bulk storable update completed", "results": results}), 200


# ═══════════════════════════════════════════════════════════════════════════════
# STORABLES
# ═══════════════════════════════════════════════════════════════════════════════

@acheron_bp.post("/vaults/storables")
@require_oauth_token
@limiter.limit("60 per hour; 300 per day")
@require_json(["kind"])
@handle_exceptions(default_exception=VaultError, logger=_logger)
def add_vault_storable(data):
    """Añade un nuevo Account o CreditCard al vault del usuario.

    Args (JSON body):
        kind (str): "account" o "creditcard"
        title (str): Título del storable
        isRecovery (bool, optional): Si true, añade al vault de recuperación.
        
        Para account:
            username (str): Nombre de usuario
            domain (str): Dominio del servicio
            password (str): Contraseña
            internalId (str, optional): ID interno único
        
        Para creditcard:
            cardHolderName (str): Nombre del titular
            cardNumber (str): Número de tarjeta
            expirationDate (str): Fecha de expiración (MM/YY)
            postalCode (str): Código postal
            cvv (str): Código CVV

    Returns:
        201 — Storable criado.
            {"message": "Storable created", "storableId": 1, "internalId": "abc", ...}
        400 — Error de validación.
        409 — El internalId ya existe.

    Example:
        curl -X POST "https://api.example.com/vaults/storables" \\
             -H "Authorization: Bearer <token>" \\
             -H "Content-Type: application/json" \\
             -d '{
                 "kind": "account",
                 "title": "Gmail",
                 "username": "user@gmail.com",
                 "domain": "gmail.com",
                 "password": "mypassword"
               }'
    """
    kind = data.get("kind")
    if kind not in ("account", "creditcard"):
        raise ValidationError(field="kind", message="kind must be 'account' or 'creditcard'", value=kind)

    uid         = get_current_user().id
    is_recovery = bool(data.get("isRecovery", False))
    internal_id = data.get("internalId")
    title       = data.get("title")
    created_at  = _parse_dt(data.get("createdAt"))
    updated_at  = _parse_dt(data.get("updatedAt"))

    payload: dict = {}
    if kind == "account":
        payload = {"username": data.get("username", ""), "domain": data.get("domain", ""), "password": data.get("password", "")}
    else:
        payload = {"cardholder_name": data.get("cardHolderName", ""), "card_number": data.get("cardNumber", ""), "expiration_date": data.get("expirationDate", ""), "postal_code": data.get("postalCode", ""), "cvv": data.get("cvv", "")}

    with get_vault_manager() as mgr:
        vault = mgr.get_vault_for_user(is_recovery=is_recovery)
        if not vault:
            return jsonify({"error": "not_found", "error_description": "Vault not found for current user", "isRecovery": is_recovery}), 404

        if internal_id and mgr.get_storable_by(vault_id=vault.id, internal_id=internal_id):
            return jsonify({"error": "conflict", "error_description": f"Storable with internalId={internal_id} already exists", "internalId": internal_id, "vaultId": vault.id}), 409

        st = mgr.add_storable_to_vault(vault_id=vault.id, kind=kind, internal_id=internal_id, title=title, created_at=created_at, updated_at=updated_at, **payload)
    _logger.info(f"Storable {st.id} añadido al vault {vault.id} — user={get_current_user().username}")
    return jsonify({"message": "Storable created", "storableId": st.id, "internalId": st.internal_id, "vaultId": st.vault_id, "isRecovery": is_recovery, "kind": kind}), 201


@acheron_bp.delete("/vaults/storables")
@require_oauth_token
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=VaultError, logger=_logger)
def delete_vault_storable():
    """Elimina un Storable del vault del usuario por su internalId.

    Args (JSON body):
        internalId (str): ID interno del storable a eliminar.
        isRecovery (bool, optional): Si true, opera sobre el vault de recuperación.

    Returns:
        200 — Storable eliminado.
            {"message": "Storable deleted", "storableId": 1, "internalId": "abc", ...}
        400 — internalId faltante.
        404 — Storable no encontrado.

    Warning:
        Esta acción es irreversible.

    Example:
        curl -X DELETE "https://api.example.com/vaults/storables" \\
             -H "Authorization: Bearer <token>" \\
             -H "Content-Type: application/json" \\
             -d '{"internalId": "abc123"}'
    """
    data = require_json()
    if isinstance(data, tuple):
        return data

    internal_id = data.get("internalId")
    if not internal_id:
        raise ValidationError(field="internalId", message="internalId is required", value=internal_id)

    uid         = get_current_user().id
    is_recovery = bool(data.get("isRecovery", False))
    with get_vault_manager() as mgr:
        vault = mgr.get_vault_for_user(is_recovery=is_recovery)

        if not vault:
            return jsonify({"error": "not_found", "error_description": "Vault not found", "isRecovery": is_recovery}), 404

        st = mgr.get_storable_by(vault_id=vault.id, internal_id=internal_id)
        if not st:
            return jsonify({"error": "not_found", "error_description": "Storable not found in this vault", "internalId": internal_id}), 404

        if not mgr.delete_storable(st.id):
            return jsonify({"error": "deletion_failed", "error_description": "Could not delete storable", "internalId": internal_id}), 500

        _logger.info(f"Storable {st.id} (internalId={internal_id}) eliminado — user={get_current_user().username}")
    return jsonify({"message": "Storable deleted", "storableId": st.id, "internalId": internal_id, "vaultId": vault.id, "isRecovery": is_recovery}), 200


# ── Helpers privados ──────────────────────────────────────────────────────────

def require_json():
    """Extrae y valida el body JSON de la petición."""
    if not request.is_json:
        return jsonify({"error": "invalid_request", "error_description": "Content-Type must be application/json"}), 400
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid_request", "error_description": "Request body must be JSON"}), 400
    return data


def _parse_is_recovery() -> bool:
    """Extrae el parámetro 'isRecovery' de la query string."""
    val = request.args.get("isRecovery", "false").lower()
    return val in ("true", "1", "yes")


def _parse_dt(value: str | None) -> datetime:
    """Convierte un string ISO a datetime, o devuelve utcnow() si es inválido."""
    if not value:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return datetime.utcnow()
