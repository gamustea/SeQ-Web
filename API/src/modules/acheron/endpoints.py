from __future__ import annotations

from datetime import datetime
from flask import jsonify, request
from flask_smorest import Blueprint as SmorestBlueprint
from contextlib import contextmanager

from src.modules.shared._exceptions import (
    handle_exceptions,
)
from src.modules.shared._endpoints import limiter
from src.modules.shared.schemas import ErrorSchema
from src.modules.acheron.exceptions import VaultError, VaultNotFoundError
from src.modules.system.logging import SecOpsLogger
from src.modules.users import require_oauth_token, require_attributes, AttributeType, get_current_user
from .managers import VaultManager
from .schemas import (
    IsRecoveryQuerySchema,
    StorableCreateSchema,
    StorableDeleteSchema,
    BulkOperationSchema,
    VaultUpsertResponseSchema,
    StorableResponseSchema,
    BulkUpdateResponseSchema,
)


acheron_blp = SmorestBlueprint(
    "acheron", __name__,
    description="Gestion de vaults y secretos (Acheron)"
)
_logger = SecOpsLogger("acheron").get_logger()


@contextmanager
def get_vault_manager():
    yield VaultManager(get_current_user())


@acheron_blp.get("/acheron/vault")
@acheron_blp.arguments(IsRecoveryQuerySchema, location="query", as_kwargs=True)
@acheron_blp.response(200, description="Vault del usuario en formato JSON")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(404, schema=ErrorSchema, description="Vault not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_READ])
@limiter.limit("120 per hour; 500 per day")
@handle_exceptions(default_exception=VaultNotFoundError, logger=_logger)
def get_vault(**kwargs):
    """Obtener el vault del usuario en formato JSON"""
    is_recovery = kwargs.get("isRecovery", False)
    with get_vault_manager() as mgr:
        vault = mgr.get_vault_for_user(is_recovery=is_recovery)

        if not vault:
            return jsonify({
                "error": "not_found",
                "error_description": "Vault not found for current user",
                "isRecovery": is_recovery,
            }), 404

        payload = mgr.export_vault_to_json(vault.id)
    _logger.info(f"Vault {vault.id} devuelto -- user={get_current_user().username}")
    return payload


@acheron_blp.post("/acheron/vault")
@acheron_blp.arguments(IsRecoveryQuerySchema, location="query", as_kwargs=True)
@acheron_blp.response(201, VaultUpsertResponseSchema, description="Vault created")
@acheron_blp.alt_response(200, schema=VaultUpsertResponseSchema, description="Vault updated")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Invalid body")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_CREATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=VaultError, logger=_logger)
def upsert_vault(**kwargs):
    """Crear o reemplazar completamente el vault del usuario"""
    uid = get_current_user().id
    is_recovery = kwargs.get("isRecovery", False)

    if not request.is_json:
        return jsonify({
            "error": "invalid_request",
            "error_description": "Content-Type must be application/json",
        }), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({
            "error": "invalid_request",
            "error_description": "Request body must be a JSON object",
        }), 400

    with get_vault_manager() as mgr:
        vault, created = mgr.upsert_vault_from_json(data, is_recovery=is_recovery)
        _logger.info(f"Vault {'creado' if created else 'actualizado'} (ID={vault.id}) -- user={get_current_user().username}")
    return jsonify({
        "message": "Vault created" if created else "Vault updated",
        "vaultId": vault.id,
        "isRecovery": is_recovery,
    }), 201 if created else 200


@acheron_blp.patch("/acheron/storables")
@acheron_blp.arguments(BulkOperationSchema(many=True))
@acheron_blp.response(200, BulkUpdateResponseSchema, description="Bulk update completed")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Invalid body")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_UPDATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=VaultError, logger=_logger)
def patch_vault_storables(data):
    """Actualizar en bulk uno o varios Storables del usuario (array de operaciones)"""
    uid = get_current_user().id
    with get_vault_manager() as mgr:
        results = mgr.bulk_update_storables(operations=data)
        _logger.info(f"Bulk update: {len(data)} operaciones -- user={get_current_user().username}")
    return {"message": "Bulk storable update completed", "results": results}


@acheron_blp.post("/vaults/storables")
@acheron_blp.arguments(StorableCreateSchema)
@acheron_blp.response(201, StorableResponseSchema, description="Storable created")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(404, schema=ErrorSchema, description="Vault not found")
@acheron_blp.alt_response(409, schema=ErrorSchema, description="internalId already exists")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_CREATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=VaultError, logger=_logger)
def add_vault_storable(data):
    """Anadir un nuevo Account o CreditCard al vault del usuario"""
    kind = data["kind"]

    uid = get_current_user().id
    is_recovery = data.get("isRecovery", False)
    internal_id = data.get("internalId")
    title = data.get("title")
    created_at = _parse_dt(data.get("createdAt"))
    updated_at = _parse_dt(data.get("updatedAt"))

    payload = {}
    if kind == "account":
        payload = {
            "username": data.get("username", ""),
            "domain": data.get("domain", ""),
            "password": data.get("password", ""),
        }
    else:
        payload = {
            "cardholder_name": data.get("cardHolderName", ""),
            "card_number": data.get("cardNumber", ""),
            "expiration_date": data.get("expirationDate", ""),
            "postal_code": data.get("postalCode", ""),
            "cvv": data.get("cvv", ""),
        }

    with get_vault_manager() as mgr:
        vault = mgr.get_vault_for_user(is_recovery=is_recovery)
        if not vault:
            return jsonify({
                "error": "not_found",
                "error_description": "Vault not found for current user",
                "isRecovery": is_recovery,
            }), 404

        if internal_id and mgr.get_storable_by(vault_id=vault.id, internal_id=internal_id):
            return jsonify({
                "error": "conflict",
                "error_description": f"Storable with internalId={internal_id} already exists",
                "internalId": internal_id,
                "vaultId": vault.id,
            }), 409

        st = mgr.add_storable_to_vault(
            vault_id=vault.id, kind=kind, internal_id=internal_id,
            title=title, created_at=created_at, updated_at=updated_at,
            **payload,
        )
    _logger.info(f"Storable {st.id} anadido al vault {vault.id} -- user={get_current_user().username}")
    return jsonify({
        "message": "Storable created",
        "storableId": st.id,
        "internalId": st.internal_id,
        "vaultId": st.vault_id,
        "isRecovery": is_recovery,
        "kind": kind,
    }), 201


@acheron_blp.delete("/vaults/storables")
@acheron_blp.arguments(StorableDeleteSchema)
@acheron_blp.response(200, StorableResponseSchema, description="Storable deleted")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Missing internalId")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(404, schema=ErrorSchema, description="Storable not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=VaultError, logger=_logger)
def delete_vault_storable(data):
    """Eliminar un Storable del vault por su internalId"""
    internal_id = data["internalId"]

    uid = get_current_user().id
    is_recovery = data.get("isRecovery", False)
    with get_vault_manager() as mgr:
        vault = mgr.get_vault_for_user(is_recovery=is_recovery)

        if not vault:
            return jsonify({
                "error": "not_found",
                "error_description": "Vault not found",
                "isRecovery": is_recovery,
            }), 404

        st = mgr.get_storable_by(vault_id=vault.id, internal_id=internal_id)
        if not st:
            return jsonify({
                "error": "not_found",
                "error_description": "Storable not found in this vault",
                "internalId": internal_id,
            }), 404

        if not mgr.delete_storable(st.id):
            return jsonify({
                "error": "deletion_failed",
                "error_description": "Could not delete storable",
                "internalId": internal_id,
            }), 500

        _logger.info(f"Storable {st.id} (internalId={internal_id}) eliminado -- user={get_current_user().username}")
    return jsonify({
        "message": "Storable deleted",
        "storableId": st.id,
        "internalId": internal_id,
        "vaultId": vault.id,
        "isRecovery": is_recovery,
    }), 200


def _parse_is_recovery() -> bool:
    val = request.args.get("isRecovery", "false").lower()
    return val in ("true", "1", "yes")


def _parse_dt(value):
    if not value:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return datetime.utcnow()
