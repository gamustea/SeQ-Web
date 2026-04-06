"""
endpoints/acheron.py
────────────────────
Blueprint de gestión de bóvedas (Acheron). Gestiona dos prefijos de URL:
  /acheron  — operaciones sobre Vaults
  /vaults   — operaciones sobre Storables individuales

Rutas:
  GET    /acheron/vault           — obtener vault del usuario
  POST   /acheron/vault           — crear/actualizar vault completo (upsert)
  PATCH  /acheron/storables       — actualizar bulk de Storables
  POST   /vaults/storables        — añadir un Storable al vault
  DELETE /vaults/storables        — eliminar un Storable del vault
"""

from __future__ import annotations

from datetime import datetime

from flask import Blueprint, jsonify, request

from src.core.exceptions import (
    ExceptionHandler,
    UserNotFoundError,
    ValidationError,
    create_error_response,
)
from src.misc import SecOpsLogger

from ._shared import (
    get_current_user_id,
    get_current_username,
    get_vault_manager,
    limiter,
    require_oauth_token,
)

acheron_bp = Blueprint("acheron", __name__)
_logger    = SecOpsLogger("acheron").get_logger()


# ═══════════════════════════════════════════════════════════════════════════════
# VAULT
# ═══════════════════════════════════════════════════════════════════════════════

@acheron_bp.get("/acheron/vault")
@require_oauth_token
@limiter.limit("120 per hour; 500 per day")
def get_vault():
    """Devuelve el vault del usuario en formato JSON."""
    try:
        uid         = get_current_user_id()
        is_recovery = _parse_is_recovery()
        mgr         = get_vault_manager(uid)
        vault       = mgr.get_vault_for_user(is_recovery=is_recovery)

        if not vault:
            return jsonify({"error": "not_found", "error_description": "Vault not found for current user", "isRecovery": is_recovery}), 404

        payload = mgr.export_vault_to_json(vault.id)
        _logger.info(f"Vault {vault.id} devuelto — user={get_current_username()}")
        return jsonify(payload), 200

    except UserNotFoundError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except PermissionError as exc:
        return jsonify({"error": "forbidden", "error_description": str(exc)}), 403
    except Exception as exc:
        _logger.error(f"Error en GET /acheron/vault: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@acheron_bp.post("/acheron/vault")
@require_oauth_token
@limiter.limit("60 per hour; 300 per day")
def upsert_vault():
    """Crea o reemplaza completamente el vault del usuario."""
    data = _require_json()
    if isinstance(data, tuple):
        return data

    try:
        uid         = get_current_user_id()
        is_recovery = _parse_is_recovery()
        mgr         = get_vault_manager(uid)
        vault, created = mgr.upsert_vault_from_json(data, is_recovery=is_recovery)

        _logger.info(f"Vault {'creado' if created else 'actualizado'} (ID={vault.id}) — user={get_current_username()}")
        return jsonify({"message": "Vault created" if created else "Vault updated", "vaultId": vault.id, "isRecovery": is_recovery}), 201 if created else 200

    except UserNotFoundError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except (KeyError, ValueError) as exc:
        return jsonify({"error": "invalid_request", "error_description": str(exc)}), 400
    except PermissionError as exc:
        return jsonify({"error": "forbidden", "error_description": str(exc)}), 403
    except Exception as exc:
        _logger.error(f"Error en POST /acheron/vault: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@acheron_bp.patch("/acheron/storables")
@require_oauth_token
@limiter.limit("60 per hour; 300 per day")
def patch_vault_storables():
    """Actualiza en bulk uno o varios Storables del usuario."""
    if not request.is_json:
        return jsonify({"error": "invalid_request", "error_description": "Content-Type must be application/json"}), 400

    data = request.get_json(silent=True)
    if not isinstance(data, list):
        err, code = create_error_response(
            ValidationError(field="body", message="Body must be a JSON array of operations", value=data),
            include_debug_info=False,
        )
        return jsonify(err), code

    try:
        uid     = get_current_user_id()
        mgr     = get_vault_manager(uid)
        results = mgr.bulk_update_storables(operations=data)
        _logger.info(f"Bulk update: {len(data)} operaciones — user={get_current_username()}")
        return jsonify({"message": "Bulk storable update completed", "results": results}), 200

    except UserNotFoundError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except ValidationError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en PATCH /acheron/storables: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


# ═══════════════════════════════════════════════════════════════════════════════
# STORABLES
# ═══════════════════════════════════════════════════════════════════════════════

@acheron_bp.post("/vaults/storables")
@require_oauth_token
@limiter.limit("60 per hour; 300 per day")
def add_vault_storable():
    """Añade un nuevo Account o CreditCard al vault del usuario."""
    data = _require_json()
    if isinstance(data, tuple):
        return data

    try:
        kind = data.get("kind")
        if kind not in ("account", "creditcard"):
            raise ValidationError(field="kind", message="kind must be 'account' or 'creditcard'", value=kind)

        uid         = get_current_user_id()
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

        mgr   = get_vault_manager(uid)
        vault = mgr.get_vault_for_user(is_recovery=is_recovery)
        if not vault:
            return jsonify({"error": "not_found", "error_description": "Vault not found for current user", "isRecovery": is_recovery}), 404

        if internal_id and mgr.get_storable_by(vault_id=vault.id, internal_id=internal_id):
            return jsonify({"error": "conflict", "error_description": f"Storable with internalId={internal_id} already exists", "internalId": internal_id, "vaultId": vault.id}), 409

        st = mgr.add_storable_to_vault(vault_id=vault.id, kind=kind, internal_id=internal_id, title=title, created_at=created_at, updated_at=updated_at, **payload)
        _logger.info(f"Storable {st.id} añadido al vault {vault.id} — user={get_current_username()}")
        return jsonify({"message": "Storable created", "storableId": st.id, "internalId": st.internal_id, "vaultId": st.vault_id, "isRecovery": is_recovery, "kind": kind}), 201

    except (UserNotFoundError, ValidationError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en POST /vaults/storables: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@acheron_bp.delete("/vaults/storables")
@require_oauth_token
@limiter.limit("60 per hour; 200 per day")
def delete_vault_storable():
    """Elimina un Storable del vault del usuario por su internalId."""
    data = _require_json()
    if isinstance(data, tuple):
        return data

    try:
        internal_id = data.get("internalId")
        if not internal_id:
            raise ValidationError(field="internalId", message="internalId is required", value=internal_id)

        uid         = get_current_user_id()
        is_recovery = bool(data.get("isRecovery", False))
        mgr         = get_vault_manager(uid)
        vault       = mgr.get_vault_for_user(is_recovery=is_recovery)

        if not vault:
            return jsonify({"error": "not_found", "error_description": "Vault not found", "isRecovery": is_recovery}), 404

        st = mgr.get_storable_by(vault_id=vault.id, internal_id=internal_id)
        if not st:
            return jsonify({"error": "not_found", "error_description": "Storable not found in this vault", "internalId": internal_id}), 404

        if not mgr.delete_storable(st.id):
            return jsonify({"error": "deletion_failed", "error_description": "Could not delete storable", "internalId": internal_id}), 500

        _logger.info(f"Storable {st.id} (internalId={internal_id}) eliminado — user={get_current_username()}")
        return jsonify({"message": "Storable deleted", "storableId": st.id, "internalId": internal_id, "vaultId": vault.id, "isRecovery": is_recovery}), 200

    except (UserNotFoundError, ValidationError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en DELETE /vaults/storables: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


# ── Helpers privados ──────────────────────────────────────────────────────────

def _require_json():
    if not request.is_json:
        return jsonify({"error": "invalid_request", "error_description": "Content-Type must be application/json"}), 400
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid_request", "error_description": "Request body must be JSON"}), 400
    return data


def _parse_is_recovery() -> bool:
    val = request.args.get("isRecovery", "false").lower()
    return val in ("true", "1", "yes")


def _parse_dt(value: str | None) -> datetime:
    if not value:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return datetime.utcnow()
