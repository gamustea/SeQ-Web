"""
endpoints/_shared.py
────────────────────
Utilidades compartidas por todos los blueprints:
  - Decorador de autenticación OAuth (require_oauth_token)
  - Helpers de acceso al usuario actual
  - Factoría de managers (DRY)
  - Función auxiliar de búsqueda de escaneos por ID
  - Constantes de validación centralizadas
  - Helper de construcción del PDFCreator
"""

from __future__ import annotations

import os
from functools import wraps
from typing import Optional, Tuple, Any

from flask import request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from src.core.exceptions import (
    ScanNotFoundError,
    UserNotFoundError,
    ValidationError,
    create_error_response,
)
from src.core.model import Scan
from src.logic.documents import PDFCreator, NmapPrintingStrategy, NiktoPrintingStrategy, OpenVASPrintingStrategy
from src.logic.managers import (
    AegisManager,
    NmapScanManager,
    NiktoScanManager,
    OAuthTokenManager,
    OpenVASScanManager,
    UserManager,
    VaultManager,
)
from src.misc import SecOpsLogger

_logger = SecOpsLogger(name="API").get_logger()

# Único Limiter de la aplicación. Se asocia a la app Flask mediante
# init_app(app) desde run.py (patrón Application Factory).
# default_limits=[] significa que no hay límite global automático;
# cada ruta define el suyo propio con @limiter.limit(...).
limiter = Limiter(
    get_remote_address,
    default_limits=[],
    storage_uri="memory://",
)


CANCELLABLE_STATES    = frozenset({"pending", "running"})
VALID_SCAN_TYPES      = frozenset({"nmap", "nikto", "openvas", "all"})
VALID_OPENVAS_CONFIGS = frozenset({"full_fast", "full_deep", "full_ultimate"})
MAX_PDF_SIZE_BYTES    = 50 * 1024 * 1024  # 50 MB

def get_current_user_id() -> int:
    return request.current_user_id  # type: ignore[attr-defined]

def get_current_username() -> str:
    return request.current_username  # type: ignore[attr-defined]

def require_oauth_token(f):
    """
    Verifica el Bearer token en la cabecera Authorization.

    Inyecta `request.current_user_id` y `request.current_username`
    para que los handlers downstream los lean sin tocar la BD.
    Cierra siempre la sesión del OAuthTokenManager en un bloque
    finally para que la conexión se devuelva al pool aunque ocurra
    una excepción durante la verificación.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        oauth_manager = None
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                return jsonify({
                    "error": "unauthorized",
                    "error_description": "Missing Authorization header",
                }), 401

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return jsonify({
                    "error": "unauthorized",
                    "error_description": "Invalid Authorization header format. Use: Bearer <token>",
                }), 401

            token = parts[1]
            oauth_manager = _get_oauth_manager()
            payload = oauth_manager.verify_access_token(token)

            if not payload:
                return jsonify({
                    "error": "invalid_token",
                    "error_description": "The access token is invalid or expired",
                }), 401

            request.current_user_id = int(payload["sub"])   # type: ignore[attr-defined]
            request.current_username = payload["username"]  # type: ignore[attr-defined]

            _logger.info(
                f"Autenticado vía OAuth: {payload['username']} (ID: {payload['sub']})"
            )
            return f(*args, **kwargs)

        except Exception as exc:
            _logger.error(f"Error en autenticación OAuth: {exc}", exc_info=True)
            return jsonify({
                "error": "server_error",
                "error_description": "Authentication error",
            }), 500
        finally:
            if oauth_manager is not None:
                try:
                    oauth_manager.close_session()
                except Exception:
                    pass

    return decorated

def _get_user_manager() -> UserManager:
    return UserManager()

def _get_oauth_manager() -> OAuthTokenManager:
    return OAuthTokenManager()

def get_user_managers(
    user_id: int,
) -> Tuple[NmapScanManager, NiktoScanManager, OpenVASScanManager]:
    """
    Crea los tres managers de escaneo para el usuario indicado.
    El UserManager auxiliar se cierra en un finally para garantizar
    que su conexión vuelve al pool aunque get_user_by_id lance.
    """
    um = _get_user_manager()
    try:
        user = um.get_user_by_id(user_id)
    finally:
        um.close_session()
    nmap    = NmapScanManager(user)
    nikto   = NiktoScanManager(user)
    openvas = OpenVASScanManager(user)
    return nmap, nikto, openvas

def get_vault_manager(user_id: int) -> VaultManager:
    um = _get_user_manager()
    try:
        user = um.get_user_by_id(user_id)
    finally:
        um.close_session()
    if not user:
        raise UserNotFoundError(user_id=user_id)
    return VaultManager(user)

def get_aegis_manager(user_id: int) -> AegisManager:
    um = _get_user_manager()
    try:
        user = um.get_user_by_id(user_id)
    finally:
        um.close_session()
    if not user:
        raise UserNotFoundError(user_id=user_id)
    return AegisManager(user)

get_user_manager  = _get_user_manager
get_oauth_manager = _get_oauth_manager

def get_scan_by_id_for_user(
    scan_id: int,
    nmap_manager:    NmapScanManager,
    nikto_manager:   NiktoScanManager,
    openvas_manager: OpenVASScanManager,
) -> Tuple[Optional[Scan], str]:
    """
    Busca un escaneo entre los tres tipos. Devuelve (scan, tipo) o (None, '').
    El tipo es 'nmap', 'nikto' u 'openvas'.
    """
    scan = nmap_manager.get_scan_by_id(scan_id)
    if scan:
        return scan, scan.scan_type

def resolve_manager(
    scan_type: str,
    nmap_manager:    NmapScanManager,
    nikto_manager:   NiktoScanManager,
    openvas_manager: OpenVASScanManager,
) -> NmapScanManager | NiktoScanManager | OpenVASScanManager:
    """Devuelve el manager correcto a partir del tipo de escaneo (DRY)."""
    _logger.debug(f"Resolviendo manager para tipo de escaneo: {scan_type}")
    if scan_type == "nmap":
        return nmap_manager
    if scan_type == "nikto":
        return nikto_manager
    return openvas_manager

def verify_scan_ownership(scan: Scan, user_id: int, scan_id: int) -> None:
    """
    Verifica que el escaneo pertenece al usuario. Responde 404 en caso
    contrario para evitar enumerar IDs ajenos.
    """
    if scan.user_id != user_id:
        _logger.warning(
            f"Usuario {user_id} intentó acceder al escaneo {scan_id} "
            f"(propietario: {scan.user_id})"
        )
        raise ScanNotFoundError(scan_id)

def build_pdf_creator(scan: Scan) -> PDFCreator:
    """Construye el PDFCreator con la estrategia correcta según el tipo de escaneo."""
    scan_type = getattr(scan, "scan_type", "").lower()

    if scan_type == "nmap":
        strategy = NmapPrintingStrategy(scan=scan)
    elif scan_type == "nikto":
        strategy = NiktoPrintingStrategy(scan=scan)
    elif scan_type == "openvas":
        strategy = OpenVASPrintingStrategy(scan=scan)
    else:
        raise ValidationError(
            field="scan_type",
            message=f"Tipo de escaneo '{scan_type}' no soportado",
            expected="'nmap', 'nikto' u 'openvas'",
        )

    return PDFCreator(strategy)
