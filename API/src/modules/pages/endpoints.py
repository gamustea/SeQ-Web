"""
pages_endpoints.py
══════════════════════════════════════════════════════════════════════════════

Blueprint que sirve las páginas web de la interfaz. Registrado en /pages.

Este módulo proporciona endpoints para servir las páginas HTML de la interfaz
de usuario. El acceso está controlado según el tipo de página.

────────────────────────────────────────────────────────────────────────────────
ENDPOINTS DISPONIBLES
────────────────────────────────────────────────────────────────────────────────

Páginas
    GET /pages/login — Página de login (pública)
    GET /pages/<name> — Otras páginas (requieren autenticación)

────────────────────────────────────────────────────────────────────────────────
AUTENTICACIÓN
────────────────────────────────────────────────────────────────────────────────

• /pages/login — Sin autenticación (público)
• /pages/<name> — Requiere token OAuth2 válido

────────────────────────────────────────────────────────────────────────────────
EJEMPLOS DE USO
────────────────────────────────────────────────────────────────────────────────

# Acceder a la página de login
curl https://api.example.com/pages/login

# Acceder a Sentinel (requiere token)
curl -H "Authorization: Bearer <token>" https://api.example.com/pages/sentinel

────────────────────────────────────────────────────────────────────────────────
NOTAS
────────────────────────────────────────────────────────────────────────────────

Las páginas se sirven desde el directorio Interface/web/pages/ del proyecto.
Los archivos HTML debe existir previamente en el sistema de archivos.
"""

import os
from flask import Blueprint, send_from_directory, jsonify

pages_bp = Blueprint("pages", __name__)

_PAGES_DIR = r"C:\Users\gmiga\Documents\GitHub\SecOps\web\legacy"

@pages_bp.route("/login")
def serve_login():
    return send_from_directory(_PAGES_DIR, "login.html")

@pages_bp.route("/<string:page_name>")
def serve_page(page_name: str):
    filename = page_name if page_name.endswith(".html") else f"{page_name}.html"
    if filename == "login.html":
        return serve_login()
    target = os.path.join(_PAGES_DIR, filename)
    if not os.path.isfile(target):
        return jsonify({"error": "not_found", "error_description": f"La página '{filename}' no existe."}), 404
    return send_from_directory(_PAGES_DIR, filename)
