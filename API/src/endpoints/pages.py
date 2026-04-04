"""
endpoints/pages.py
──────────────────
Blueprint que sirve las páginas web de la interfaz bajo /pages/<nombre>.
Requiere autenticación OAuth para proteger el acceso.
"""

import os
from flask import Blueprint, send_from_directory, jsonify
from src.endpoints._shared import require_oauth_token

pages_bp = Blueprint("pages", __name__)

_PUBLIC_PAGES = {"login.html"}
_PAGES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "Interface", "web", "pages")
)

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
        return jsonify({"error": "not_found", "message": f"La página '{filename}' no existe."}), 404
    return send_from_directory(_PAGES_DIR, filename)

@pages_bp.route("/debug-path")
def debug_path():
    import os
    return jsonify({
        "pages_dir": _PAGES_DIR,
        "exists": os.path.isdir(_PAGES_DIR),
        "files": os.listdir(_PAGES_DIR) if os.path.isdir(_PAGES_DIR) else []
    })