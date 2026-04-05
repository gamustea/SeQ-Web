"""
Paquete de endpoints de la API SeQ.

Cada módulo expone un Blueprint de Flask. Este __init__.py los registra
todos con sus prefijos de URL, centralizando la configuración de rutas
en un único lugar y manteniendo run.py libre de lógica de negocio.

Blueprints disponibles
─────────────────────
  oauth_bp      →  /oauth
  users_bp      →  /users
  sentinel_bp   →  /sentinel
  acheron_bp    →  /acheron  +  /vaults  (gestión de Vaults/Storables)
  aegis_bp      →  /aegis
  health_bp     →  /  (ping de salud sin prefijo)
"""

from flask import Flask

from .oauth_endpoints import oauth_bp
from .users_endpoints import users_bp
from .sentinel_endpoints import sentinel_bp
from .acheron_endpoints import acheron_bp
from .aegis_endpoints import aegis_bp
from .health_endpoints import health_bp
from .pages_endpoints import pages_bp


def register_blueprints(app: Flask) -> None:
    """Registra todos los blueprints en la aplicación Flask."""
    app.register_blueprint(health_bp)
    app.register_blueprint(oauth_bp,    url_prefix="/oauth")
    app.register_blueprint(users_bp,    url_prefix="/users")
    app.register_blueprint(sentinel_bp, url_prefix="/sentinel")
    app.register_blueprint(acheron_bp,  url_prefix="/acheron")
    app.register_blueprint(aegis_bp,    url_prefix="/aegis")
    app.register_blueprint(pages_bp,    url_prefix="/pages")
