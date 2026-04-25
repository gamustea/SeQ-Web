"""
src.modules.health - Endpoint de salud de la API

Exponente:
    - health_bp: Health check endpoint
"""

from .endpoints import health_bp

__all__ = ["health_bp"]