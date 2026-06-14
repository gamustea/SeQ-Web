"""
taskqueue/connection.py
───────────────────────
Fuente única de conexiones Redis para el sistema de tareas.

RQ necesita una conexión binaria (``decode_responses=False``) porque
serializa los jobs con pickle. Las claves propias del taskqueue (hashes,
sorted sets, flags de cancelación) son cadenas y se manejan mejor con una
conexión decodificada. ``RedisConnectionFactory`` centraliza la lectura de
configuración para que host/port/db/password vivan en un único lugar y no
se dupliquen entre la cola y el worker.
"""

from __future__ import annotations

import redis as redis_lib

import src.modules.system.config_reading as CR


class RedisConnectionFactory:
    """Crea conexiones Redis a partir de la configuración central."""

    @staticmethod
    def _kwargs() -> dict:
        cfg = CR.get_redis_config()
        return {
            "host": cfg["host"],
            "port": cfg["port"],
            "db": cfg["db"],
            "password": cfg["password"],
        }

    @classmethod
    def raw(cls) -> redis_lib.Redis:
        """Conexión binaria para RQ (jobs serializados con pickle)."""
        return redis_lib.Redis(**cls._kwargs(), decode_responses=False)

    @classmethod
    def decoded(cls) -> redis_lib.Redis:
        """Conexión decodificada para las claves string del taskqueue."""
        return redis_lib.Redis(**cls._kwargs(), decode_responses=True)
