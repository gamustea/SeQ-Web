"""
taskqueue/registry.py
─────────────────────
Registro central de categorías/colas conocidas (Open/Closed Principle).

En lugar de codificar la lista de colas en el núcleo de ``TaskQueue``, cada
módulo registra su categoría al importarse, por ejemplo::

    from src.modules.system.taskqueue import QueueRegistry
    QueueRegistry.register("sentinel.scan", "sentinel.report")

Así, añadir un módulo nuevo no obliga a editar ``TaskQueue`` ni el worker.
La cola ``"default"`` siempre está presente.
"""

from __future__ import annotations

import threading
from typing import List

DEFAULT_QUEUE = "default"


class QueueRegistry:
    """Conjunto thread-safe de nombres de cola registrados."""

    _names: set = {DEFAULT_QUEUE}
    _lock = threading.Lock()

    @classmethod
    def register(cls, *names: str) -> None:
        """Registra una o varias categorías. Idempotente."""
        with cls._lock:
            for name in names:
                if name:
                    cls._names.add(name)

    @classmethod
    def names(cls) -> List[str]:
        """Devuelve los nombres de cola registrados, ordenados."""
        with cls._lock:
            return sorted(cls._names)

    @classmethod
    def is_registered(cls, name: str) -> bool:
        with cls._lock:
            return name in cls._names
