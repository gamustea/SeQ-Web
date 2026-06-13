"""
system/__init__.py
Módulo de gestión de configuración de SecOps.
Proporciona endpoints para leer y escribir SecOpsConfig.json.
"""

from .logging import SecOpsLogger
from .platform import PlatformDetector
from .endpoints import system_blp
from .taskqueue import TaskQueue, Task, TaskStatus

__all__ = [
    "SecOpsLogger",
    "PlatformDetector",
    "system_blp",
    "TaskQueue",
    "Task",
    "TaskStatus",
]