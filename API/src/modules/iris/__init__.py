from src.modules.system.taskqueue import QueueRegistry

from .model import IrisAnalysis, IrisRuleResult
from .managers import IrisManager
from .endpoints import iris_blp

# Registro de la categoría de cola de este módulo (OCP).
QueueRegistry.register("iris.analyze")

__all__ = [
    "IrisAnalysis",
    "IrisRuleResult",
    "IrisManager",
    "iris_blp",
]
